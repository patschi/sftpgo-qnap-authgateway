package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// HttpServerMiddleware takes care of transparent logging and request-id
func HttpServerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		ip := clientIPFromRequest(r)

		requestID := shortRequestID(8)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Server", fmt.Sprintf("%s/%s", AppName, AppVersion))

		log.WithFields(log.Fields{
			"request_id": requestID,
			"method":     r.Method,
			"user_agent": r.UserAgent(),
			"path":       r.URL.Path,
			"request_ip": ip,
		}).Debug("incoming request")

		// Create a logger with request fields
		logger := log.WithFields(log.Fields{
			"request_id": requestID,
		})

		// Add the logger to the request context
		ctx := context.WithValue(r.Context(), "logger", logger)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)

		log.WithFields(log.Fields{
			"request_id": requestID,
			"duration":   time.Since(start),
		}).Debug("handled request")
	})
}

// clientIPFromRequest returns the client's IP address.
// It prefers X-Forwarded-For (first entry), then X-Real-IP, then RemoteAddr.
func clientIPFromRequest(r *http.Request) string {
	if f := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); f != "" {
		parts := strings.Split(f, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIp := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIp != "" {
		return realIp
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// -----------------------------
// Handler
// -----------------------------

// webAuthHandler is the main handler for the auth endpoint.
// It handles authentication requests from sftpgo and returns a response to sftpgo.
// It is called by the HTTP server mux.
//
// The handler is responsible for:
// - validating the request
// - authenticating the user
// - fetching shares from the QNAP API
// - building the virtual folders
// - returning a response to sftpgo
func webAuthHandler(w http.ResponseWriter, r *http.Request) {
	// use custom logger from context
	authLog := LoggerFromContext(r.Context())

	// a few sanity checks
	// only allow POST
	if r.Method != http.MethodPost {
		authLog.WithFields(log.Fields{
			"path":   r.URL.Path,
			"method": r.Method,
		}).Warn("invalid method accessed")
		http.Error(w, "method not implemented", http.StatusMethodNotAllowed)
		return
	}

	// only allow AuthPath call
	if r.URL.Path != AuthPath {
		authLog.WithFields(log.Fields{
			"path":   r.URL.Path,
			"method": r.Method,
		}).Warn("invalid path accessed")
		http.NotFound(w, r)
		return
	}

	// limit request body size to MaxBodyBytes
	r.Body = http.MaxBytesReader(w, r.Body, int64(MaxBodyBytes))
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			authLog.WithError(err).Warn("auth: failed to close request body")
		}
	}(r.Body)

	// decode body
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// check if body exceeded MaxBodyBytes
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			// Body exceeded MaxBodyBytes
			authLog.WithError(err).Warn("request body too large")
			writeDeny(w, http.StatusRequestEntityTooLarge, "body_too_large",
				fmt.Sprintf("request body too large (limit %d bytes)", MaxBodyBytes))
			return
		}

		// otherwise it's a malformed JSON body'
		authLog.WithError(err).Warn("malformed JSON body")
		writeDeny(w, http.StatusBadRequest, "invalid_json", "malformed JSON body")
		return
	}

	// check for supported authentication methods
	if req.PublicKey != "" || req.KeyboardInteractive != "" || req.TlsCert != "" {
		authLog.Warn("unsupported authentication method")
		writeDeny(w, http.StatusBadRequest, "unsupported_method", "unsupported authentication method")
		return
	}

	// check if required parameters are present
	if req.Username == "" || len(req.Password) == 0 || req.IP == "" {
		authLog.Warn("missing required parameters")
		writeDeny(w, http.StatusBadRequest, "missing_params", "missing required parameters")
		return
	}

	// add username to all logs
	authLog = authLog.WithField("user", req.Username)

	authLog.WithFields(log.Fields{
		"protocol": req.Protocol,
		"ip":       req.IP,
	}).Info("auth request received")

	// Create a per-request cookie jar and client (no shared cookies)
	jar, err := cookiejar.New(nil)
	if err != nil {
		authLog.WithError(err).Error("failed to create cookie jar")
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: HttpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !QnapCheckCert,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	// Create context with timeout derived from request context
	ctx, cancel := context.WithTimeout(r.Context(), HttpTimeout)
	defer cancel()

	// qnapLogin uses ctx to abort the request if timeout
	authLog.Debug("initiating qnap login")
	sid, err := qnapLogin(ctx, client, QnapUrl, req)
	req.Password.Wipe() // Wipe password from memory

	if err != nil {
		// log and deny
		// invalid credentials -> WARN (per policy)
		if errors.Is(err, errAuthFailed) {
			authLog.Warn("qnap authentication failed")
			writeDeny(w, http.StatusUnauthorized, "auth_failed", "authentication failed")
			return
		}
		// other errors (timeout, network) -> ERROR
		authLog.WithError(err).Errorf("qnap login error")
		writeDeny(w, http.StatusInternalServerError, "qnap_error", "qnap authentication error")
		return
	}
	authLog.Info("qnap login workflow reported success")

	// Fetch shares
	shares, err := qnapGetShares(ctx, client, QnapUrl, sid, req.Username)
	if err != nil {
		authLog.WithError(err).Errorf("failed to fetch shares for user")
		writeDeny(w, http.StatusInternalServerError, "share_fetch_failed", "failed to query shares")
		return
	}

	// Shares received. Proceeding.
	authLog.WithFields(log.Fields{
		"user":  req.Username,
		"count": len(shares),
	}).Info("accessible shares retrieved")

	// Logout user from QNAP
	authLog.Debug("Logging user out of QNAP API...")
	if err := qnapLogout(ctx, client, QnapUrl, sid); err != nil {
		authLog.WithError(err).Errorf("failed to logout of qnap. proceeding...")
	} else {
		authLog.Info("Destroyed login session for user in QNAP API")
	}

	// Build virtual folders and permissions
	perms, folders := buildVirtualFolders(authLog, shares)

	// Calculate user expiry in 5 minutes from now (in unix timestamp milliseconds)
	// Just to ensure no login will be valid for more than 5 minutes and needs to be renewed via this service
	userExpiry := time.Now().Add(5 * time.Minute).UnixMilli()

	// Build response success
	resp := sftpgoResponse{
		Status:         1,
		Username:       req.Username,
		ExpirationDate: userExpiry,
		HomeDir:        "/var/tmp",
		VirtualFolders: folders,
		Permissions:    perms,
	}

	// Encode response as JSON and return to client
	data, err := json.Marshal(resp)
	if err != nil {
		authLog.WithError(err).Error("failed to encode success response")
		writeDeny(w, http.StatusInternalServerError, "json_encode_failed", "failed to encode success response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)

	authLog.Info("reported authentication success to sftpgo")
	authLog.WithField("response", string(data)).Trace("debug authentication json response")
}

// buildVirtualFolders builds the virtual folders and permissions for the given QNAP shares.
// It returns a map of permissions and a slice of virtual folders.
func buildVirtualFolders(authLog *log.Entry, shares []qnapShareNode) (map[string][]string, []sftpgoVF) {

	// Build virtual folders
	perms := make(map[string][]string, len(shares)+1)
	vfs := make([]sftpgoVF, 0, len(shares))

	// Deny access to the root folder
	perms["/"] = SharePermsListOnly

	// Check each QNAP share
	for _, s := range shares {
		// Skip any shares that are not iconCls=folder
		if s.IconCls != "folder" {
			authLog.WithFields(log.Fields{
				"name": s.ID,
				"text": s.Text,
				"icon": s.IconCls,
			}).Debug("skipped share as it is not iconCls=folder")
			continue
		}

		// skip any shares that the user does not have either
		// read or write access to
		if s.Cls != "r" && s.Cls != "w" {
			authLog.WithFields(log.Fields{
				"name": s.ID,
				"text": s.Text,
				"cls":  s.Cls,
			}).Debug("skipped share with non-r/w modes")
			continue
		}

		// build virtual folder
		name := s.Text
		if name == "" {
			name = strings.Trim(s.ID, "/")
			authLog.WithField("name", name).Warn("empty share name, using ID instead")
		}
		name = strings.TrimSpace(name)

		// Build paths for virtual folder and QNAP
		sftpgoPath := strings.TrimSpace(s.ID)
		qnapPath := strings.Replace(QnapSharePath, "{name}", name, 1)

		// build permissions
		var vfPerms = SharePermsDeny // default to deny
		if s.Cls == "w" {
			vfPerms = SharePermsReadWrite
		} else if s.Cls == "r" {
			vfPerms = SharePermsReadOnly
		}
		perms[sftpgoPath] = vfPerms

		// adding virtual folder
		vf := sftpgoVF{
			Name:        name,
			VirtualPath: sftpgoPath,
			MappedPath:  qnapPath,
			Description: fmt.Sprintf("QNAP Share: %s", name),
		}
		vfs = append(vfs, vf)
		authLog.WithFields(log.Fields{
			"name":        name,
			"sftpgo_path": sftpgoPath,
			"qnap_path":   qnapPath,
			"perms":       vfPerms,
		}).Debug("added virtual folder")
	}

	return perms, vfs
}

// -----------------------------
// Helpers
// -----------------------------

// writeDeny writes a JSON response to w with the given status code and error code.
// It also sets the Content-Type header to application/json.
//
// The response is formatted as:
//
//	{
//	  "status": 0,
//	  "username": "",
//	  "error": "message",
//	  "meta": {
//	    "code": "err_code"
//	  }
//	}
func writeDeny(w http.ResponseWriter, httpCode int, errCode string, message string) {
	resp := sftpgoResponse{
		Status:   0,
		Username: "",
		Error:    message,
		Meta: map[string]string{
			"code": errCode,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// LoggerFromContext is a function to get logger from other context
func LoggerFromContext(ctx context.Context) *log.Entry {
	if logger, ok := ctx.Value("logger").(*log.Entry); ok {
		return logger
	}
	// Return default logger if none in context
	return log.NewEntry(log.StandardLogger())
}

// shortRequestID generates a random hexadecimal string of length n or a fallback time-based string on failure.
func shortRequestID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// fallback in case of failure
		return time.Now().Format("150405.000") // HHMMSS.milliseconds
	}
	return hex.EncodeToString(b)
}
