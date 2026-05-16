package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

// -----------------------------
// Types for auth gateway
// -----------------------------

// authRequest is the incoming request from sftpgo (parameters which are used for this gateway).
type authRequest struct {
	Username            string      `json:"username"`
	Password            SecureBytes `json:"password"`
	Protocol            string      `json:"protocol"` // SSH, FTP, DAV, HTTP
	IP                  string      `json:"ip"`
	PublicKey           string      `json:"public_key"`
	KeyboardInteractive string      `json:"keyboard_interactive"`
	TLSCert             string      `json:"tls_cert"`
}

// HTTPServerMiddleware takes care of transparent logging and request-id.
func HTTPServerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now().UTC()
		ip := clientIPFromRequest(r)

		//nolint:mnd // request id length is considered fixed and there is no need to adjust
		requestID := shortRequestID(8)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("Server", fmt.Sprintf("%s/%s", AppName, AppVersion))

		// Suppress noisy per-request logs for the health check endpoint
		quiet := r.URL.Path == AuthHealthPath

		if !quiet {
			logger.Debugw("incoming request",
				"request_id", requestID,
				"method", r.Method,
				"user_agent", r.UserAgent(),
				"path", r.URL.Path,
				"request_ip", ip,
			)
		}

		// Create a logger with request fields
		reqLogger := logger.With("request_id", requestID)

		// Add the logger to the request context
		ctx := context.WithValue(r.Context(), loggerContextKey, reqLogger)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)

		if !quiet {
			logger.Debugw("done handling request",
				"request_id", requestID,
				"duration", time.Since(start),
			)
		}
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
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
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
	defer closeIOBody(&r.Body)

	// use custom logger from context
	authLog := LoggerFromContext(r.Context())

	// a few sanity checks
	// only allow POST
	if r.Method != http.MethodPost {
		authLog.Warnw("invalid method accessed",
			"path", r.URL.Path,
			"method", r.Method,
		)
		http.Error(w, "method not implemented", http.StatusMethodNotAllowed)
		return
	}

	// limit request body size to MaxBodyBytes
	r.Body = http.MaxBytesReader(w, r.Body, int64(MaxBodyBytes))

	// decode body
	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// check if body exceeded MaxBodyBytes
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			// Body exceeded MaxBodyBytes
			authLog.Warnw("request body too large", "error", err)
			writeDeny(w, http.StatusRequestEntityTooLarge, "body_too_large",
				fmt.Sprintf("request body too large (limit %d bytes)", MaxBodyBytes))
			return
		}

		// otherwise it's a malformed JSON body
		authLog.Warnw("malformed JSON body", "error", err)
		writeDeny(w, http.StatusBadRequest, "invalid_json", "malformed JSON body")
		return
	}

	// check for supported authentication methods
	if req.PublicKey != "" || req.KeyboardInteractive != "" || req.TLSCert != "" {
		authLog.Warnw("unsupported authentication method",
			"password", len(req.Password.String()),
			"public_key", req.PublicKey,
			"keyboard_interactive", req.KeyboardInteractive,
			"tls_cert", req.TLSCert,
		)
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
	authLog = authLog.With("user", req.Username)

	authLog.Infow("auth request received",
		"protocol", req.Protocol,
		"ip", req.IP,
	)

	// Process authentication request
	resp, err := performAuthentication(authLog, r, w, req)
	if err != nil {
		authLog.Errorw("failed to process authentication request", "error", err)
		return
	}

	// Encode response as JSON and return to the client
	data, err := json.Marshal(resp)
	if err != nil {
		authLog.Errorw("failed to encode success response", "error", err)
		writeDeny(w, http.StatusInternalServerError, "json_encode_failed",
			"failed to encode success response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, respErr := w.Write(data); respErr != nil {
		authLog.Errorw("failed to write response", "error", respErr)
	}

	authLog.Info("reported authentication success to sftpgo")
	authLog.Logw(TraceLevel, "debug authentication json response", "response", string(data))
}

// webHealthHandler is the health check endpoint. For example, used by docker health checks.
func webHealthHandler(w http.ResponseWriter, r *http.Request) {
	// use custom logger from context
	authLog := LoggerFromContext(r.Context())

	// a few sanity checks
	// only allow GET or HEAD
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		authLog.Warnw("invalid method accessed",
			"path", r.URL.Path,
			"method", r.Method,
		)
		http.Error(w, "method not implemented", http.StatusMethodNotAllowed)
		return
	}

	data := []byte("")
	// Only build response body for GET requests
	if r.Method == http.MethodGet {
		uptime := int64(time.Since(AppStartTime).Seconds())

		// Build response success in JSON format
		status := map[string]interface{}{
			"status": "ok",
			"uptime": uptime,
		}

		// Encode response as JSON and return to the client
		var err error
		data, err = json.Marshal(status)
		if err != nil {
			authLog.Errorw("failed to encode health response", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
	}

	w.WriteHeader(http.StatusOK)
	if _, respErr := w.Write(data); respErr != nil {
		authLog.Errorw("failed to write response", "error", respErr)
	}

	logger.Logw(TraceLevel, "debug health check response", "response", string(data))
}

// performAuthentication performs the authentication workflow.
// It returns a sftpgoResponse and an error.
//
// The workflow is as follows:
// - create a per-request cookie jar and client (no shared cookies)
// - create context with timeout derived from request context
// - qnapLogin uses ctx to abort the request if timeout
// - fetch shares from QNAP API
// - build virtual folders and permissions
// - sync folders to sftpgo
func performAuthentication(authLog *zap.SugaredLogger, r *http.Request, w http.ResponseWriter,
	req authRequest) (sftpgoResponse, error) {
	// Create a per-request cookie jar and client (no shared cookies)
	jar, err := cookiejar.New(nil)
	if err != nil {
		authLog.Errorw("failed to create cookie jar", "error", err)
		writeDeny(w, http.StatusInternalServerError, "internal_error",
			"failed to initialize authentication")
		return sftpgoResponse{}, err
	}

	//nolint:gosec,exhaustruct // intentional: user decides to ignore, defaults acceptable
	client := &http.Client{
		Jar:     jar,
		Timeout: HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !config.Qnap.CheckCert,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	// Create context with timeout derived from request context
	ctx, cancel := context.WithTimeout(r.Context(), HTTPTimeout)
	defer cancel()

	// qnapLogin uses ctx to abort the request if timeout
	authLog.Debug("initiating qnap login")
	sid, err := qnapLogin(ctx, authLog, client, config.Qnap.URL, req)
	req.Password.Wipe() // Wipe password from memory

	if err != nil {
		// log and deny
		// invalid credentials -> WARN (per policy)
		if errors.Is(err, errAuthFailed) {
			authLog.Warn("qnap authentication failed")
			writeDeny(w, http.StatusUnauthorized, "auth_failed", "authentication failed")
			return sftpgoResponse{}, err
		}
		// other errors (timeout, network) -> ERROR
		authLog.Errorw("qnap login error", "error", err)
		writeDeny(w, http.StatusInternalServerError, "qnap_error", "qnap authentication error")
		return sftpgoResponse{}, err
	}
	authLog.Info("qnap login workflow reported success")

	// Fetch shares
	shares, err := qnapGetShares(ctx, authLog, client, config.Qnap.URL, sid)
	if err != nil {
		authLog.Errorw("failed to fetch shares for user", "error", err)
		writeDeny(w, http.StatusInternalServerError, "share_fetch_failed", "failed to query shares")
		return sftpgoResponse{}, err
	}

	// Shares received. Proceeding.
	authLog.Infow("accessible shares retrieved", "count", len(shares))

	// Logout user from QNAP
	authLog.Debug("logging user out of qnap api...")
	if qlErr := qnapLogout(ctx, authLog, client, config.Qnap.URL, sid); qlErr != nil {
		authLog.Errorw("failed to logout of qnap. proceeding...", "error", qlErr)
	}

	// Build virtual folders and permissions
	folders, virtualFolders := buildVirtualFolders(authLog, shares)

	// Initiate sftpgo virtual folder sync
	failedFolders, err := sftpgoSyncFolders(authLog, folders)
	if err != nil {
		authLog.Errorw("failed to sync folders, denying login", "error", err)
		writeDeny(w, http.StatusInternalServerError, "sync_folders_failed",
			"failed to sync folders")
		return sftpgoResponse{}, err
	}
	filterInvalidFolders(&virtualFolders, failedFolders)

	// Calculate user expiry in 5 minutes from now (in unix timestamp milliseconds)
	// Just to ensure no login will be valid for more than 5 minutes and needs to be renewed via this service
	userExpiry := time.Now().Add(config.Sftpgo.AccountExpiration.AsDuration()).UnixMilli()

	// Get home directory
	homeDir := strings.ReplaceAll(config.Sftpgo.HomeDir, "{user}", req.Username)

	// Build permissions map
	perms := getPermissionMap(authLog, virtualFolders)

	// Build filters map
	filters := sftpgoUserFilters{
		ExternalAuthCacheTime: int(config.Sftpgo.AuthCacheTime.AsDuration().Seconds()),
	}

	// Build response success
	//nolint:exhaustruct // intentional; not all fields needed/work in progress
	resp := sftpgoResponse{
		Status:         1,
		Username:       req.Username,
		ExpirationDate: userExpiry,
		HomeDir:        homeDir,
		VirtualFolders: virtualFolders,
		Permissions:    perms,
		Filters:        filters,
	}

	// Set UID/GID if possible
	userInfo, passwdErr := getPasswdFileUser(req.Username)
	if passwdErr == nil {
		authLog.Debugw("setting UID/GID for user", "uid", userInfo.UID, "gid", userInfo.GID)
		resp.UID = userInfo.UID
		resp.GID = userInfo.GID
	}

	return resp, nil
}

// getPermissionMap builds the permissions map for sftpgo based on the virtual folders.
func getPermissionMap(authLog *zap.SugaredLogger, virtualFolders []sftpgoVirtualFolder) map[string][]string {
	// Allocate permissions map +1 for the root folder
	perms := make(map[string][]string, len(virtualFolders)+1)

	// Default permission to the root folder by default
	perms["/"] = SharePermsListOnly

	// Set permissions for all other folders
	for i := range virtualFolders {
		perms[virtualFolders[i].VirtualPath] = virtualFolders[i].Permission
	}

	authLog.Logw(TraceLevel, "permissions map", "permissions", perms)
	return perms
}

// filterInvalidFolders filters out any failed folders from virtualFolders.
// It modifies virtualFolders in-place.
func filterInvalidFolders(virtualFolders *[]sftpgoVirtualFolder, failedFolders []string) {
	// Remove any failed folders from virtualFolders
	if len(failedFolders) > 0 {
		// Create a set of failed folder names for O(1) lookup
		failedSet := make(map[string]struct{}, len(failedFolders))
		for _, name := range failedFolders {
			failedSet[name] = struct{}{}
		}

		// Filter out failed folders
		filteredFolders := (*virtualFolders)[:0]
		for _, vf := range *virtualFolders {
			if _, isFailed := failedSet[vf.Name]; !isFailed {
				filteredFolders = append(filteredFolders, vf)
			}
		}
		*virtualFolders = filteredFolders
	}
}

// buildVirtualFolders builds the virtual folders and permissions for the given QNAP shares.
// It returns a map of permissions and a slice of virtual folders.
func buildVirtualFolders(authLog *zap.SugaredLogger,
	shares []qnapShareNode) ([]sftpgoBackendFolder, []sftpgoVirtualFolder) {
	// Build virtual folders
	folders := make([]sftpgoBackendFolder, 0, len(shares))
	virtualFolders := make([]sftpgoVirtualFolder, 0, len(shares))

	// Check each QNAP share
	for _, s := range shares {
		// Skip any shares that are not iconCls=folder
		if s.IconCls != "folder" {
			authLog.Debugw("skipped share as it is not iconCls=folder",
				"name", s.ID,
				"text", s.Text,
				"icon", s.IconCls,
			)
			continue
		}

		// skip any shares that the user does not have either
		// read or write access to
		if s.Cls != "r" && s.Cls != "w" {
			authLog.Debugw("skipped share with non-r/w modes",
				"name", s.ID,
				"text", s.Text,
				"cls", s.Cls,
			)
			continue
		}

		// build virtual folder
		// the name is the link between "backend" and "frontend" folder
		name := s.Text
		if name == "" {
			name = strings.Trim(s.ID, "/")
			authLog.Warnw("empty share name, using ID instead", "name", name)
		}
		name = QnapSharePrefix + strings.TrimSpace(name)
		name = strings.ReplaceAll(name, "/", "_")
		name = strings.ReplaceAll(name, " ", "_")

		// Build paths for virtual folder and QNAP
		sftpgoPath := strings.TrimSpace(s.ID)

		qnapPath := strings.TrimSpace(config.Qnap.SharePath)
		qnapPath = strings.ReplaceAll(qnapPath, "{name}", s.ID)
		qnapPath = strings.ReplaceAll(qnapPath, "//", "/")

		// build permissions
		var vfPerms = SharePermsDeny // default to deny
		switch s.Cls {
		case "w":
			vfPerms = SharePermsReadWrite
		case "r":
			vfPerms = SharePermsReadOnly
		}

		// Parse description
		folderDesc := strings.ReplaceAll(config.Sftpgo.ManagedFolderDesc, "{name}", s.Text)

		// adding sftpgo folder
		folder := sftpgoBackendFolder{
			Name:        name,
			MappedPath:  qnapPath,
			Description: folderDesc,
			Filesystem: &sftpgoFolderFilesystem{
				Provider: 0,
			},
		}
		folders = append(folders, folder)

		// add sftpgo folder (backend) <> sftpgo virtual folder mapping (frontend; user-facing)
		virtualFolder := sftpgoVirtualFolder{
			Name:        name,
			VirtualPath: sftpgoPath,
			Permission:  vfPerms,
		}
		virtualFolders = append(virtualFolders, virtualFolder)

		// log
		authLog.Debugw("added qnap share to array",
			"name", name,
			"sftpgo_path", sftpgoPath,
			"qnap_path", qnapPath,
			"perms", vfPerms,
		)
	}

	authLog.Logw(TraceLevel, "all folders", "folders", folders)
	return folders, virtualFolders
}

// -----------------------------
// Helpers
// -----------------------------

// closeIOBody closes the given io.ReadCloser and logs any errors.
func closeIOBody(body *io.ReadCloser) {
	if body == nil {
		return
	}
	readErr := (*body).Close()
	if readErr != nil {
		logger.Errorw("failed to close response body", "error", readErr)
	}
}

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
	//nolint:exhaustruct // intentional; not all fields needed for error response
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
func LoggerFromContext(ctx context.Context) *zap.SugaredLogger {
	if reqLogger, ok := ctx.Value(loggerContextKey).(*zap.SugaredLogger); ok {
		return reqLogger
	}
	// Return default logger if none in context
	return logger
}

// shortRequestID generates a random hexadecimal string of length n or a fallback time-based string on failure.
func shortRequestID(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		// fallback in case of failure
		return time.Now().Format("150405.000") // HHMMSS.milliseconds
	}
	return hex.EncodeToString(b)
}

// -----------------------------
// Custom data type for secure bytes
// -----------------------------

// Ensure interface conformance at compile time.
var _ encoding.TextUnmarshaler = (*SecureBytes)(nil)

// SecureBytes is a byte slice used for in-memory password handling during authentication requests.
type SecureBytes []byte

// UnmarshalText lets encoding/json populate the bytes from a JSON string
// without base64 decoding. The input is the unescaped string bytes.
func (w *SecureBytes) UnmarshalText(text []byte) error {
	*w = append((*w)[:0], text...) // copy so we control the memory
	return nil
}

// Base64Encoded returns a base64‑encoded copy of the bytes.
// It avoids creating a Go string, so the encoded data can be wiped.
func (w *SecureBytes) Base64Encoded() []byte {
	if w == nil || len(*w) == 0 {
		return nil
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(*w)))
	base64.StdEncoding.Encode(dst, *w)
	runtime.KeepAlive(w) // ensure a source isn't optimized away prematurely
	return dst
}

// WriteBase64To writes the base64 encoding to dst without creating an intermediate string.
func (w *SecureBytes) WriteBase64To(dst io.Writer) error {
	if w == nil || len(*w) == 0 {
		return nil
	}
	enc := base64.NewEncoder(base64.StdEncoding, dst)
	_, err := enc.Write(*w)
	closeErr := enc.Close()
	if err == nil {
		err = closeErr
	}
	runtime.KeepAlive(w)
	return err
}

// Wipe zeroes the memory in place and releases the slice.
func (w *SecureBytes) Wipe() {
	if w == nil {
		logger.Warn("Wipe called on nil SecureBytes")
		return
	}
	for i := range *w {
		(*w)[i] = 0
	}
	// Optionally, drop references.
	*w = nil
	runtime.KeepAlive(w) // prevent compiler from optimizing away
}

// String returns the string representation of the bytes.
func (w *SecureBytes) String() string {
	return "[REDACTED]"
}

// WipeBuffer is a custom function to wipe buffers explicitly.
// Helper function variant: call as WipeBuffer(&buf).
func WipeBuffer(buf *bytes.Buffer) {
	if buf == nil {
		logger.Warn("WipeBuffer called on nil buffer")
		return
	}
	b := buf.Bytes()
	if cap(b) > 0 {
		bs := b[:cap(b)] // span full backing array from the current start
		for i := range bs {
			bs[i] = 0
		}
	}
	buf.Reset() // drop references
	*buf = bytes.Buffer{}
	runtime.KeepAlive(b) // ensure zeroing isn't optimized away
}
