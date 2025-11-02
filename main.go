package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// -----------------------------
// Configuration constants
// -----------------------------

const (
	// AppName is the name of the application
	AppName = "SftpgoQnapAuthGateway"
	// AppVersion is the current version of the application
	AppVersion = "0.1.0"

	// AuthPath server listen address and endpoint
	AuthPath = "/auth"
	// HttpTimeout defines HTTP client timeout for requests to QNAP API
	HttpTimeout = 10 * time.Second
	// MaxBodyBytes is limiting body size for JSON parsing
	MaxBodyBytes = 2 * 1024 // 2 KiB
)

var (
	// QnapHttp defines the protocol to use for QNAP API calls
	QnapHttp string
	// QnapHost defines the host to use for QNAP API calls
	QnapHost string
	// QnapPort defines the port to use for QNAP API calls
	QnapPort string
	// QnapSharePath defines path for QNAP shares where share is located
	// (example: /share/{path}/; as in /share/Public)
	QnapSharePath string
	// QnapCheckCert defines if we should check certificates when accessing QNAP API
	QnapCheckCert bool

	// SharePermsDeny means no access on sftpgo folder
	SharePermsDeny = []string{}
	// SharePermsReadOnly is the default permissions for read-only shares
	SharePermsReadOnly = []string{"list", "download"}
	// SharePermsReadWrite is the default permissions for read-write shares
	SharePermsReadWrite = []string{"*"}
)

// -----------------------------
// Types for QNAP responses
// -----------------------------

// xmlLoginResp is the response from QNAP API for login requests
type xmlLoginResp struct {
	XMLName    xml.Name `xml:"QDocRoot"`
	AuthPassed string   `xml:"authPassed"`
	AuthSid    string   `xml:"authSid"`
	ErrorValue string   `xml:"errorValue"`
}

// shareNode is a single shared folder
type shareNode struct {
	Text         string `json:"text"`
	ID           string `json:"id"`
	Cls          string `json:"cls"`
	IconCls      string `json:"iconCls"`
	NoSupportACL int    `json:"noSupportACL"`
}

// -----------------------------
// Types for incoming request and SFTPGo response
// -----------------------------

// authRequest is the incoming request from sftpgo (parameters which are used for this gateway)
type authRequest struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	Protocol            string `json:"protocol"` // SSH, FTP, DAV, HTTP
	IP                  string `json:"ip"`
	PublicKey           string `json:"public_key"`
	KeyboardInteractive string `json:"keyboard_interactive"`
	TlsCert             string `json:"tls_cert"`
}

// sftpgoVF is a virtual folder in sftpgo
type sftpgoVF struct {
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MappedPath  string `json:"mapped_path"`
}

// sftpgoResponse is the final response to sftpgo after authentication
type sftpgoResponse struct {
	Id             int32               `json:"id,omitempty"`
	Status         int                 `json:"status"`                    // 0 = disabled, 1 = enabled
	Username       string              `json:"username"`                  // empty = disallow login
	Uid            int32               `json:"uid,omitempty"`             // 0 = no change
	Gid            int32               `json:"gid,omitempty"`             // 0 = no change
	ExpirationDate int64               `json:"expiration_date,omitempty"` // 0 = no expiration; unix timestamp in milliseconds
	HomeDir        string              `json:"home_dir,omitempty"`
	VirtualFolders []sftpgoVF          `json:"virtual_folders,omitempty"`
	Permissions    map[string][]string `json:"permissions,omitempty"`
	Meta           map[string]string   `json:"meta,omitempty"`
	Error          string              `json:"error,omitempty"`
}

// -----------------------------
// Helper functions
// -----------------------------

// getEnv retrieves environment variable with ability of fallback value
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
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

// LoggerFromContext is a function to get logger from other context
func LoggerFromContext(ctx context.Context) *log.Entry {
	if logger, ok := ctx.Value("logger").(*log.Entry); ok {
		return logger
	}
	// Return default logger if none in context
	return log.NewEntry(log.StandardLogger())
}

// -----------------------------
// Main
// -----------------------------

func init() {
	// Force UTC timezone
	time.Local = time.UTC // ensure default time.Local is UTC for timestamp generation

	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.000",
		DisableColors:   true,
		CallerPrettyfier: func(f *runtime.Frame) (function string, file string) {
			return f.Function, ""
		},
	})
	log.SetLevel(log.DebugLevel)
	log.Infof("%s %s starting up", AppName, AppVersion)

	// Set log level
	logLevelStr := strings.TrimSpace(os.Getenv("LOG_LEVEL"))
	if logLevelStr == "" {
		log.SetLevel(log.DebugLevel)
		log.Infof("LOG_LEVEL not set, defaulting to DEBUG")
	} else if l, err := log.ParseLevel(strings.ToLower(logLevelStr)); err != nil {
		log.SetLevel(log.InfoLevel)
		log.Warnf("Invalid LOG_LEVEL=%q, defaulting to INFO: %v", logLevelStr, err)
	} else {
		log.SetLevel(l)
	}
	log.WithField("loglevel", strings.ToUpper(log.GetLevel().String())).Infof("current log level")
}

func main() {
	// Initialize values and read from environment variables
	QnapHttp = getEnv("QNAP_HTTP", "https")
	QnapHost = getEnv("QNAP_HOST", "127.0.0.1")
	QnapPort = getEnv("QNAP_PORT", "443")

	QnapSharePath = getEnv("QNAP_SHARE_PATH", "/share/{name}/")
	QnapSharePath = strings.TrimSpace(QnapSharePath)

	QnapCheckCertStr := getEnv("QNAP_CHECKCERT", "true")
	QnapCheckCert = false
	if strings.ToLower(strings.TrimSpace(QnapCheckCertStr)) == "true" {
		QnapCheckCert = true
	}
	log.WithField("state", QnapCheckCert).Info("QNAP API certificate check state")

	AuthGwHttps := getEnv("AUTHGW_HTTPS", "false")
	AuthGwAddr := getEnv("AUTHGW_ADDR", "0.0.0.0")
	AuthGwPort := getEnv("AUTHGW_PORT", "9999")

	// Check if we are running in HTTPS mode
	AuthGwScheme := "http"
	if AuthGwHttps == "true" {
		AuthGwScheme = "https"
		log.Fatal("not yet implemented")
	}

	// HTTP server mux and handler
	mux := http.NewServeMux()
	mux.HandleFunc(AuthPath, authHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", AuthGwAddr, AuthGwPort),
		Handler: HttpServerMiddleware(mux),

		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.WithFields(log.Fields{
			"authgw": fmt.Sprintf("%s://%s:%s%s", AuthGwScheme, AuthGwAddr, AuthGwPort, AuthPath),
			"qnap":   fmt.Sprintf("%s://%s:%s", QnapHttp, QnapHost, QnapPort),
		}).Info("starting QNAP auth gateway")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("HTTP server error: %v", err)
			os.Exit(1)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutdown signal received, stopping http server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Errorf("http server shutdown error")
	} else {
		log.Info("http server stopped gracefully")
	}
}

// HttpServerMiddleware takes care about transparent logging and request-id
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

// authHandler is the main handler for the auth endpoint.
// It handles authentication requests from sftpgo and returns a response to sftpgo.
// It is called by the HTTP server mux.
//
// The handler is responsible for:
// - validating the request
// - authenticating the user
// - fetching shares from the QNAP API
// - building the virtual folders
// - returning a response to sftpgo
func authHandler(w http.ResponseWriter, r *http.Request) {
	// use custom logger from context
	rlog := LoggerFromContext(r.Context())

	// a few sanity checks
	// only allow POST
	if r.Method != http.MethodPost {
		rlog.WithFields(log.Fields{
			"path":   r.URL.Path,
			"method": r.Method,
		}).Warn("invalid method accessed")
		http.Error(w, "method not implemented", http.StatusMethodNotAllowed)
		return
	}

	// only allow AuthPath call
	if r.URL.Path != AuthPath {
		rlog.WithFields(log.Fields{
			"path":   r.URL.Path,
			"method": r.Method,
		}).Warn("invalid path accessed")
		http.NotFound(w, r)
		return
	}

	// limit body and decode
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxBodyBytes))
	var req authRequest
	if err := dec.Decode(&req); err != nil {
		rlog.WithError(err).Warn("malformed JSON body")
		writeDeny(w, http.StatusBadRequest, "invalid_json", "malformed JSON body")
		return
	}

	// check for supported authentication methods
	if req.PublicKey != "" || req.KeyboardInteractive != "" || req.TlsCert != "" {
		rlog.Warn("unsupported authentication method")
		writeDeny(w, http.StatusBadRequest, "unsupported_method", "unsupported authentication method")
		return
	}

	if req.Username == "" || req.Password == "" || req.IP == "" {
		rlog.Warn("missing required parameters")
		writeDeny(w, http.StatusBadRequest, "missing_params", "missing required parameters")
		return
	}

	// add username to all logs
	rlog = rlog.WithField("user", req.Username)

	rlog.WithFields(log.Fields{
		"protocol": req.Protocol,
		"ip":       req.IP,
	}).Info("auth request received")

	// Create per-request cookie jar and client (no shared cookies)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: HttpTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !QnapCheckCert},
		},
	}

	// Create context with timeout derived from request context
	ctx, cancel := context.WithTimeout(r.Context(), HttpTimeout)
	defer cancel()

	base := fmt.Sprintf("%s://%s:%s", QnapHttp, QnapHost, QnapPort)

	// qnapLogin uses ctx to abort the request if timeout
	rlog.Debug("initiating qnap login")
	sid, err := qnapLogin(ctx, client, base, req.Username, req.Password)
	if err != nil {
		// log and deny
		// invalid credentials -> WARN (per policy)
		if errors.Is(err, errAuthFailed) {
			rlog.Warn("qnap authentication failed")
			writeDeny(w, http.StatusUnauthorized, "auth_failed", "authentication failed")
			return
		}
		// other errors (timeout, network) -> ERROR
		rlog.WithError(err).Errorf("qnap login error")
		writeDeny(w, http.StatusInternalServerError, "qnap_error", "qnap authentication error")
		return
	}
	rlog.Info("qnap login workflow reported success")

	// Fetch shares
	shares, err := qnapGetShares(ctx, client, base, sid, req.Username)
	if err != nil {
		rlog.WithError(err).Errorf("failed to fetch shares for user")
		writeDeny(w, http.StatusInternalServerError, "share_fetch_failed", "failed to query shares")
		return
	}

	// Shares received. Proceeding.
	rlog.WithFields(log.Fields{
		"user":  req.Username,
		"count": len(shares),
	}).Info("accessible shares retrieved")

	// Logout user from QNAP
	rlog.Debug("Logging user out of QNAP API...")
	if err := qnapLogout(ctx, client, base, sid); err != nil {
		rlog.WithError(err).Errorf("failed to logout of qnap. proceeding...")
	} else {
		rlog.Info("Destroyed login session for user in QNAP API")
	}

	// Build virtual folders
	perms := make(map[string][]string, len(shares)+1)
	vfs := make([]sftpgoVF, 0, len(shares))

	// Deny access to the root folder
	perms["/"] = SharePermsDeny

	// Check each QNAP share
	for _, s := range shares {
		// Skip any shares which are not iconCls=folder
		if s.IconCls != "folder" {
			rlog.WithFields(log.Fields{
				"name": s.ID,
				"text": s.Text,
				"icon": s.IconCls,
			}).Debug("skipped share as it is not iconCls=folder")
			continue
		}

		// skip any shares which user does not have either
		// read or write access to
		if s.Cls != "r" && s.Cls != "w" {
			rlog.WithFields(log.Fields{
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
		}
		name = strings.TrimSpace(name)

		// Build paths for virtual folder and QNAP
		sftpgoPath := strings.TrimSpace(s.ID)
		qnapPath := strings.Replace(QnapSharePath, "{name}", name, 1)

		// build permissions
		var vfPerms = SharePermsDeny
		if s.Cls == "w" {
			vfPerms = SharePermsReadWrite
		} else if s.Cls == "r" {
			vfPerms = SharePermsReadOnly
		}
		perms[sftpgoPath] = vfPerms

		// adding virtual folder
		vf := sftpgoVF{
			Name:        sftpgoPath,
			MappedPath:  qnapPath,
			Description: fmt.Sprintf("QNAP Share: %s", name),
		}
		vfs = append(vfs, vf)
		rlog.WithFields(log.Fields{
			"user":        req.Username,
			"name":        name,
			"sftpgo_path": sftpgoPath,
			"qnap_path":   qnapPath,
			"perms":       vfPerms,
		}).Debug("added virtual folder")
	}

	// Calculate user expiry in 5 minutes in unix timestamp milliseconds
	userExpiry := time.Now().Add(5*time.Minute).UnixNano() / 1000000

	// Respond success
	resp := sftpgoResponse{
		Status:         1,
		Username:       req.Username,
		ExpirationDate: userExpiry,
		HomeDir:        "/",
		VirtualFolders: vfs,
		Permissions:    perms,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		rlog.WithError(err).Error("failed to encode success response")
		writeDeny(w, http.StatusInternalServerError, "json_encode_failed", "failed to encode success response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)

	log.Info("reported authentication success to sftpgo")
	log.WithField("response", string(data)).Trace("debug authentication json response")
}

// -----------------------------
// Deny helper
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

// -----------------------------
// QNAP helpers: login + get_tree
// Each uses ctx; client is per-request and has its own cookiejar.
// -----------------------------

var errAuthFailed = errors.New("authentication failed")

// qnapLogin authenticates a user with a QNAP device and returns the session ID if login is successful or an error otherwise.
func qnapLogin(ctx context.Context, client *http.Client, baseURL string, user string, pass string) (string, error) {
	enc := base64.StdEncoding.EncodeToString([]byte(pass))

	loginURL := fmt.Sprintf("%s/cgi-bin/authLogin.cgi", baseURL)
	params := url.Values{}
	params.Set("user", user)
	params.Set("pwd", enc)
	params.Set("serviceKey", "1")
	params.Set("service", "1")

	log.WithFields(log.Fields{"user": user}).Debug("calling qnap auth endpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		// network/timeout errors
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("login: failed to close response body")
		}
	}(resp.Body)
	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// treat non-200 as auth failure for credential issues or QNAP errors differently
		// we attempt to parse body to determine, but default to auth failed
		return "", fmt.Errorf("login HTTP %d - body: %s", resp.StatusCode, string(bodyBytes))
	}

	reqBody := strings.TrimSpace(string(bodyBytes))
	log.WithFields(log.Fields{"user": user, "response": reqBody}).Trace("qnap login api response received")

	// Parse XML response
	var xr xmlLoginResp
	if err := xml.Unmarshal(bodyBytes, &xr); err != nil {
		log.WithField("xml", reqBody).WithError(err).Warn("failed to parse xml login response")
		return "", fmt.Errorf("unable to parse login response")
	}
	log.WithField("response", fmt.Sprintf("%+v", xr)).Trace("parsed qnap api response struct")

	// check if login was successful
	if xr.AuthSid != "" && xr.AuthPassed == "1" {
		log.WithField("user", user).Debug("qnap login successful")
		return xr.AuthSid, nil

	} else if xr.AuthSid != "" || xr.AuthPassed != "1" {
		log.WithField("user", user).Warn("qnap login failed")
		return "", errAuthFailed
	}

	return "", fmt.Errorf("unknown error or unexpected response from qnap api")
}

// qnapLogout logs out a user from a QNAP NAS via the authLogout API endpoint.
// It takes a context and HTTP client as parameters.
// Returns an error in case of failure.
func qnapLogout(ctx context.Context, client *http.Client, baseURL string, sid string) error {
	log.WithField("sid", sid).Trace("Destroying session on QNAP API")

	logoutURL := fmt.Sprintf("%s/cgi-bin/authLogout.cgi", baseURL)

	params := url.Values{}
	params.Set("sid", sid)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithError(err).Error("logout: failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout failed HTTP %d: %s", resp.StatusCode, string(body))
	}

	log.WithField("sid", sid).Trace("User session destroyed on QNAP API")
	return nil
}

// qnapGetShares retrieves a list of shared folders from a QNAP NAS via the get_tree API endpoint.
// It takes a context, HTTP client, NAS base URL, session ID, and user identifier as parameters.
// Returns a slice of shareNode containing share details or an error in case of failure.
func qnapGetShares(ctx context.Context, client *http.Client, baseURL string, sid string, user string) ([]shareNode, error) {

	sharesUrl := fmt.Sprintf("%s/cgi-bin/filemanager/utilRequest.cgi", baseURL)
	params := url.Values{}
	params.Set("func", "get_tree")
	params.Set("node", "share_root")
	params.Set("is_iso", "0")
	params.Set("check_acl", "1")
	params.Set("vol", "0")
	params.Set("sid", sid)

	log.WithField("user", user).Debugf("calling qnap get_tree endpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sharesUrl, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.WithField("user", user).WithError(err).Error("getShares: failed to close response body")
		}
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	log.WithFields(log.Fields{
		"user": user,
		"body": strings.TrimSpace(string(body)),
	}).Tracef("qnap shares api response received")

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get_tree HTTP %d - body: %s", resp.StatusCode, string(body))
	}

	// parse as array
	var arr []shareNode
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, fmt.Errorf("unable to parse get_tree response: %s", err)
	}
	log.WithFields(log.Fields{
		"user":     user,
		"response": fmt.Sprintf("%+v", arr),
	}).Trace("parsed qnap get_tree response")

	return arr, nil
}
