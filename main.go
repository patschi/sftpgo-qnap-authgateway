package main

import (
	"bytes"
	"context"
	"encoding"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	// AuthGwAddr defines to which address it's binding it on
	AuthGwAddr string
	// AuthGwPort defines to which port it's binding it on'
	AuthGwPort string
	// AuthGwHttps defines if it's running in HTTPS mode or not'
	AuthGwHttps bool

	// QnapUrl defines the full URL to use for QNAP API calls
	// (example: https://10.0.0.100)
	QnapUrl string
	// QnapCheckCert defines if the certificate of QNAP should be checked when accessing QNAP API
	QnapCheckCert bool
	// QnapSharePath defines a path for QNAP shares where the share is located
	// (example: /share/{path}/; as in /share/Public)
	QnapSharePath string

	// SftpgoApiUrl is the URL of the sftpgo API
	// (only https://sftpgo.example.com; do NOT include the /api/ prefix)
	SftpgoApiUrl string
	// SftpgoCheckCert defines if the certificate of sftpgo should be checked when accessing sftpgo REST API
	SftpgoCheckCert bool
	// SftpgoApiToken is the token to use for authentication with the sftpgo API
	SftpgoApiToken string
	// SftpgoVirtualFolderSync is a flag to enable/disable virtual folder sync after successful
	// authentication to QNAP NAS: When enabled, it will create, delete or update virtual folders
	// in sftpgo based on the shares accessible for specific user during time of login.
	SftpgoVirtualFolderSync bool

	// Share Permission Definitions
	SharePermsDeny      = []string{}
	SharePermsListOnly  = []string{"list"}
	SharePermsReadOnly  = []string{"list", "download"}
	SharePermsReadWrite = []string{"*"}
)

// -----------------------------
// Types for auth gateway
// -----------------------------

// authRequest is the incoming request from sftpgo (parameters which are used for this gateway)
type authRequest struct {
	Username            string      `json:"username"`
	Password            SecureBytes `json:"password"`
	Protocol            string      `json:"protocol"` // SSH, FTP, DAV, HTTP
	IP                  string      `json:"ip"`
	PublicKey           string      `json:"public_key"`
	KeyboardInteractive string      `json:"keyboard_interactive"`
	TlsCert             string      `json:"tls_cert"`
}

// -----------------------------
// Types for QNAP responses
// -----------------------------

// qnapLoginResp is the response from QNAP API for login requests
type qnapLoginResp struct {
	XMLName    xml.Name `xml:"QDocRoot"`
	AuthPassed string   `xml:"authPassed"`
	AuthSid    string   `xml:"authSid"`
	ErrorValue string   `xml:"errorValue"`
}

// qnapShareNode is a single shared folder
type qnapShareNode struct {
	Text         string `json:"text"`
	ID           string `json:"id"`
	Cls          string `json:"cls"`
	IconCls      string `json:"iconCls"`
	NoSupportACL int    `json:"noSupportACL"`
}

// -----------------------------
// Types for incoming request and SFTPGo response
// -----------------------------

// sftpgoVirtualFolder links a virtual folder to a single folder in sftpgo
type sftpgoVirtualFolder struct {
	Name        string `json:"name"`
	VirtualPath string `json:"virtual_path"`
}

// sftpgoFolder is a single virtual folder in sftpgo
type sftpgoFolder struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description,omitempty"`
	MappedPath  string                  `json:"mapped_path"`
	Filesystem  *sftpgoFolderFilesystem `json:"filesystem"`
}

// sftpgoFolderFilesystem is the filesystem provider for a virtual folder
// (currently only local filesystem is supported; its value is always 0)
type sftpgoFolderFilesystem struct {
	Provider int `json:"provider"`
}

// sftpgoResponse is the final response to sftpgo after authentication
type sftpgoResponse struct {
	Id             int32                 `json:"id,omitempty"`
	Status         int                   `json:"status"`                    // 0 = disabled, 1 = enabled
	Username       string                `json:"username"`                  // empty = disallow login
	Uid            int32                 `json:"uid,omitempty"`             // 0 = no change
	Gid            int32                 `json:"gid,omitempty"`             // 0 = no change
	ExpirationDate int64                 `json:"expiration_date,omitempty"` // 0 = no expiration; unix timestamp in ms
	HomeDir        string                `json:"home_dir,omitempty"`
	VirtualFolders []sftpgoVirtualFolder `json:"virtual_folders,omitempty"` // user-facing folders seen after login
	Permissions    map[string][]string   `json:"permissions,omitempty"`     // permissions for each virtual folder
	Meta           map[string]string     `json:"meta,omitempty"`
	Error          string                `json:"error,omitempty"`
}

// -----------------------------
// Custom data type for secure bytes
// -----------------------------

// Ensure interface conformance at compile time.
var _ encoding.TextUnmarshaler = (*SecureBytes)(nil)

// SecureBytes is a byte slice used to store passwords in the database.
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
		log.Warn("Wipe called on nil SecureBytes")
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

// WipeBuffer is a custom Function to wipe buffers explicitly.
// Helper function variant: call as WipeBuffer(&buf).
func WipeBuffer(buf *bytes.Buffer) {
	if buf == nil {
		log.Warn("WipeBuffer called on nil buffer")
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

// -----------------------------
// Helper functions
// -----------------------------

// getEnv retrieves environment variable with the ability of fallback value
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
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

	// Set the log level
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
	// Load all settings, primarily from environment variables
	loadSettings()

	// HTTP server mux and handler
	mux := http.NewServeMux()
	mux.HandleFunc(AuthPath, webAuthHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", AuthGwAddr, AuthGwPort),
		Handler: HttpServerMiddleware(mux),

		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Check if we are running in HTTPS mode
	AuthGwScheme := "http"
	if AuthGwHttps {
		AuthGwScheme = "https"
		log.Fatal("not yet implemented")
	} else {
		log.Warn("running in HTTP mode. not secure. not recommended for production!")
	}

	// Start server in goroutine
	go func() {
		log.WithFields(log.Fields{
			"authgw": fmt.Sprintf("%s://%s:%s%s", AuthGwScheme, AuthGwAddr, AuthGwPort, AuthPath),
			"qnap":   QnapUrl,
			"sftpgo": SftpgoApiUrl,
		}).Info("starting QNAP auth gateway")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("HTTP server error: %v", err)
			os.Exit(1)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutdown signal received, stopping...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.WithError(err).Errorf("http server shutdown error")
	} else {
		log.Info("http server stopped gracefully")
	}
}

func loadSettings() {
	// Initialize values and read from environment variables

	// QNAP API
	QnapUrl = getEnv("QNAP_URL", "https://host.docker.internal")
	QnapUrl = strings.TrimSpace(strings.TrimSuffix(QnapUrl, "/"))

	QnapSharePath = getEnv("QNAP_SHARE_PATH", "/share/{name}/")
	QnapSharePath = strings.TrimSpace(QnapSharePath)

	QnapCheckCertStr := getEnv("QNAP_CHECK_CERT", "true")
	QnapCheckCert = true
	if strings.ToLower(strings.TrimSpace(QnapCheckCertStr)) == "false" {
		QnapCheckCert = false
		log.Warn("QNAP_CHECK_CERT is disabled and certificate of QNAP is not validated. " +
			"Not recommended for production!")
	}

	// sftpgo API
	SftpgoApiUrl = getEnv("SFTPGO_API_URL", "http://host.docker.internal:8080")
	SftpgoApiUrl = strings.TrimSpace(strings.TrimSuffix(SftpgoApiUrl, "/"))

	SftpgoApiToken = getEnv("SFTPGO_API_TOKEN", "")

	SftpgoVirtualFolderSyncStr := getEnv("SFTPGO_FOLDER_SYNC", "false")
	SftpgoVirtualFolderSync = false
	if strings.ToLower(strings.TrimSpace(SftpgoVirtualFolderSyncStr)) == "true" {
		SftpgoVirtualFolderSync = true
		log.WithField("state", SftpgoVirtualFolderSync).Info("SFTPGO virtual folder sync state")
	}

	if SftpgoVirtualFolderSync && SftpgoApiToken == "" {
		log.Fatal("SFTPGO_API_TOKEN is not set, but SFTPGO_FOLDER_SYNC is enabled")
	}

	SftpgoCheckCertStr := getEnv("SFTPGO_CHECK_CERT", "true")
	SftpgoCheckCert = true
	if strings.ToLower(strings.TrimSpace(SftpgoCheckCertStr)) == "false" {
		SftpgoCheckCert = false
		log.Warn("SFTPGO_CHECK_CERT is disabled and certificate of sftpgo is not validated. " +
			"Not recommended for production!")
	}

	// Auth Gateway configuration
	AuthGwHttps = false
	AuthGwHttpsStr := getEnv("AUTHGW_HTTPS", "false")
	if strings.ToLower(strings.TrimSpace(AuthGwHttpsStr)) == "true" {
		AuthGwHttps = true
	}

	AuthGwAddr = getEnv("AUTHGW_ADDR", "0.0.0.0")
	AuthGwPort = getEnv("AUTHGW_PORT", "9999")
}
