package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// -----------------------------
// Configuration constants/variables
// -----------------------------

const (
	// AppName is the name of the application
	AppName = "SftpgoQnapAuthGateway"
	// AppVersion is the current version of the application
	AppVersion = "0.1.0"

	// AuthPath server listen address and endpoint
	AuthPath = "/auth"
	// MaxBodyBytes is limiting body size for JSON parsing
	MaxBodyBytes = 5 * 1024 // 5 KiB

	// HTTPTimeout defines HTTP client timeout for every HTTP request to QNAP/sftpgo API
	HTTPTimeout = 7 * time.Second
	// HTTPServerReadTimeout defines the HTTP server read timeout
	HTTPServerReadTimeout = 15 * time.Second
	// HTTPServerWriteTimeout defines the HTTP server write timeout
	HTTPServerWriteTimeout = 15 * time.Second
	// HTTPServerIdleTimeout defines the HTTP server idle timeout
	HTTPServerIdleTimeout = 60 * time.Second

	// QnapSharePrefix is the prefix that will be added for every share name
	// This will be used as a human-readable identifier for the share in sftpgo
	QnapSharePrefix = "QNAP_SHARE_"
)

var (
	// AuthGwAddr defines to which address it's binding it on
	AuthGwAddr string
	// AuthGwPort defines to which port it's binding it on'
	AuthGwPort string
	// AuthGwHTTPS defines if it's running in HTTPS mode or not'
	AuthGwHTTPS bool

	// QnapURL defines the full URL to use for QNAP API calls
	// (example: https://10.0.0.100)
	QnapURL string
	// QnapCheckCert defines if the certificate of QNAP should be checked when accessing QNAP API
	QnapCheckCert bool
	// QnapSharePath defines a path for QNAP shares where the share is located
	// (example: /share/{path}/; as in /share/Public)
	QnapSharePath string

	// SftpgoAPIURL is the URL of the sftpgo API
	// (only https://sftpgo.example.com; do NOT include the /api/ prefix)
	SftpgoAPIURL string
	// SftpgoCheckCert defines if the certificate of sftpgo should be checked when accessing sftpgo REST API
	SftpgoCheckCert bool
	// SftpgoAPIUser is the username to use for authentication with the sftpgo API
	SftpgoAPIUser string
	// SftpgoAPIPass is the password to use for authentication with the sftpgo API
	SftpgoAPIPass string
	// SftpgoHomeDir is the home directory to use for the sftpgo user
	// (default: /var/tmp; "{username}" will be replaced with the username)
	SftpgoHomeDir string
	// SftpgoVirtualFolderSync is a flag to enable/disable virtual folder sync after successful
	// authentication to QNAP NAS: When enabled, it will create, delete or update virtual folders
	// in sftpgo based on the shares accessible for specific user during time of login.
	SftpgoVirtualFolderSync bool
	// SftpgoManagedFolderDesc is the description text that will be added to every share description
	SftpgoManagedFolderDesc string

	// SftpgoAccountExpiration is the duration for which the user account will be valid after successful login.
	SftpgoAccountExpiration string
	// SftpgoAccountExpirationTime is the parsed duration value of SftpgoAccountExpiration.
	SftpgoAccountExpirationTime time.Duration

	SharePermsDeny      []string
	SharePermsListOnly  = []string{"list"}
	SharePermsReadOnly  = []string{"list", "download"}
	SharePermsReadWrite = []string{"*"}
)

// contextKey is a string wrapper for context keys.
type contextKey string

// loggerContextKey is the context key for the logger instance.
const loggerContextKey contextKey = "logger"

// -----------------------------
// Main
// -----------------------------

// main is the main function.
func main() {
	// Setup logger
	setupLogger()

	// Load all settings, primarily from environment variables
	loadSettings()

	// HTTP server mux and handler
	mux := http.NewServeMux()
	mux.HandleFunc(AuthPath, webAuthHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", AuthGwAddr, AuthGwPort),
		Handler:      HTTPServerMiddleware(mux),
		ReadTimeout:  HTTPServerReadTimeout,
		WriteTimeout: HTTPServerWriteTimeout,
		IdleTimeout:  HTTPServerIdleTimeout,
	}

	// Check if we are running in HTTPS mode
	authGwScheme := "http"
	if AuthGwHTTPS {
		authGwScheme = "https"
		log.Fatal("not yet implemented")
	}

	if !AuthGwHTTPS {
		log.Warn("running in HTTP mode. not secure. not recommended for production!")
	}

	// Start server in goroutine
	go func() {
		log.WithFields(log.Fields{
			"authgw": fmt.Sprintf("%s://%s:%s%s", authGwScheme, AuthGwAddr, AuthGwPort, AuthPath),
			"qnap":   QnapURL,
			"sftpgo": SftpgoAPIURL,
		}).Info("starting qnap auth gateway")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("error starting HTTP server")
			os.Exit(1)
		}
	}()

	// handle graceful shutdown
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

// loadSettings loads all settings from environment variables.
func loadSettings() {
	// --- QNAP API Configuration ---
	QnapURL = normalizeURL(getEnv("QNAP_URL", "https://host.docker.internal"))
	QnapSharePath = strings.TrimSpace(strings.TrimSuffix(getEnv("QNAP_SHARE_PATH", "/share/{name}"), "/"))

	QnapCheckCert = parseBoolEnv("QNAP_CHECK_CERT", true)
	if !QnapCheckCert {
		log.Warn("QNAP_CHECK_CERT is disabled — certificate validation is skipped. " +
			"Not recommended for production!")
	}

	// --- SFTPGo API Configuration ---
	SftpgoAPIURL = normalizeURL(getEnv("SFTPGO_API_URL", "http://host.docker.internal:8080"))
	SftpgoAPIUser = getEnv("SFTPGO_API_USER", "sa-qnap-authgw")
	SftpgoAPIPass = getEnv("SFTPGO_API_PASS", "")

	SftpgoVirtualFolderSync = parseBoolEnv("SFTPGO_FOLDER_SYNC", false)
	SftpgoManagedFolderDesc = getEnv("SFTPGO_FOLDER_DESCRIPTION", "QNAP Share: {name} / Managed by sftpgo-qnap-auth-gateway")
	SftpgoAccountExpiration = getEnv("SFTPGO_ACCOUNT_EXPIRATION", "5m")

	var parseErr error
	SftpgoAccountExpirationTime, parseErr = time.ParseDuration(SftpgoAccountExpiration)
	if parseErr != nil {
		log.WithError(parseErr).Fatalf("invalid SFTPGO_ACCOUNT_EXPIRATION value: %q", SftpgoAccountExpiration)
	}

	if SftpgoVirtualFolderSync && SftpgoAPIPass == "" {
		log.Fatal("SFTPGO_API_PASS is not set, but SFTPGO_FOLDER_SYNC is enabled!")
	}

	SftpgoCheckCert = parseBoolEnv("SFTPGO_CHECK_CERT", true)
	if !SftpgoCheckCert {
		log.Warn("SFTPGO_CHECK_CERT is disabled — certificate validation is skipped. " +
			"Not recommended for production!")
	}

	SftpgoHomeDir = getEnv("SFTPGO_HOME_DIR", "/var/tmp")

	// --- Auth Gateway Configuration ---
	AuthGwHTTPS = parseBoolEnv("AUTHGW_HTTPS", false)
	AuthGwAddr = getEnv("AUTHGW_ADDR", "0.0.0.0")
	AuthGwPort = getEnv("AUTHGW_PORT", "9999")
}

// setupLogger is initializing the logger and setting up the log level.
func setupLogger() {
	// Setup logging
	log.SetOutput(os.Stdout)
	log.SetReportCaller(true)
	//nolint:exhaustruct // defaults acceptable
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02T15:04:05.000",
		DisableColors:    false,
		ForceColors:      false,
		DisableQuote:     false,
		ForceQuote:       true,
		PadLevelText:     true,
		DisableSorting:   false,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
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

// --- Helper Functions ---

// getEnv retrieves environment variable with the ability of fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// normalizeURL trims spaces and removes trailing slashes from a URL.
func normalizeURL(raw string) string {
	return strings.TrimSpace(strings.TrimSuffix(raw, "/"))
}

// parseBoolEnv reads an environment variable as a boolean with a default fallback.
func parseBoolEnv(key string, defaultValue bool) bool {
	val := strings.ToLower(strings.TrimSpace(getEnv(key, strconv.FormatBool(defaultValue))))
	switch val {
	case "true", "1", "yes", "y", "on":
		return true
	case "false", "0", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}
