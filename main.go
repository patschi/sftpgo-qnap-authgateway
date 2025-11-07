package main

import (
	"context"
	"errors"
	"fmt"
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
// Configuration constants/variables
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

	// QnapSharePrefix is the prefix that will be added for every share name
	// This will be used as a human-readable identifier for the share in sftpgo
	QnapSharePrefix = "QNAP_SHARE_"
	// SftpgoManagedFolderDesc is the description text that will be added to every share description
	SftpgoManagedFolderDesc = "QNAP Share: %s"
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

	SharePermsDeny      = []string{}
	SharePermsListOnly  = []string{"list"}
	SharePermsReadOnly  = []string{"list", "download"}
	SharePermsReadWrite = []string{"*"}
)

// -----------------------------
// Main
// -----------------------------

// init initializes the application
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

// main is the main function
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
	}

	if !AuthGwHttps {
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

// loadSettings loads all settings from environment variables
func loadSettings() {
	// --- QNAP API Configuration ---
	QnapUrl = normalizeURL(getEnv("QNAP_URL", "https://host.docker.internal"))
	QnapSharePath = strings.TrimSpace(getEnv("QNAP_SHARE_PATH", "/share/{name}/"))

	QnapCheckCert = parseBoolEnv("QNAP_CHECK_CERT", true)
	if !QnapCheckCert {
		log.Warn("QNAP_CHECK_CERT is disabled — certificate validation is skipped. " +
			"Not recommended for production!")
	}

	// --- SFTPGo API Configuration ---
	SftpgoApiUrl = normalizeURL(getEnv("SFTPGO_API_URL", "http://host.docker.internal:8080"))
	SftpgoApiToken = getEnv("SFTPGO_API_TOKEN", "")

	SftpgoVirtualFolderSync = parseBoolEnv("SFTPGO_FOLDER_SYNC", false)
	log.WithField("state", SftpgoVirtualFolderSync).Info("SFTPGO virtual folder sync state")

	if SftpgoVirtualFolderSync && SftpgoApiToken == "" {
		log.Fatal("SFTPGO_API_TOKEN is not set, but SFTPGO_FOLDER_SYNC is enabled")
	}

	SftpgoCheckCert = parseBoolEnv("SFTPGO_CHECK_CERT", true)
	if !SftpgoCheckCert {
		log.Warn("SFTPGO_CHECK_CERT is disabled — certificate validation is skipped. " +
			"Not recommended for production!")
	}

	// --- Auth Gateway Configuration ---
	AuthGwHttps = parseBoolEnv("AUTHGW_HTTPS", false)
	AuthGwAddr = getEnv("AUTHGW_ADDR", "0.0.0.0")
	AuthGwPort = getEnv("AUTHGW_PORT", "9999")
}

// --- Helper Functions ---

// getEnv retrieves environment variable with the ability of fallback value
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
	val := strings.ToLower(strings.TrimSpace(getEnv(key, fmt.Sprintf("%v", defaultValue))))
	switch val {
	case "true", "1", "yes", "y", "on":
		return true
	case "false", "0", "no", "n", "off":
		return false
	default:
		return defaultValue
	}
}
