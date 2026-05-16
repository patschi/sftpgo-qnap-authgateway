package main

import (
	"context"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TraceLevel is a custom log level below DebugLevel used to preserve
// the original logrus-style Trace verbosity within zap, which has no
// built-in Trace level.
const TraceLevel = zapcore.Level(-2)

// logger is the package-wide sugared zap logger.
// It is initialized in setupLogger() before any logging happens.
var logger *zap.SugaredLogger

// -----------------------------
// Application constants
// -----------------------------

const (
	// AppName is the name of the application
	AppName = "SftpgoQnapAuthGateway"
	// AppVersion is the current version of the application
	AppVersion = "0.2.0"

	// AuthGwAddr defines to which address it's binding it on
	AuthGwAddr = "0.0.0.0"
	// AuthGwPort defines to which port it's binding it on
	AuthGwPort = "9999"
	// AuthPath listen path endpoint for authentication
	AuthPath = "/auth"
	// AuthHealthPath listen path endpoint for health check
	AuthHealthPath = "/healthz"

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

	// DefaultAccountExpiration is the default duration a sftpgo user account remains valid after login.
	DefaultAccountExpiration = 5 * time.Minute
	// DefaultAuthCacheTime is the default duration sftpgo caches a successful authentication for.
	DefaultAuthCacheTime = 5 * time.Minute
)

var (
	// AppStartTime is the time when the application started
	AppStartTime time.Time

	// SharePermsDeny is the permission without any permissions
	SharePermsDeny []string
	// SharePermsListOnly is the permission to only list the share
	SharePermsListOnly = []string{"list"}
	// SharePermsReadOnly is the permission to only read the files within the share
	SharePermsReadOnly = []string{"list", "download"}
	// SharePermsReadWrite is the permission to read and write the files within the share
	SharePermsReadWrite = []string{"*"}
)

// -----------------------------
// Duration type
// -----------------------------

// Duration wraps time.Duration to marshal as a human-readable string in JSON.
type Duration time.Duration

// MarshalText implements encoding.TextMarshaler.
//
//nolint:unparam // error return is part of the encoding.TextMarshaler interface contract
func (d *Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(*d).String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	dur, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// AsDuration returns the value as a standard time.Duration.
func (d *Duration) AsDuration() time.Duration {
	return time.Duration(*d)
}

// -----------------------------
// Settings types
// -----------------------------

// AuthGatewaySettings are settings for this auth gateway.
type AuthGatewaySettings struct {
	// LogLevel defines the log level to use (debug, info, warn, error, fatal)
	LogLevel string `env:"LOG_LEVEL" json:"log_level"`
	// CertificateFile is the path to the certificate file
	CertificateFile string `env:"AUTHGW_CERTIFICATE_FILE" json:"certificate_file"`
	// KeyFile is the path to the key file
	KeyFile string `env:"AUTHGW_KEY_FILE" json:"key_file"`
}

// QnapSettings are settings for QNAP.
type QnapSettings struct {
	// URL defines the full URL to use for QNAP API calls (example: https://10.0.0.100)
	URL string `env:"QNAP_URL" json:"url" normalize:"url"`
	// CheckCert defines if the certificate of QNAP should be checked when accessing QNAP API
	CheckCert bool `env:"QNAP_CHECK_CERT" json:"check_cert"`
	// SharePath defines a path for QNAP shares where the share is located (example: /share/{name}/ = /share/Public)
	SharePath string `env:"QNAP_SHARE_PATH" json:"share_path" normalize:"url"`
	// PasswdFile is the path to the passwd file (usually within the container)
	// This is hidden as it is used during development only.
	PasswdFile string `env:"QNAP_PASSWD_FILE" json:"passwd_file"`
}

// SftpgoAPISettings are settings on how to access sftpgo API.
type SftpgoAPISettings struct {
	// URL is the URL of the sftpgo API (only https://sftpgo.example.com; do NOT include the /api/ prefix)
	URL string `env:"SFTPGO_API_URL" json:"url" normalize:"url"`
	// CheckCert defines if the certificate of sftpgo should be checked when accessing sftpgo REST API
	CheckCert bool `env:"SFTPGO_API_CHECK_CERT" json:"check_cert"`
	// Username is the username to use for authentication with the sftpgo API
	Username string `env:"SFTPGO_API_USER" json:"user"`
	// Password is the password to use for authentication with the sftpgo API
	Password string `env:"SFTPGO_API_PASS" json:"pass"`
}

// SftpgoSettings are settings for sftpgo.
type SftpgoSettings struct {
	// API contains the settings for accessing the sftpgo API
	API SftpgoAPISettings `json:"api"`
	// HomeDir is the home directory for the sftpgo user (default: /var/tmp; "{username}" is replaced with the username)
	HomeDir string `env:"SFTPGO_HOME_DIR" json:"home_dir"`
	// VirtualFolderSync is a flag to enable/disable virtual folder sync after successful
	// authentication to QNAP NAS: When enabled, it will create, delete, or update virtual folders
	// in sftpgo based on the shares accessible for a specific user during the time of login.
	VirtualFolderSync bool `env:"SFTPGO_FOLDER_SYNC" json:"virtual_folder_sync"`
	// ManagedFolderDesc is the description text that will be added to every share description
	ManagedFolderDesc string `env:"SFTPGO_FOLDER_DESCRIPTION" json:"managed_folder_desc"`
	// AccountExpiration is the duration for which the user account will be valid after successful login
	AccountExpiration Duration `env:"SFTPGO_ACCOUNT_EXPIRATION" json:"account_expiration"`
	// AuthCacheTime is the duration for how long sftpgo should cache the successful login
	AuthCacheTime Duration `env:"SFTPGO_AUTH_CACHE_TIME" json:"auth_cache_time"`
}

// Settings is the root configuration struct.
type Settings struct {
	// AuthGateway are settings for this auth gateway
	AuthGateway AuthGatewaySettings `json:"auth_gateway"`
	// Qnap are settings for QNAP
	Qnap QnapSettings `json:"qnap"`
	// Sftpgo are settings for sftpgo
	Sftpgo SftpgoSettings `json:"sftpgo"`
}

// config is the global configuration with embedded default values.
// Environment variables listed in `env` struct tags override these defaults.
//
//nolint:gosec // G101: file paths and usernames below are defaults, not hardcoded credentials.
var config = Settings{
	AuthGateway: AuthGatewaySettings{
		LogLevel:        "info",
		CertificateFile: "",
		KeyFile:         "",
	},
	Qnap: QnapSettings{
		URL:        "https://host.docker.internal",
		CheckCert:  true,
		SharePath:  "/share/{name}",
		PasswdFile: "/qnap_passwd",
	},
	Sftpgo: SftpgoSettings{
		API: SftpgoAPISettings{
			URL:       "http://sftpgo:8080",
			CheckCert: true,
			Username:  "sa-qnap-authgw",
			Password:  "",
		},
		HomeDir:           "/var/tmp",
		VirtualFolderSync: false,
		ManagedFolderDesc: "QNAP Share: {name} / Managed by sftpgo-qnap-auth-gateway",
		AccountExpiration: Duration(DefaultAccountExpiration),
		AuthCacheTime:     Duration(DefaultAuthCacheTime),
	},
}

// contextKey is a string wrapper for context keys.
type contextKey string

// loggerContextKey is the context key for the logger instance.
const loggerContextKey contextKey = "logger"

// -----------------------------
// Main
// -----------------------------

// main is the main function.
func main() {
	AppStartTime = time.Now()

	// Load settings from environment variables before logger setup, so LOG_LEVEL is available.
	if err := loadEnvInto(&config); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to load settings: %v\n", err)
		os.Exit(1)
	}

	// Setup logger using the loaded log level.
	setupLogger()
	defer func() { _ = logger.Sync() }() // flush buffered log entries on shutdown

	// Validate loaded settings, log warnings, and abort on fatal misconfigurations.
	validateSettings()

	mux := http.NewServeMux()
	mux.HandleFunc(AuthPath, webAuthHandler)
	mux.HandleFunc(AuthHealthPath, webHealthHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", AuthGwAddr, AuthGwPort),
		Handler:      HTTPServerMiddleware(mux),
		ReadTimeout:  HTTPServerReadTimeout,
		WriteTimeout: HTTPServerWriteTimeout,
		IdleTimeout:  HTTPServerIdleTimeout,
	}

	// HTTPS is enabled when both CertificateFile and KeyFile are set.
	useHTTPS := config.AuthGateway.CertificateFile != "" && config.AuthGateway.KeyFile != ""
	authGwScheme := "http"
	if useHTTPS {
		authGwScheme = "https"
	} else {
		logger.Warn("running in HTTP mode. not secure. not recommended for production!")
	}

	go func() {
		logger.Infow("starting qnap auth gateway",
			"authgw", fmt.Sprintf("%s://%s:%s%s", authGwScheme, AuthGwAddr, AuthGwPort, AuthPath),
			"qnap", config.Qnap.URL,
			"sftpgo", config.Sftpgo.API.URL,
		)
		var err error
		if useHTTPS {
			err = server.ListenAndServeTLS(config.AuthGateway.CertificateFile, config.AuthGateway.KeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalw("error starting HTTP server", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info("shutdown signal received, stopping...")

	//nolint:mnd // internal fixed timeout to allow the HTTP server to gracefully shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Errorw("http server shutdown error", "error", err)
	} else {
		logger.Info("http server stopped gracefully")
	}
}

// loggableConfig is a fmt.Stringer that renders the current settings as JSON
// with the API password masked. Implementing fmt.Stringer lets zap evaluate
// the value lazily, so the JSON marshal only happens when debug is enabled.
type loggableConfig struct{}

// String implements fmt.Stringer.
func (loggableConfig) String() string {
	cfg := config
	if cfg.Sftpgo.API.Password != "" {
		cfg.Sftpgo.API.Password = "**MASKED**"
	}
	data, err := json.Marshal(&cfg)
	if err != nil {
		return fmt.Sprintf("(failed to marshal settings: %v)", err)
	}
	return string(data)
}

// validateSettings checks the loaded configuration for invalid or unsafe values,
// logs warnings, and calls logger.Fatal for unrecoverable misconfigurations.
func validateSettings() {
	logger.Debugw("loaded settings", "settings", loggableConfig{})

	// Both AUTHGW_CERTIFICATE_FILE and AUTHGW_KEY_FILE must be set together to enable HTTPS.
	certSet := config.AuthGateway.CertificateFile != ""
	keySet := config.AuthGateway.KeyFile != ""
	if certSet != keySet {
		logger.Fatal("AUTHGW_CERTIFICATE_FILE and AUTHGW_KEY_FILE must both be set to enable HTTPS")
	}

	if !config.Qnap.CheckCert {
		logger.Warn("QNAP_CHECK_CERT is disabled - certificate validation is skipped. " +
			"Not recommended for production!")
	}

	if !config.Sftpgo.API.CheckCert {
		logger.Warn("SFTPGO_API_CHECK_CERT is disabled - certificate validation is skipped. " +
			"Not recommended for production!")
	}

	if config.Sftpgo.AuthCacheTime > config.Sftpgo.AccountExpiration {
		logger.Fatal("SFTPGO_AUTH_CACHE_TIME cannot be longer than SFTPGO_ACCOUNT_EXPIRATION")
	}

	if config.Sftpgo.VirtualFolderSync && config.Sftpgo.API.Password == "" {
		logger.Fatal("SFTPGO_API_PASS is not set, but SFTPGO_FOLDER_SYNC is enabled!")
	}

	if checkPasswdFileExistence() {
		logger.Info("QNAP passwd file detected: it will be used to gather user's UID/GID information")
	} else {
		logger.Warn("QNAP passwd file not detected: it will NOT be used to gather user's UID/GID user information")
	}
}

// parseLogLevel parses a textual log level into a zapcore.Level.
// It accepts the standard zap levels plus the project-specific "trace".
func parseLogLevel(s string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return TraceLevel, nil
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	case "panic":
		return zapcore.PanicLevel, nil
	}
	return zapcore.InfoLevel, fmt.Errorf("not a valid log level: %q", s)
}

// encodeLevel is a zap level encoder that knows how to render the custom TraceLevel.
func encodeLevel(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	if l == TraceLevel {
		enc.AppendString("TRACE")
		return
	}
	zapcore.CapitalLevelEncoder(l, enc)
}

// encodeCaller renders the caller as the fully-qualified function name,
// matching the previous logrus CallerPrettyfier behavior.
func encodeCaller(c zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(c.Function)
}

// setupLogger initializes the package-wide sugared zap logger based on the configured log level.
// It supports the project-specific "trace" level via a custom zapcore.LevelEnabler.
func setupLogger() {
	logLevelStr := strings.TrimSpace(config.AuthGateway.LogLevel)

	var level zapcore.Level
	// initialLog is deferred until after the logger is constructed below,
	// so the parse-time message is emitted through the actual logger.
	var initialLog func()

	if logLevelStr == "" {
		level = zapcore.DebugLevel
		initialLog = func() { logger.Info("LOG_LEVEL not set, defaulting to DEBUG") }
	} else if parsed, err := parseLogLevel(logLevelStr); err != nil {
		level = zapcore.InfoLevel
		initialLog = func() {
			logger.Warnf("Invalid LOG_LEVEL=%q, defaulting to INFO: %v", logLevelStr, err)
		}
	} else {
		level = parsed
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:             "time",
		LevelKey:            "level",
		NameKey:             "logger",
		CallerKey:           "caller",
		FunctionKey:         zapcore.OmitKey,
		MessageKey:          "msg",
		StacktraceKey:       "stacktrace",
		SkipLineEnding:      false,
		LineEnding:          zapcore.DefaultLineEnding,
		EncodeLevel:         encodeLevel,
		EncodeTime:          zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000"),
		EncodeDuration:      zapcore.StringDurationEncoder,
		EncodeCaller:        encodeCaller,
		EncodeName:          nil,
		NewReflectedEncoder: nil,
		ConsoleSeparator:    "",
	}

	levelEnabler := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= level
	})

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.Lock(os.Stdout),
		levelEnabler,
	)

	zapLogger := zap.New(core, zap.AddCaller())
	logger = zapLogger.Sugar()

	if initialLog != nil {
		initialLog()
	}

	levelStr := strings.ToUpper(level.String())
	if level == TraceLevel {
		levelStr = "TRACE"
	}
	logger.Infof("%s %s starting up", AppName, AppVersion)
	logger.Infow("current log level", "loglevel", levelStr)
}

// -----------------------------
// Environment loading
// -----------------------------

// loadEnvInto populates the fields of s from environment variables using `env` struct tags.
// Only variables that are explicitly set in the environment override the current (default) value.
// Supported field types: string, bool, types implementing encoding.TextUnmarshaler, and nested structs.
// String fields tagged with normalize:"url" have trailing slashes and surrounding whitespace trimmed.
func loadEnvInto(s any) error {
	rv := reflect.ValueOf(s)
	if rv.Kind() != reflect.Pointer || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("loadEnvInto: expected pointer to struct, got %T", s)
	}
	return populateFromEnv(rv.Elem())
}

// populateFromEnv recursively populates struct fields from environment variables.
func populateFromEnv(rv reflect.Value) error {
	rt := rv.Type()
	for i := range rt.NumField() {
		if err := populateStructField(rt.Field(i), rv.Field(i)); err != nil {
			return err
		}
	}
	return nil
}

// populateStructField applies environment variable overrides to a single struct field,
// recursing into nested structs that have no env tag of their own.
func populateStructField(field reflect.StructField, fv reflect.Value) error {
	envKey := field.Tag.Get("env")

	// Fields without an env tag are either nested config groups (recurse) or ignored.
	if envKey == "" {
		if fv.Kind() == reflect.Struct {
			return populateFromEnv(fv)
		}
		return nil
	}

	rawVal, present := os.LookupEnv(envKey)
	if !present {
		return nil // env var not set; keep default
	}
	rawVal = strings.TrimSpace(rawVal)

	// Prefer TextUnmarshaler if implemented (e.g., Duration, time.Time).
	// Checked before the Kind switch so struct types implementing
	// TextUnmarshaler are unmarshaled instead of recursed into.
	if fv.CanAddr() {
		if unmarshaler, isUnmarshaler := fv.Addr().Interface().(encoding.TextUnmarshaler); isUnmarshaler {
			if err := unmarshaler.UnmarshalText([]byte(rawVal)); err != nil {
				return fmt.Errorf("env %s: %w", envKey, err)
			}
			return nil
		}
	}

	return setScalarField(field, fv, envKey, rawVal)
}

// setScalarField writes a string-encoded env value into a primitive scalar field.
// Supported kinds: string (with optional url normalization) and bool.
func setScalarField(field reflect.StructField, fv reflect.Value, envKey, rawVal string) error {
	switch fv.Kind() { //nolint:exhaustive // only string and bool are supported scalars; other kinds fall through to the default error
	case reflect.String:
		if field.Tag.Get("normalize") == "url" {
			rawVal = normalizeURL(rawVal)
		}
		fv.SetString(rawVal)

	case reflect.Bool:
		b, err := strconv.ParseBool(rawVal)
		if err != nil {
			return fmt.Errorf("env %s: invalid boolean value %q: %w", envKey, rawVal, err)
		}
		fv.SetBool(b)

	default:
		return fmt.Errorf("env %s: unsupported field type %s", envKey, fv.Type())
	}
	return nil
}

// normalizeURL trims surrounding whitespace and trailing slashes from a URL or path.
func normalizeURL(raw string) string {
	return strings.TrimSpace(strings.TrimSuffix(raw, "/"))
}
