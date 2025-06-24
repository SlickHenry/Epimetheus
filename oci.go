package main

import (
	"container/ring"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Configuration struct {
	TenancyOCID        string
	UserOCID           string
	KeyFingerprint     string
	PrivateKeyPath     string
	Region             string
	APIBaseURL         string
	APIVersion         string
	SyslogProtocol     string
	SyslogServer       string
	SyslogPort         string
	LogLevel           string
	LogFile            string
	FetchInterval      int
	ConnTimeout        int
	MaxMsgSize         int
	MarkerFile         string
	FieldMapFile       string
	EventMapFile       string
	Verbose            bool
	MaxRetries         int
	RetryDelay         int
	HealthCheckPort    int
	TestMode           bool
	ValidateMode       bool
	ShowVersion        bool
	EventCacheSize       int
	EventCacheWindow     int
	EnableEventCache     bool
	InitialLookbackHours int
	PollOverlapMinutes   int
	MaxEventsPerPoll     int
	CompartmentMode      string
	CompartmentIDs       []string
}

type FieldMapping struct {
	OrderedFields          []string                    `json:"ordered_fields"`
	FieldMappings          map[string]string           `json:"field_mappings"`
	Lookups                map[string]LookupConfig     `json:"lookups"`
	CacheInvalidationRules map[string][]string         `json:"cache_invalidation_rules"`
	EventFiltering         EventFilter                 `json:"event_filtering"`
	Statistics             StatisticsConfig            `json:"statistics"`
	CEFVendor              string                      `json:"cef_vendor"`
	CEFProduct             string                      `json:"cef_product"`
	CEFVersion             string                      `json:"cef_version"`
}

type EventFilter struct {
	Mode               string                  `json:"mode"`
	ExcludedEvents     []string                `json:"excluded_events"`
	IncludedEvents     []string                `json:"included_events"`
	RateLimiting       map[string]RateLimit    `json:"rate_limiting"`
	PriorityEvents     []string                `json:"priority_events"`
	UserFiltering      UserFilter              `json:"user_filtering"`
}

type RateLimit struct {
	MaxPerHour int  `json:"max_per_hour"`
	Enabled    bool `json:"enabled"`
}

type UserFilter struct {
	ExcludeServiceAccounts bool     `json:"exclude_service_accounts"`
	ExcludeUsers          []string `json:"exclude_users"`
	IncludeOnlyUsers      []string `json:"include_only_users"`
}

type StatisticsConfig struct {
	EnableDetailedLogging   bool `json:"enable_detailed_logging"`
	LogIntervalEvents       int  `json:"log_interval_events"`
	TrackCacheMetrics       bool `json:"track_cache_metrics"`
	TrackPerformanceMetrics bool `json:"track_performance_metrics"`
}

type LookupConfig struct {
	Endpoint        string            `json:"endpoint"`
	ResponseMapping map[string]string `json:"response_mapping"`
}

type ServiceStats struct {
	sync.RWMutex
	StartTime              time.Time
	LastSuccessfulRun      time.Time
	TotalEventsForwarded   int64
	TotalEventsFiltered    int64
	TotalEventsDropped     int64
	TotalAPIRequests       int64
	FailedAPIRequests      int64
	TotalRetryAttempts     int64
	SuccessfulRecoveries   int64
	SyslogReconnects       int64
	CacheHits              int64
	CacheMisses            int64
	LookupFailures         int64
	ChangeDetectionEvents  int64
	MarkerFileUpdates      int64
	LastError              string
	LastErrorTime          time.Time
	LastMarker             string
	CurrentPollDuration    time.Duration
	AverageEventsPerSecond float64
}

type RateLimitTracker struct {
	sync.RWMutex
	EventCounts map[string][]time.Time
}

// OCI Audit Event structures
type OCIAuditEvent struct {
	EventType            string                 `json:"eventType"`
	CloudEventsVersion   string                 `json:"cloudEventsVersion"`
	EventTypeVersion     string                 `json:"eventTypeVersion"`
	Source               string                 `json:"source"`
	EventID              string                 `json:"eventId"`
	EventTime            string                 `json:"eventTime"`
	ContentType          string                 `json:"contentType"`
	Data                 map[string]interface{} `json:"data"`
	Extensions           map[string]interface{} `json:"extensions,omitempty"`
}

type OCICompartment struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	LifecycleState string `json:"lifecycleState"`
	TimeCreated    string `json:"timeCreated"`
}

type ListCompartmentsResponse struct {
	Items []OCICompartment `json:"data"`
}

type SyslogWriter struct {
	protocol       string
	address        string
	conn           net.Conn
	reconnectCount int
	lastReconnect  time.Time
	maxReconnects  int
	reconnectDelay time.Duration
}

type LookupCache struct {
	sync.RWMutex
	data map[string]map[string]interface{}
}

type CacheStats struct {
	Hits   int
	Misses int
}

type LookupStats struct {
	Failures int
	Success  int
}

type ChangeStats struct {
	ChangeEvents int
}

type EventCache struct {
	sync.RWMutex
	processedEvents map[string]time.Time
	eventRing       *ring.Ring
	maxCacheSize    int
	cacheWindow     time.Duration
}

type EventCacheStats struct {
	DuplicatesDetected int64
	CacheHits          int64
	CacheMisses        int64
	CacheSize          int
}

type TimeBasedMarker struct {
	LastEventTime time.Time `json:"last_event_time"`
	LastEventID   string    `json:"last_event_id"`
	PollCount     int64     `json:"poll_count"`
}

type OCIClient struct {
	httpClient *http.Client
	privateKey *rsa.PrivateKey
	config     *Configuration
}

var (
	serviceStats     = &ServiceStats{StartTime: time.Now()}
	rateLimitTracker = &RateLimitTracker{EventCounts: make(map[string][]time.Time)}
	lookupCache      = &LookupCache{data: make(map[string]map[string]interface{})}
	ctx              context.Context
	cancel           context.CancelFunc
	ociClient        *OCIClient
	eventTypeMap     map[string]string
	eventCache       *EventCache
	eventCacheStats  = &EventCacheStats{}
	timeBasedMarker  = &TimeBasedMarker{}
	compartments     []OCICompartment
)

func main() {
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	config := loadConfig()

	if config.ShowVersion {
		fmt.Println("OCI Audit Event Forwarder v1.0.0 - Based on Hekate Architecture")
		return
	}

	if config.ValidateMode {
		if err := validateConfig(config); err != nil {
			log.Fatalf("❌ Configuration validation failed: %v", err)
		}
		log.Println("✅ Configuration is valid")
		return
	}

	if config.TestMode {
		if err := runConnectionTests(*config); err != nil {
			log.Fatalf("❌ Connection tests failed: %v", err)
		}
		log.Println("✅ All connection tests passed")
		return
	}

	if err := setupLogging(config); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	logServiceStartup(config)

	if err := validateConfig(config); err != nil {
		log.Fatalf("❌ Configuration validation failed: %v", err)
	}

	fieldMapping := loadFieldMapping(config.FieldMapFile)
	
	// Initialize event cache
	if config.EnableEventCache {
		cacheWindow := time.Duration(config.EventCacheWindow) * time.Second
		eventCache = NewEventCache(config.EventCacheSize, cacheWindow)
		log.Printf("🧠 Event deduplication cache initialized (size: %d, window: %v)", 
			config.EventCacheSize, cacheWindow)
		
		// Start cleanup goroutine
		go eventCache.cleanupExpired()
	} else {
		log.Println("⚠️  Event deduplication cache disabled")
	}
	
	eventTypeMap = loadEventTypeMap(config.EventMapFile)

	syslogWriter, err := NewSyslogWriter(config.SyslogProtocol,
		fmt.Sprintf("%s:%s", config.SyslogServer, config.SyslogPort), config)
	if err != nil {
		log.Fatalf("❌ Failed to initialize syslog connection: %v", err)
	}
	defer syslogWriter.Close()

	log.Println("✅ Syslog connectivity verified")

	// Initialize OCI client
	ociClient, err = NewOCIClient(config)
	if err != nil {
		log.Fatalf("❌ Failed to initialize OCI client: %v", err)
	}

	// Load compartments
	if err := loadOCICompartments(config); err != nil {
		log.Fatalf("❌ Failed to load compartments: %v", err)
	}

	log.Printf("✅ Successfully authenticated with OCI")
	log.Printf("🏢 Loaded %d compartments for monitoring", len(compartments))

	log.Println("💾 Cache initialized")
	log.Printf("🗺️  Field mappings loaded (%d lookups)", len(fieldMapping.Lookups))
	log.Printf("📝 Event types loaded (%d types)", len(eventTypeMap))

	timeBasedMarker := loadTimeBasedMarker(config.MarkerFile)
	if timeBasedMarker.LastEventID != "" {
		log.Printf("📍 Resuming from marker: %s (Poll #%d)", 
			timeBasedMarker.LastEventTime.Format("2006-01-02 15:04:05"), timeBasedMarker.PollCount)
	} else {
		log.Printf("🆕 Starting fresh - will collect from %s", 
			timeBasedMarker.LastEventTime.Format("2006-01-02 15:04:05"))
	}

	if config.HealthCheckPort > 0 {
		go startHealthCheckServer(config.HealthCheckPort)
		log.Printf("🏥 Health check server started on port %d", config.HealthCheckPort)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	log.Println("🎯 Starting event polling...")

	ticker := time.NewTicker(time.Duration(config.FetchInterval) * time.Second)
	defer ticker.Stop()

	processEventsWithRecovery(config, fieldMapping, syslogWriter, timeBasedMarker)
	
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, shutting down...")
			return

		case <-ticker.C:
			timeBasedMarker = processEventsWithRecovery(config, fieldMapping, syslogWriter, timeBasedMarker)

		case sig := <-sigChan:
			log.Printf("📨 Received signal %v, initiating graceful shutdown...", sig)

			if sig == syscall.SIGHUP {
				log.Println("🔄 SIGHUP received - reloading configuration")
				fieldMapping = loadFieldMapping(config.FieldMapFile)
				eventTypeMap = loadEventTypeMap(config.EventMapFile)
				log.Println("✅ Configuration reloaded")
				continue
			}

			log.Println("💾 Saving final state and shutting down...")
			cancel()
			return
		}
	}
}



func loadConfig() *Configuration {
	// Add config file flag
	configFile := flag.String("config", getEnvOrDefault("CONFIG_FILE", ""), "Path to JSON configuration file")
	
	// Existing flags...
	tenancyOCID := flag.String("tenancy-ocid", getEnvOrDefault("OCI_TENANCY_OCID", ""), "OCI Tenancy OCID")
	userOCID := flag.String("user-ocid", getEnvOrDefault("OCI_USER_OCID", ""), "OCI User OCID")
	keyFingerprint := flag.String("key-fingerprint", getEnvOrDefault("OCI_KEY_FINGERPRINT", ""), "OCI API Key Fingerprint")
	privateKeyPath := flag.String("private-key-path", getEnvOrDefault("OCI_PRIVATE_KEY_PATH", ""), "Path to OCI private key file")
	region := flag.String("region", getEnvOrDefault("OCI_REGION", "us-phoenix-1"), "OCI Region")
	apiBaseURL := flag.String("api-base-url", getEnvOrDefault("OCI_API_BASE_URL", ""), "OCI API Base URL (auto-generated if empty)")
	apiVersion := flag.String("api-version", getEnvOrDefault("OCI_API_VERSION", "20190901"), "OCI Audit API Version")
	syslogProto := flag.String("syslog-proto", getEnvOrDefault("SYSLOG_PROTOCOL", "tcp"), "Syslog protocol (tcp/udp)")
	syslogServer := flag.String("syslog-server", getEnvOrDefault("SYSLOG_SERVER", "localhost"), "Syslog server address")
	syslogPort := flag.String("syslog-port", getEnvOrDefault("SYSLOG_PORT", "514"), "Syslog server port")
	logLevel := flag.String("log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level")
	logFile := flag.String("log-file", getEnvOrDefault("LOG_FILE", ""), "Log file path")
	fetchInterval := flag.Int("interval", getEnvOrIntDefault("FETCH_INTERVAL", 300), "Event fetch interval in seconds")
	connTimeout := flag.Int("conn-timeout", getEnvOrIntDefault("CONNECTION_TIMEOUT", 30), "Connection timeout in seconds")
	maxMsgSize := flag.Int("max-msg-size", getEnvOrIntDefault("MAX_MSG_SIZE", 8192), "Maximum syslog message size")
	markerFile := flag.String("marker-file", getEnvOrDefault("MARKER_FILE", "oci_audit_marker.json"), "Event marker file")
	fieldMapFile := flag.String("field-map", getEnvOrDefault("FIELD_MAP_FILE", "oci_field_map.json"), "Field mapping file")
	eventMapFile := flag.String("event-map", getEnvOrDefault("EVENT_MAP_FILE", "oci_event_map.json"), "Event type mapping file")
	verbose := flag.Bool("verbose", getEnvOrBoolDefault("VERBOSE", false), "Enable verbose output")
	maxRetries := flag.Int("max-retries", getEnvOrIntDefault("MAX_RETRIES", 3), "Maximum retry attempts")
	retryDelay := flag.Int("retry-delay", getEnvOrIntDefault("RETRY_DELAY", 5), "Retry delay in seconds")
	healthCheckPort := flag.Int("health-port", getEnvOrIntDefault("HEALTH_CHECK_PORT", 8080), "Health check port (0 to disable)")
	testMode := flag.Bool("test", false, "Test connections and dependencies")
	validateMode := flag.Bool("validate", false, "Validate configuration and exit")
	showVersion := flag.Bool("version", false, "Show version information")
	eventCacheSize := flag.Int("event-cache-size", getEnvOrIntDefault("EVENT_CACHE_SIZE", 10000), "Maximum number of event IDs to cache")
	eventCacheWindow := flag.Int("event-cache-window", getEnvOrIntDefault("EVENT_CACHE_WINDOW", 3600), "Event cache window in seconds")
	enableEventCache := flag.Bool("enable-event-cache", getEnvOrBoolDefault("ENABLE_EVENT_CACHE", true), "Enable event deduplication cache")
	initialLookback := flag.Int("initial-lookback-hours", getEnvOrIntDefault("INITIAL_LOOKBACK_HOURS", 24), "Hours to look back for initial poll")
	pollOverlap := flag.Int("poll-overlap-minutes", getEnvOrIntDefault("POLL_OVERLAP_MINUTES", 5), "Minutes to overlap between polls")
	maxEvents := flag.Int("max-events-per-poll", getEnvOrIntDefault("MAX_EVENTS_PER_POLL", 1000), "Maximum events to fetch per poll")
	compartmentMode := flag.String("compartment-mode", getEnvOrDefault("COMPARTMENT_MODE", "all"), "Compartment filtering mode (all, tenancy_only, include, exclude)")
	compartmentIDsStr := flag.String("compartment-ids", getEnvOrDefault("COMPARTMENT_IDS", ""), "Comma-separated list of compartment OCIDs")

	flag.Parse()

	// If config file is specified, load from JSON and merge with CLI/env overrides
	if *configFile != "" {
		config, err := loadConfigFromJSON(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config file %s: %v", *configFile, err)
		}
		
		// Override with CLI flags that were explicitly set (check against defaults)
		if *tenancyOCID != getEnvOrDefault("OCI_TENANCY_OCID", "") {
			config.TenancyOCID = *tenancyOCID
		}
		if *userOCID != getEnvOrDefault("OCI_USER_OCID", "") {
			config.UserOCID = *userOCID
		}
		if *keyFingerprint != getEnvOrDefault("OCI_KEY_FINGERPRINT", "") {
			config.KeyFingerprint = *keyFingerprint
		}
		if *privateKeyPath != getEnvOrDefault("OCI_PRIVATE_KEY_PATH", "") {
			config.PrivateKeyPath = *privateKeyPath
		}
		if *region != getEnvOrDefault("OCI_REGION", "us-phoenix-1") {
			config.Region = *region
		}
		if *apiBaseURL != getEnvOrDefault("OCI_API_BASE_URL", "") {
			config.APIBaseURL = *apiBaseURL
		}
		if *apiVersion != getEnvOrDefault("OCI_API_VERSION", "20190901") {
			config.APIVersion = *apiVersion
		}
		if *syslogProto != getEnvOrDefault("SYSLOG_PROTOCOL", "tcp") {
			config.SyslogProtocol = *syslogProto
		}
		if *syslogServer != getEnvOrDefault("SYSLOG_SERVER", "localhost") {
			config.SyslogServer = *syslogServer
		}
		if *syslogPort != getEnvOrDefault("SYSLOG_PORT", "514") {
			config.SyslogPort = *syslogPort
		}
		if *logLevel != getEnvOrDefault("LOG_LEVEL", "info") {
			config.LogLevel = *logLevel
		}
		if *logFile != getEnvOrDefault("LOG_FILE", "") {
			config.LogFile = *logFile
		}
		if *fetchInterval != getEnvOrIntDefault("FETCH_INTERVAL", 300) {
			config.FetchInterval = *fetchInterval
		}
		if *connTimeout != getEnvOrIntDefault("CONNECTION_TIMEOUT", 30) {
			config.ConnTimeout = *connTimeout
		}
		if *maxMsgSize != getEnvOrIntDefault("MAX_MSG_SIZE", 8192) {
			config.MaxMsgSize = *maxMsgSize
		}
		if *markerFile != getEnvOrDefault("MARKER_FILE", "oci_audit_marker.json") {
			config.MarkerFile = *markerFile
		}
		if *fieldMapFile != getEnvOrDefault("FIELD_MAP_FILE", "oci_field_map.json") {
			config.FieldMapFile = *fieldMapFile
		}
		if *eventMapFile != getEnvOrDefault("EVENT_MAP_FILE", "oci_event_map.json") {
			config.EventMapFile = *eventMapFile
		}
		if *verbose != getEnvOrBoolDefault("VERBOSE", false) {
			config.Verbose = *verbose
		}
		if *maxRetries != getEnvOrIntDefault("MAX_RETRIES", 3) {
			config.MaxRetries = *maxRetries
		}
		if *retryDelay != getEnvOrIntDefault("RETRY_DELAY", 5) {
			config.RetryDelay = *retryDelay
		}
		if *healthCheckPort != getEnvOrIntDefault("HEALTH_CHECK_PORT", 8080) {
			config.HealthCheckPort = *healthCheckPort
		}
		// Test, validate, and version flags always override
		config.TestMode = *testMode
		config.ValidateMode = *validateMode
		config.ShowVersion = *showVersion
		
		if *eventCacheSize != getEnvOrIntDefault("EVENT_CACHE_SIZE", 10000) {
			config.EventCacheSize = *eventCacheSize
		}
		if *eventCacheWindow != getEnvOrIntDefault("EVENT_CACHE_WINDOW", 3600) {
			config.EventCacheWindow = *eventCacheWindow
		}
		if *enableEventCache != getEnvOrBoolDefault("ENABLE_EVENT_CACHE", true) {
			config.EnableEventCache = *enableEventCache
		}
		if *initialLookback != getEnvOrIntDefault("INITIAL_LOOKBACK_HOURS", 24) {
			config.InitialLookbackHours = *initialLookback
		}
		if *pollOverlap != getEnvOrIntDefault("POLL_OVERLAP_MINUTES", 5) {
			config.PollOverlapMinutes = *pollOverlap
		}
		if *maxEvents != getEnvOrIntDefault("MAX_EVENTS_PER_POLL", 1000) {
			config.MaxEventsPerPoll = *maxEvents
		}
		if *compartmentMode != getEnvOrDefault("COMPARTMENT_MODE", "all") {
			config.CompartmentMode = *compartmentMode
		}
		if *compartmentIDsStr != getEnvOrDefault("COMPARTMENT_IDS", "") {
			var compartmentIDs []string
			if *compartmentIDsStr != "" {
				compartmentIDs = strings.Split(*compartmentIDsStr, ",")
				for i, id := range compartmentIDs {
					compartmentIDs[i] = strings.TrimSpace(id)
				}
			}
			config.CompartmentIDs = compartmentIDs
		}
		
		// Auto-generate API base URL if not provided
		if config.APIBaseURL == "" {
			config.APIBaseURL = fmt.Sprintf("https://audit.%s.oraclecloud.com", config.Region)
		}
		
		return config
	}

	// Parse compartment IDs for non-JSON config
	var compartmentIDs []string
	if *compartmentIDsStr != "" {
		compartmentIDs = strings.Split(*compartmentIDsStr, ",")
		for i, id := range compartmentIDs {
			compartmentIDs[i] = strings.TrimSpace(id)
		}
	}

	// Default behavior: use flags and environment variables
	config := &Configuration{
		TenancyOCID:      *tenancyOCID,
		UserOCID:         *userOCID,
		KeyFingerprint:   *keyFingerprint,
		PrivateKeyPath:   *privateKeyPath,
		Region:           *region,
		APIBaseURL:       *apiBaseURL,
		APIVersion:       *apiVersion,
		SyslogProtocol:   *syslogProto,
		SyslogServer:     *syslogServer,
		SyslogPort:       *syslogPort,
		LogLevel:         *logLevel,
		LogFile:          *logFile,
		FetchInterval:    *fetchInterval,
		ConnTimeout:      *connTimeout,
		MaxMsgSize:       *maxMsgSize,
		MarkerFile:       *markerFile,
		FieldMapFile:     *fieldMapFile,
		EventMapFile:     *eventMapFile,
		Verbose:          *verbose,
		MaxRetries:       *maxRetries,
		RetryDelay:       *retryDelay,
		HealthCheckPort:  *healthCheckPort,
		TestMode:         *testMode,
		ValidateMode:     *validateMode,
		ShowVersion:      *showVersion,
		EventCacheSize:       *eventCacheSize,
		EventCacheWindow:     *eventCacheWindow,
		EnableEventCache:     *enableEventCache,
		InitialLookbackHours: *initialLookback,
		PollOverlapMinutes:   *pollOverlap,
		MaxEventsPerPoll:     *maxEvents,
		CompartmentMode:      *compartmentMode,
		CompartmentIDs:       compartmentIDs,
	}

	// Auto-generate API base URL if not provided
	if config.APIBaseURL == "" {
		config.APIBaseURL = fmt.Sprintf("https://audit.%s.oraclecloud.com", config.Region)
	}

	return config
}

func loadConfigFromJSON(filename string) (*Configuration, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config Configuration
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	log.Printf("📋 Loaded configuration from %s", filename)
	return &config, nil
}

// Create a sample config file
func createSampleConfig(filename string) error {
	sampleConfig := &Configuration{
		TenancyOCID:          "ocid1.tenancy.oc1..aaaaaaaa...",
		UserOCID:             "ocid1.user.oc1..aaaaaaaa...",
		KeyFingerprint:       "aa:bb:cc:dd:ee:ff:gg:hh:ii:jj:kk:ll:mm:nn:oo:pp",
		PrivateKeyPath:       "/path/to/oci-private-key.pem",
		Region:               "us-phoenix-1",
		APIBaseURL:           "",  // Will be auto-generated
		APIVersion:           "20190901",
		SyslogProtocol:       "tcp",
		SyslogServer:         "your-syslog-server.com",
		SyslogPort:           "514",
		LogLevel:             "info",
		LogFile:              "",
		FetchInterval:        300,
		ConnTimeout:          30,
		MaxMsgSize:           8192,
		MarkerFile:           "oci_audit_marker.json",
		FieldMapFile:         "oci_field_map.json",
		EventMapFile:         "oci_event_map.json",
		Verbose:              false,
		MaxRetries:           3,
		RetryDelay:           5,
		HealthCheckPort:      8080,
		TestMode:             false,
		ValidateMode:         false,
		ShowVersion:          false,
		EventCacheSize:       10000,
		EventCacheWindow:     3600,
		EnableEventCache:     true,
		InitialLookbackHours: 24,
		PollOverlapMinutes:   5,
		MaxEventsPerPoll:     1000,
		CompartmentMode:      "all",
		CompartmentIDs:       []string{},
	}
	
	data, err := json.MarshalIndent(sampleConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sample config: %w", err)
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

func validateConfig(config *Configuration) error {
	missing := []string{}
	if config.TenancyOCID == "" {
		missing = append(missing, "OCI_TENANCY_OCID")
	}
	if config.UserOCID == "" {
		missing = append(missing, "OCI_USER_OCID")
	}
	if config.KeyFingerprint == "" {
		missing = append(missing, "OCI_KEY_FINGERPRINT")
	}
	if config.PrivateKeyPath == "" {
		missing = append(missing, "OCI_PRIVATE_KEY_PATH")
	}
	if config.SyslogServer == "" {
		missing = append(missing, "SYSLOG_SERVER")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %v", missing)
	}
	if config.FetchInterval < 10 {
		return fmt.Errorf("fetch interval must be at least 10 seconds")
	}
	return nil
}

func setupLogging(config *Configuration) error {
	var writers []io.Writer
	writers = append(writers, os.Stdout)

	if config.LogFile != "" {
		dir := filepath.Dir(config.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		writers = append(writers, file)
	}

	if len(writers) > 1 {
		log.SetOutput(io.MultiWriter(writers...))
	} else {
		log.SetOutput(writers[0])
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	return nil
}

func logServiceStartup(config *Configuration) {
	log.Printf("🚀 Starting OCI Audit Event Forwarder v1.0.0")
	log.Printf("📋 PID: %d", os.Getpid())
	log.Printf("🔐 API: %s", config.APIBaseURL)
	log.Printf("🏢 Tenancy: %s", config.TenancyOCID)
	log.Printf("🌍 Region: %s", config.Region)
	log.Printf("📡 Syslog: %s:%s (%s)", config.SyslogServer, config.SyslogPort, config.SyslogProtocol)
	log.Printf("⏱️  Interval: %ds", config.FetchInterval)
	log.Printf("📁 Marker: %s", config.MarkerFile)
	log.Printf("🗺️  Field Map: %s", config.FieldMapFile)
	log.Printf("📝 Event Map: %s", config.EventMapFile)
}

func runConnectionTests(config Configuration) error {
	log.Println("🔍 Testing configuration and connections...")

	log.Print("  Testing OCI API authentication... ")
	client, err := NewOCIClient(&config)
	if err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	ociClient = client
	log.Println("✅ SUCCESS")

	log.Print("  Testing OCI API connectivity... ")
	if err := testOCIAPI(&config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing Syslog connectivity... ")
	writer, err := NewSyslogWriter(config.SyslogProtocol, 
		fmt.Sprintf("%s:%s", config.SyslogServer, config.SyslogPort), &config)
	if err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	writer.Close()
	log.Println("✅ SUCCESS")

	log.Print("  Testing configuration files... ")
	if err := testConfigFiles(&config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing file permissions... ")
	if err := testFilePermissions(&config); err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	return nil
}

// OCI Client Implementation
func NewOCIClient(config *Configuration) (*OCIClient, error) {
	// Load private key
	keyData, err := ioutil.ReadFile(config.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	return &OCIClient{
		httpClient: &http.Client{Timeout: time.Duration(config.ConnTimeout) * time.Second},
		privateKey: privateKey,
		config:     config,
	}, nil
}

func (c *OCIClient) signRequest(req *http.Request) error {
	// Required headers for signing
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", date)
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("User-Agent", "OCI-Audit-Forwarder/1.0")

	// Build signing string
	var signingString strings.Builder
	
	// (request-target)
	signingString.WriteString(fmt.Sprintf("(request-target): %s %s", 
		strings.ToLower(req.Method), req.URL.RequestURI()))
	
	// Headers to include in signing
	headers := []string{"date", "host"}
	
	// Add content-length and x-content-sha256 for POST/PUT
	if req.Method == "POST" || req.Method == "PUT" {
		contentLength := "0"
		if req.Body != nil {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return err
			}
			req.Body = ioutil.NopCloser(strings.NewReader(string(body)))
			contentLength = fmt.Sprintf("%d", len(body))
			
			// Calculate SHA256 hash
			hash := sha256.Sum256(body)
			contentSHA256 := base64.StdEncoding.EncodeToString(hash[:])
			req.Header.Set("x-content-sha256", contentSHA256)
			headers = append(headers, "x-content-sha256")
		} else {
			// Empty body hash
			hash := sha256.Sum256([]byte{})
			contentSHA256 := base64.StdEncoding.EncodeToString(hash[:])
			req.Header.Set("x-content-sha256", contentSHA256)
			headers = append(headers, "x-content-sha256")
		}
		req.Header.Set("Content-Length", contentLength)
		headers = append(headers, "content-length")
	}

	// Build the signing string with headers
	for _, header := range headers {
		signingString.WriteString(fmt.Sprintf("\n%s: %s", header, req.Header.Get(header)))
	}

	// Sign the string
	signingBytes := []byte(signingString.String())
	hashed := sha256.Sum256(signingBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// Create authorization header
	keyID := fmt.Sprintf("%s/%s/%s", 
		c.config.TenancyOCID, 
		c.config.UserOCID, 
		c.config.KeyFingerprint)
	
	authHeader := fmt.Sprintf(
		`Signature keyId="%s",algorithm="rsa-sha256",headers="%s",signature="%s"`,
		keyID,
		strings.Join(append([]string{"(request-target)"}, headers...), " "),
		base64.StdEncoding.EncodeToString(signature),
	)
	
	req.Header.Set("Authorization", authHeader)
	return nil
}

func loadOCICompartments(config *Configuration) error {
	// Always include the tenancy root compartment
	tenancyCompartment := OCICompartment{
		ID:             config.TenancyOCID,
		Name:           "root",
		Description:    "Root tenancy compartment",
		LifecycleState: "ACTIVE",
		TimeCreated:    time.Now().Format(time.RFC3339),
	}
	compartments = []OCICompartment{tenancyCompartment}

	// Load sub-compartments if needed
	if config.CompartmentMode != "tenancy_only" {
		if err := loadSubCompartments(config.TenancyOCID, config); err != nil {
			return err
		}
	}

	// Apply filtering
	compartments = filterCompartments(compartments, config)

	log.Printf("🏢 Loaded %d compartments for monitoring:", len(compartments))
	for _, comp := range compartments {
		log.Printf("  - %s (%s) [%s]", comp.Name, comp.ID, comp.LifecycleState)
	}

	return nil
}

func loadSubCompartments(compartmentID string, config *Configuration) error {
	apiURL := fmt.Sprintf("%s/%s/compartments", config.APIBaseURL, config.APIVersion)
	u, err := url.Parse(apiURL)
	if err != nil {
		return err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("lifecycleState", "ACTIVE")
	q.Set("limit", "1000")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}

	if err := ociClient.signRequest(req); err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("compartments request failed: %d - %s", resp.StatusCode, string(body))
	}

	var compartmentsResp ListCompartmentsResponse
	if err := json.Unmarshal(body, &compartmentsResp); err != nil {
		return fmt.Errorf("failed to parse compartments response: %w", err)
	}

	compartments = append(compartments, compartmentsResp.Items...)

	// Recursively load sub-compartments
	for _, comp := range compartmentsResp.Items {
		if err := loadSubCompartments(comp.ID, config); err != nil {
			log.Printf("⚠️  Warning: failed to load sub-compartments for %s: %v", comp.ID, err)
		}
	}

	return nil
}

func filterCompartments(allCompartments []OCICompartment, config *Configuration) []OCICompartment {
	switch config.CompartmentMode {
	case "all":
		return allCompartments
	case "tenancy_only":
		// Return only the root tenancy compartment
		var tenancyOnly []OCICompartment
		for _, comp := range allCompartments {
			if comp.ID == config.TenancyOCID {
				tenancyOnly = append(tenancyOnly, comp)
				break
			}
		}
		return tenancyOnly
	case "include":
		return filterIncludeCompartments(allCompartments, config.CompartmentIDs)
	case "exclude":
		return filterExcludeCompartments(allCompartments, config.CompartmentIDs)
	default:
		log.Printf("⚠️  Warning: unknown compartment mode '%s', using 'all'", config.CompartmentMode)
		return allCompartments
	}
}

func filterIncludeCompartments(allCompartments []OCICompartment, includeIDs []string) []OCICompartment {
	if len(includeIDs) == 0 {
		return allCompartments
	}

	var filtered []OCICompartment
	for _, comp := range allCompartments {
		for _, id := range includeIDs {
			if comp.ID == id {
				filtered = append(filtered, comp)
				break
			}
		}
	}
	return filtered
}

func filterExcludeCompartments(allCompartments []OCICompartment, excludeIDs []string) []OCICompartment {
	if len(excludeIDs) == 0 {
		return allCompartments
	}

	var filtered []OCICompartment
	for _, comp := range allCompartments {
		excluded := false
		for _, id := range excludeIDs {
			if comp.ID == id {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, comp)
		}
	}
	return filtered
}

func testOCIAPI(config *Configuration) error {
	// Test with a simple compartment list request
	apiURL := fmt.Sprintf("%s/%s/compartments?compartmentId=%s&limit=1", 
		config.APIBaseURL, config.APIVersion, config.TenancyOCID)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return err
	}

	if err := ociClient.signRequest(req); err != nil {
		return err
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("API test returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func testConfigFiles(config *Configuration) error {
	if _, err := os.Stat(config.FieldMapFile); os.IsNotExist(err) {
		defaultMapping := createDefaultFieldMapping()
		if err := saveFieldMapping(config.FieldMapFile, defaultMapping); err != nil {
			return fmt.Errorf("failed to create default field mapping: %w", err)
		}
		log.Printf("📋 Created default field mapping file: %s", config.FieldMapFile)
	}

	if _, err := os.Stat(config.EventMapFile); os.IsNotExist(err) {
		defaultEventMap := createDefaultEventTypeMap()
		if err := saveEventTypeMap(config.EventMapFile, defaultEventMap); err != nil {
			return fmt.Errorf("failed to create default event type mapping: %w", err)
		}
		log.Printf("📝 Created default event type mapping file: %s", config.EventMapFile)
	}

	return nil
}

func testFilePermissions(config *Configuration) error {
	dir := filepath.Dir(config.MarkerFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create marker file directory: %w", err)
	}

	testFile := filepath.Join(dir, "test_permissions")
	if err := ioutil.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot write to marker file directory: %w", err)
	}
	os.Remove(testFile)

	return nil
}

func NewSyslogWriter(protocol, address string, config *Configuration) (*SyslogWriter, error) {
	conn, err := net.DialTimeout(protocol, address, time.Duration(config.ConnTimeout)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog server: %w", err)
	}

	return &SyslogWriter{
		protocol:       protocol,
		address:        address,
		conn:           conn,
		maxReconnects:  10,
		reconnectDelay: 5 * time.Second,
	}, nil
}

func (w *SyslogWriter) Write(message string) error {
	if w.conn == nil {
		return fmt.Errorf("no connection available")
	}
	_, err := fmt.Fprintln(w.conn, message)
	return err
}

func (w *SyslogWriter) Close() error {
	if w.conn != nil {
		return w.conn.Close()
	}
	return nil
}

func (w *SyslogWriter) Reconnect() error {
	if time.Since(w.lastReconnect) < w.reconnectDelay {
		return fmt.Errorf("reconnection rate limited")
	}

	if w.reconnectCount >= w.maxReconnects {
		return fmt.Errorf("max reconnection attempts exceeded")
	}

	if w.conn != nil {
		w.conn.Close()
	}

	conn, err := net.DialTimeout(w.protocol, w.address, 30*time.Second)
	if err != nil {
		w.reconnectCount++
		w.lastReconnect = time.Now()
		serviceStats.Lock()
		serviceStats.SyslogReconnects++
		serviceStats.Unlock()
		return fmt.Errorf("failed to reconnect to syslog server: %w", err)
	}

	w.conn = conn
	w.reconnectCount = 0
	w.lastReconnect = time.Now()
	log.Printf("✅ Successfully reconnected to syslog server")
	return nil
}

func getEventDeduplicationKey(event OCIAuditEvent) string {
	// Create a composite key from OCI audit event properties
	var keyParts []string
	
	// Always include event type, event ID, and event time
	keyParts = append(keyParts, fmt.Sprintf("t%s", event.EventType))
	keyParts = append(keyParts, fmt.Sprintf("id%s", event.EventID))
	keyParts = append(keyParts, fmt.Sprintf("time%s", event.EventTime))
	
	// Add data fields if present
	if event.Data != nil {
		if compartmentID, exists := event.Data["compartmentId"].(string); exists {
			keyParts = append(keyParts, fmt.Sprintf("comp%s", compartmentID))
		}
		if resourceID, exists := event.Data["resourceId"].(string); exists {
			keyParts = append(keyParts, fmt.Sprintf("res%s", resourceID))
		}
		if identity, exists := event.Data["identity"].(map[string]interface{}); exists {
			if principalID, exists := identity["principalId"].(string); exists {
				keyParts = append(keyParts, fmt.Sprintf("prin%s", principalID))
			}
		}
	}
	
	return strings.Join(keyParts, "|")
}

func startHealthCheckServer(port int) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		serviceStats.RLock()
		
		// Get cache stats if available
		var cacheStats EventCacheStats
		if eventCache != nil {
			cacheStats = eventCache.GetStats()
		}
		
		status := map[string]interface{}{
			"status":                      "healthy",
			"uptime":                      time.Since(serviceStats.StartTime).String(),
			"last_successful_run":         serviceStats.LastSuccessfulRun.Format(time.RFC3339),
			"total_events":                serviceStats.TotalEventsForwarded,
			"total_filtered":              serviceStats.TotalEventsFiltered,
			"total_dropped":               serviceStats.TotalEventsDropped,
			"total_api_requests":          serviceStats.TotalAPIRequests,
			"failed_api_requests":         serviceStats.FailedAPIRequests,
			"retry_attempts":              serviceStats.TotalRetryAttempts,
			"successful_recoveries":       serviceStats.SuccessfulRecoveries,
			"syslog_reconnects":           serviceStats.SyslogReconnects,
			"cache_hits":                  serviceStats.CacheHits,
			"cache_misses":                serviceStats.CacheMisses,
			"lookup_failures":             serviceStats.LookupFailures,
			"change_detection_events":     serviceStats.ChangeDetectionEvents,
			"marker_file_updates":         serviceStats.MarkerFileUpdates,
			"last_error":                  serviceStats.LastError,
			"last_error_time":             serviceStats.LastErrorTime.Format(time.RFC3339),
			"average_events_per_second":   serviceStats.AverageEventsPerSecond,
			"compartments_monitored":      len(compartments),
			"event_cache": map[string]interface{}{
				"duplicates_detected": cacheStats.DuplicatesDetected,
				"cache_hits":         cacheStats.CacheHits,
				"cache_misses":       cacheStats.CacheMisses,
				"cache_size":         cacheStats.CacheSize,
			},
		}
		serviceStats.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		serviceStats.RLock()
		fmt.Fprintf(w, "oci_audit_forwarder_uptime_seconds %d\n", int64(time.Since(serviceStats.StartTime).Seconds()))
		fmt.Fprintf(w, "oci_audit_forwarder_total_events %d\n", serviceStats.TotalEventsForwarded)
		fmt.Fprintf(w, "oci_audit_forwarder_total_filtered %d\n", serviceStats.TotalEventsFiltered)
		fmt.Fprintf(w, "oci_audit_forwarder_total_dropped %d\n", serviceStats.TotalEventsDropped)
		fmt.Fprintf(w, "oci_audit_forwarder_api_requests_total %d\n", serviceStats.TotalAPIRequests)
		fmt.Fprintf(w, "oci_audit_forwarder_api_requests_failed %d\n", serviceStats.FailedAPIRequests)
		fmt.Fprintf(w, "oci_audit_forwarder_syslog_reconnects %d\n", serviceStats.SyslogReconnects)
		fmt.Fprintf(w, "oci_audit_forwarder_cache_hits %d\n", serviceStats.CacheHits)
		fmt.Fprintf(w, "oci_audit_forwarder_cache_misses %d\n", serviceStats.CacheMisses)
		fmt.Fprintf(w, "oci_audit_forwarder_compartments_monitored %d\n", len(compartments))
		serviceStats.RUnlock()
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("❌ Health check server error: %v", err)
	}
}

func processEventsWithRecovery(config *Configuration, fieldMapping FieldMapping, syslogWriter *SyslogWriter, marker TimeBasedMarker) TimeBasedMarker {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🚨 PANIC recovered in processEvents: %v", r)
			serviceStats.Lock()
			serviceStats.LastError = fmt.Sprintf("PANIC: %v", r)
			serviceStats.LastErrorTime = time.Now()
			serviceStats.Unlock()
		}
	}()

	newMarker, err := processAllEventsWithStats(config, fieldMapping, syslogWriter, marker)
	if err != nil {
		log.Printf("❌ Error processing events: %v", err)
		serviceStats.Lock()
		serviceStats.LastError = err.Error()
		serviceStats.LastErrorTime = time.Now()
		serviceStats.FailedAPIRequests++
		serviceStats.Unlock()
		
		// Return marker with updated poll count even on failure
		newMarker = marker
		newMarker.PollCount++
	}

	return newMarker
}

func processAllEventsWithStats(config *Configuration, fieldMapping FieldMapping, syslogWriter *SyslogWriter, marker TimeBasedMarker) (TimeBasedMarker, error) {
	pollStart := time.Now()
	
	totalEventsProcessed := 0
	totalEventsFiltered := 0
	totalEventsDropped := 0
	totalDuplicates := 0
	numErrors := 0
	totalRetryErrors := 0
	recoveries := 0
	cacheHits := 0
	cacheMisses := 0
	lookupFailures := 0
	changeDetectionEvents := 0
	
	serviceStats.Lock()
	serviceStats.TotalAPIRequests++
	serviceStats.Unlock()
	
	allEvents, newMarker, err := fetchOCIAuditEventsWithRetry(config, marker, &totalRetryErrors, &recoveries)
	if err != nil {
		numErrors++
		log.Printf("❌ Error fetching events: %v", err)
		return marker, err
	}
	
	pollEnd := time.Now()
	
	if len(allEvents) > 0 {
		// Use enhanced filtering with deduplication
		filteredEvents, droppedCount, duplicateCount, eventCacheHits, eventCacheMisses := filterEventsWithDeduplication(allEvents, fieldMapping.EventFiltering, fieldMapping.Statistics)
		totalEventsFiltered += droppedCount
		totalDuplicates += duplicateCount
		
		if len(filteredEvents) > 0 {
			forwarded, dropped, _, lookupStats, changeStats, err := forwardEventsWithStats(
				filteredEvents, config, fieldMapping, syslogWriter)
			
			if err != nil {
				numErrors++
				log.Printf("❌ Error forwarding events: %v", err)
				return marker, err
			}
			
			totalEventsProcessed += forwarded
			totalEventsDropped += dropped
			lookupFailures += lookupStats.Failures
			changeDetectionEvents += changeStats.ChangeEvents
		}
		
		// Track event cache stats separately from lookup cache stats
		cacheHits += eventCacheHits
		cacheMisses += eventCacheMisses
	}
	
	// Save the new marker
	if err := saveTimeBasedMarker(config.MarkerFile, newMarker); err != nil {
		log.Printf("⚠️  Warning: Error saving marker file: %v", err)
	} else {
		serviceStats.Lock()
		serviceStats.MarkerFileUpdates++
		serviceStats.Unlock()
	}
	
	var periodStart, periodEnd int64
	if len(allEvents) > 0 {
		// Use the time range of the actual events fetched
		firstEvent := allEvents[0]
		lastEvent := allEvents[len(allEvents)-1]
		firstTime, _ := time.Parse(time.RFC3339, firstEvent.EventTime)
		lastTime, _ := time.Parse(time.RFC3339, lastEvent.EventTime)
		periodStart = firstTime.Unix()
		periodEnd = lastTime.Unix()
	} else {
		// No events - use the API query window
		var startTime time.Time
		if marker.PollCount == 0 {
			startTime = pollStart.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
		} else {
			startTime = marker.LastEventTime.Add(-time.Duration(config.PollOverlapMinutes) * time.Minute)
		}
		periodStart = startTime.Unix()
		periodEnd = pollEnd.Unix()
	}
	
	var eventsPerSecond float64
	if pollEnd.After(pollStart) && totalEventsProcessed > 0 {
		duration := pollEnd.Sub(pollStart).Seconds()
		eventsPerSecond = float64(totalEventsProcessed) / duration
		
		serviceStats.Lock()
		serviceStats.CurrentPollDuration = pollEnd.Sub(pollStart)
		serviceStats.AverageEventsPerSecond = eventsPerSecond
		serviceStats.LastSuccessfulRun = pollEnd
		serviceStats.TotalEventsForwarded += int64(totalEventsProcessed)
		serviceStats.TotalEventsFiltered += int64(totalEventsFiltered)
		serviceStats.TotalEventsDropped += int64(totalEventsDropped)
		serviceStats.CacheHits += int64(cacheHits)
		serviceStats.CacheMisses += int64(cacheMisses)
		serviceStats.LookupFailures += int64(lookupFailures)
		serviceStats.ChangeDetectionEvents += int64(changeDetectionEvents)
		serviceStats.TotalRetryAttempts += int64(totalRetryErrors)
		serviceStats.SuccessfulRecoveries += int64(recoveries)
		serviceStats.Unlock()
	}
	
	log.Printf("📊 Time-Based Poll #%d Summary [%d - %d]: Events=%d, Duplicates=%d, Filtered=%d, Forwarded=%d, Dropped=%d, "+
		"Rate=%.2f events/sec, Errors=%d, Retries=%d, Recoveries=%d, EventCache H/M=%d/%d, "+
		"Next Poll From=%s",
		newMarker.PollCount, periodStart, periodEnd,
		len(allEvents), totalDuplicates, totalEventsFiltered,
		totalEventsProcessed, totalEventsDropped, eventsPerSecond, numErrors, totalRetryErrors,
		recoveries, cacheHits, cacheMisses,
		newMarker.LastEventTime.Add(-time.Duration(config.PollOverlapMinutes) * time.Minute).Format("2006-01-02T15:04:05"))	
	return newMarker, nil
}

func fetchOCIAuditEventsWithRetry(config *Configuration, marker TimeBasedMarker, totalRetryErrors *int, recoveries *int) ([]OCIAuditEvent, TimeBasedMarker, error) {
	var lastErr error
	
	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(config.RetryDelay) * time.Second
			log.Printf("🔄 Retry attempt %d/%d after %v", attempt, config.MaxRetries, delay)
			time.Sleep(delay)
		}
		
		events, newMarker, err := fetchOCIAuditEvents(config, marker)
		if err == nil {
			if attempt > 0 {
				*recoveries++
			}
			return events, newMarker, nil
		}
		
		*totalRetryErrors++
		lastErr = err
		log.Printf("❌ API request attempt %d failed: %v", attempt+1, err)
	}
	
	return nil, marker, fmt.Errorf("all retry attempts failed, last error: %w", lastErr)
}

func fetchOCIAuditEvents(config *Configuration, marker TimeBasedMarker) ([]OCIAuditEvent, TimeBasedMarker, error) {
	var allEvents []OCIAuditEvent
	
	// Calculate time window
	var startTime time.Time
	endTime := time.Now()
	
	if marker.LastEventTime.IsZero() || marker.PollCount == 0 {
		// First poll: Use initial lookback
		startTime = endTime.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
	} else {
		// Subsequent polls: Use configured overlap minutes
		overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
		startTime = marker.LastEventTime.Add(-overlapDuration)
	}
	
	if config.Verbose {
		overlapStr := fmt.Sprintf("%dm", config.PollOverlapMinutes)
		if marker.PollCount == 0 {
			overlapStr = fmt.Sprintf("%dh", config.InitialLookbackHours)
		}
		log.Printf("🔍 Fetching events: Start=%s, End=%s (overlap=%s)", 
			startTime.Format("2006-01-02T15:04:05"), 
			endTime.Format("2006-01-02T15:04:05"),
			overlapStr)
	}
	
	// Fetch events from all compartments
	for _, compartment := range compartments {
		events, err := fetchCompartmentEvents(config, compartment.ID, startTime, endTime)
		if err != nil {
			log.Printf("⚠️  Warning: Failed to fetch events for compartment %s (%s): %v", 
				compartment.Name, compartment.ID, err)
			continue
		}
		
		// Add compartment context to events
		for i := range events {
			if events[i].Data == nil {
				events[i].Data = make(map[string]interface{})
			}
			events[i].Data["compartmentName"] = compartment.Name
		}
		
		allEvents = append(allEvents, events...)
		
		if config.Verbose && len(events) > 0 {
			log.Printf("🔍 Compartment %s: %d events", compartment.Name, len(events))
		}
	}
	
	// Sort all events by time to ensure proper ordering
	sort.Slice(allEvents, func(i, j int) bool {
		timeI, _ := time.Parse(time.RFC3339, allEvents[i].EventTime)
		timeJ, _ := time.Parse(time.RFC3339, allEvents[j].EventTime)
		return timeI.Before(timeJ)
	})
	
	// Create new marker with the current poll's endTime
	newMarker := TimeBasedMarker{
		LastEventTime: endTime,
		LastEventID:   "",
		PollCount:     marker.PollCount + 1,
	}
	
	// Optional: Store a reference to the newest event for debugging
	if len(allEvents) > 0 {
		newestEvent := allEvents[len(allEvents)-1]
		newMarker.LastEventID = getEventDeduplicationKey(newestEvent)
	}
	
	return allEvents, newMarker, nil
}

func fetchCompartmentEvents(config *Configuration, compartmentID string, startTime, endTime time.Time) ([]OCIAuditEvent, error) {
	var allEvents []OCIAuditEvent
	var nextPage string
	
	for {
		events, nextPageToken, err := fetchCompartmentEventsPage(config, compartmentID, startTime, endTime, nextPage)
		if err != nil {
			return nil, err
		}
		
		allEvents = append(allEvents, events...)
		
		if nextPageToken == "" {
			break
		}
		nextPage = nextPageToken
		
		// Safety check to prevent infinite loops
		if len(allEvents) > config.MaxEventsPerPoll {
			log.Printf("⚠️  Warning: Hit max events limit (%d) for compartment %s", config.MaxEventsPerPoll, compartmentID)
			break
		}
	}
	
	return allEvents, nil
}

func fetchCompartmentEventsPage(config *Configuration, compartmentID string, startTime, endTime time.Time, pageToken string) ([]OCIAuditEvent, string, error) {
	apiURL := fmt.Sprintf("%s/%s/auditEvents", config.APIBaseURL, config.APIVersion)
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, "", err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("startTime", startTime.Format(time.RFC3339))
	q.Set("endTime", endTime.Format(time.RFC3339))
	q.Set("limit", "1000")
	
	if pageToken != "" {
		q.Set("page", pageToken)
	}
	
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, "", err
	}

	if err := ociClient.signRequest(req); err != nil {
		return nil, "", fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("audit events request failed: %d - %s", resp.StatusCode, string(body))
	}

	var events []OCIAuditEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, "", fmt.Errorf("failed to parse audit events response: %w", err)
	}

	// Get next page token from header
	nextPage := resp.Header.Get("opc-next-page")

	return events, nextPage, nil
}

func shouldProcessEvent(event OCIAuditEvent, eventType string, filter EventFilter) bool {
	for _, priority := range filter.PriorityEvents {
		if eventType == priority {
			return true
		}
	}
	
	if !passesUserFilter(event, filter.UserFiltering) {
		return false
	}
	
	if !passesRateLimit(eventType, filter.RateLimiting) {
		return false
	}
	
	switch filter.Mode {
	case "include":
		if len(filter.IncludedEvents) == 0 {
			return true
		}
		for _, included := range filter.IncludedEvents {
			if eventType == included {
				return true
			}
		}
		return false
		
	case "exclude":
		for _, excluded := range filter.ExcludedEvents {
			if eventType == excluded {
				return false
			}
		}
		return true
		
	default:
		return true
	}
}

func passesRateLimit(eventType string, rateLimits map[string]RateLimit) bool {
	limit, exists := rateLimits[eventType]
	if !exists || !limit.Enabled {
		return true
	}
	
	rateLimitTracker.Lock()
	defer rateLimitTracker.Unlock()
	
	now := time.Now()
	hourAgo := now.Add(-time.Hour)
	
	var recentEvents []time.Time
	if timestamps, exists := rateLimitTracker.EventCounts[eventType]; exists {
		for _, timestamp := range timestamps {
			if timestamp.After(hourAgo) {
				recentEvents = append(recentEvents, timestamp)
			}
		}
	}
	
	if len(recentEvents) >= limit.MaxPerHour {
		return false
	}
	
	recentEvents = append(recentEvents, now)
	rateLimitTracker.EventCounts[eventType] = recentEvents
	
	return true
}

func passesUserFilter(event OCIAuditEvent, userFilter UserFilter) bool {
	if userFilter.ExcludeServiceAccounts && isServiceAccount(event) {
		return false
	}
	
	if len(userFilter.IncludeOnlyUsers) > 0 {
		userID := getUserIDFromEvent(event)
		for _, user := range userFilter.IncludeOnlyUsers {
			if userID == user {
				return true
			}
		}
		return false
	}
	
	userID := getUserIDFromEvent(event)
	for _, user := range userFilter.ExcludeUsers {
		if userID == user {
			return false
		}
	}
	
	return true
}

func getUserIDFromEvent(event OCIAuditEvent) string {
	if event.Data == nil {
		return ""
	}
	
	if identity, exists := event.Data["identity"].(map[string]interface{}); exists {
		if principalID, exists := identity["principalId"].(string); exists {
			return principalID
		}
	}
	
	return ""
}

func isServiceAccount(event OCIAuditEvent) bool {
	if event.Data == nil {
		return false
	}
	
	if identity, exists := event.Data["identity"].(map[string]interface{}); exists {
		if authType, exists := identity["authType"].(string); exists {
			// OCI internal service calls typically use "natv" auth type
			return authType == "natv" && strings.Contains(strings.ToLower(event.Source), "service")
		}
	}
	
	return false
}

func forwardEventsWithStats(events []OCIAuditEvent, config *Configuration, 
	fieldMapping FieldMapping, syslogWriter *SyslogWriter) (int, int, CacheStats, LookupStats, ChangeStats, error) {
	
	var forwarded, dropped int
	var cacheStats CacheStats
	var lookupStats LookupStats
	var changeStats ChangeStats
	
	for _, event := range events {
		// Declare eventKey at the beginning of the loop so it's available throughout
		eventKey := getEventDeduplicationKey(event)
		
		enrichedEvent, cacheHit, lookupSuccess := enrichEvent(event, fieldMapping, config)
		
		if cacheHit {
			cacheStats.Hits++
		} else {
			cacheStats.Misses++
		}
		
		if !lookupSuccess {
			lookupStats.Failures++
		} else {
			lookupStats.Success++
		}
		
		cefMessage := formatEventAsCEF(enrichedEvent, config, fieldMapping)
		syslogMessage := formatSyslogMessage("oci-audit-forwarder", cefMessage)
		
		if len(syslogMessage) > config.MaxMsgSize {
			syslogMessage = syslogMessage[:config.MaxMsgSize]
		}
		
		if err := syslogWriter.Write(syslogMessage); err != nil {
			log.Printf("🔄 Syslog write failed, attempting reconnect: %v", err)
			if reconnectErr := syslogWriter.Reconnect(); reconnectErr != nil {
				return forwarded, dropped, cacheStats, lookupStats, changeStats, fmt.Errorf("reconnection failed: %w", reconnectErr)
			}
			
			if err = syslogWriter.Write(syslogMessage); err != nil {
				dropped++
				log.Printf("❌ Failed to forward event Key=%s after reconnect: %v", eventKey, err)
				continue
			}
		}
		
		// ONLY mark as processed AFTER successful forwarding
		if eventCache != nil {
			eventCache.MarkProcessed(eventKey)
			log.Printf("✅ MARKED PROCESSED: Key=%s, Type=%s, EventTime=%s, ProcessedAt=%s", 
				eventKey, event.EventType, 
				event.EventTime,
				time.Now().Format("2006-01-02T15:04:05"))
		}
			
		forwarded++
	}
	
	return forwarded, dropped, cacheStats, lookupStats, changeStats, nil
}

func enrichEvent(event OCIAuditEvent, fieldMapping FieldMapping, config *Configuration) (map[string]interface{}, bool, bool) {
	eventKey := getEventDeduplicationKey(event)
	enriched := map[string]interface{}{
		"eventKey":            eventKey,
		"eventType":          event.EventType,
		"eventId":            event.EventID,
		"eventTime":          event.EventTime,
		"source":             event.Source,
		"cloudEventsVersion": event.CloudEventsVersion,
		"eventTypeVersion":   event.EventTypeVersion,
		"contentType":        event.ContentType,
	}
	
	// Add all data fields
	if event.Data != nil {
		for k, v := range event.Data {
			enriched[k] = v
		}
	}
	
	// Add extensions if present
	if event.Extensions != nil {
		for k, v := range event.Extensions {
			enriched[fmt.Sprintf("ext_%s", k)] = v
		}
	}
	
	// Add event type name if available
	if eventName, exists := eventTypeMap[event.EventType]; exists {
		enriched["eventTypeName"] = eventName
	}
	
	return enriched, true, true
}

func formatEventAsCEF(event map[string]interface{}, config *Configuration, fieldMapping FieldMapping) string {
	eventType := fmt.Sprintf("%v", event["eventType"])
	eventName := "OCI Audit Event"
	
	if name, exists := eventTypeMap[eventType]; exists {
		eventName = name
	}
	
	severity := mapEventTypeToSeverity(eventType)
	
	vendor := fieldMapping.CEFVendor
	if vendor == "" {
		vendor = "Oracle"
	}
	product := fieldMapping.CEFProduct
	if product == "" {
		product = "CloudInfrastructure"
	}
	version := fieldMapping.CEFVersion
	if version == "" {
		version = "1.0"
	}
	
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|",
		vendor, product, version, eventType, eventName, severity)
	
	extensions := make(map[string]string)
	
	// Apply field mappings
	for sourceKey, targetKey := range fieldMapping.FieldMappings {
		if value, exists := event[sourceKey]; exists && value != nil {
			extensions[targetKey] = sanitizeCEFValue(fmt.Sprintf("%v", value))
		}
	}
	
	// Add unmapped fields
	for k, v := range event {
		if !isMappedField(k, fieldMapping.FieldMappings) && v != nil {
			extensions[k] = sanitizeCEFValue(fmt.Sprintf("%v", v))
		}
	}
	
	// Add timestamp in the required format
	if eventTime, exists := event["eventTime"].(string); exists {
		if parsedTime, err := time.Parse(time.RFC3339, eventTime); err == nil {
			extensions["rt"] = parsedTime.Format("Jan _2 15:04:05")
		}
	}
	
	var parts []string
	
	// Add ordered fields first
	for _, field := range fieldMapping.OrderedFields {
		if value, exists := extensions[field]; exists {
			parts = append(parts, fmt.Sprintf("%s=%s", field, value))
			delete(extensions, field)
		}
	}
	
	// Add remaining fields in sorted order
	var remaining []string
	for k := range extensions {
		remaining = append(remaining, k)
	}
	sort.Strings(remaining)
	
	for _, field := range remaining {
		parts = append(parts, fmt.Sprintf("%s=%s", field, extensions[field]))
	}
	
	return header + strings.Join(parts, " ")
}

func mapEventTypeToSeverity(eventType string) int {
	eventType = strings.ToLower(eventType)
	
	// Map OCI event types to CEF severity levels
	if strings.Contains(eventType, "delete") || strings.Contains(eventType, "terminate") {
		return 8 // High
	} else if strings.Contains(eventType, "create") || strings.Contains(eventType, "update") {
		return 6 // Medium
	} else if strings.Contains(eventType, "get") || strings.Contains(eventType, "list") {
		return 3 // Low
	}
	
	return 5 // Medium (default)
}

func sanitizeCEFValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	
	// Truncate if too long
	if len(value) > 500 {
		value = value[:497] + "..."
	}
	
	return value
}

func formatSyslogMessage(hostname, message string) string {
	priority := "134" // Local use facility (16) + Informational severity (6)
	timestamp := time.Now().Format("Jan _2 15:04:05")
	return fmt.Sprintf("<%s>%s %s %s", priority, timestamp, hostname, message)
}

func isMappedField(fieldName string, fieldMappings map[string]string) bool {
	_, exists := fieldMappings[fieldName]
	return exists
}

func loadFieldMapping(filename string) FieldMapping {
	defaultMapping := createDefaultFieldMapping()
	
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("📋 Creating default field mapping file: %s", filename)
			saveFieldMapping(filename, defaultMapping)
		}
		return defaultMapping
	}
	
	var mapping FieldMapping
	if err := json.Unmarshal(data, &mapping); err != nil {
		log.Printf("❌ Error parsing field mapping file: %v, using defaults", err)
		return defaultMapping
	}
	
	return mapping
}

func loadEventTypeMap(filename string) map[string]string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("📝 Creating default event type mapping file: %s", filename)
			defaultMap := createDefaultEventTypeMap()
			saveEventTypeMap(filename, defaultMap)
			return defaultMap
		}
		log.Printf("❌ Error reading event type mapping file: %v", err)
		return make(map[string]string)
	}
	
	var eventMap map[string]string
	if err := json.Unmarshal(data, &eventMap); err != nil {
		log.Printf("❌ Error parsing event type mapping file: %v", err)
		return make(map[string]string)
	}
	
	return eventMap
}

func createDefaultFieldMapping() FieldMapping {
	return FieldMapping{
		OrderedFields: []string{
			"rt", "cs1", "cs2", "suser", "dvc", "src", "deviceEventClassId", 
			"externalId", "compartmentId", "compartmentName", "resourceName", 
			"resourceId", "principalName", "ipAddress", "userAgent",
		},
		FieldMappings: map[string]string{
			"eventTime":       "rt",
			"eventType":       "deviceEventClassId",
			"eventId":         "externalId",
			"source":          "dvc",
			"compartmentId":   "cs1",
			"compartmentName": "cs1Label",
			"resourceName":    "dvchost",
			"resourceId":      "deviceExternalId",
			"principalName":   "suser",
			"ipAddress":       "src",
			"userAgent":       "requestClientApplication",
		},
		Lookups: map[string]LookupConfig{},
		CacheInvalidationRules: map[string][]string{},
		EventFiltering: EventFilter{
			Mode:           "exclude",
			ExcludedEvents: []string{},
			IncludedEvents: []string{},
			RateLimiting:   map[string]RateLimit{},
			PriorityEvents: []string{},
			UserFiltering: UserFilter{
				ExcludeServiceAccounts: false,
				ExcludeUsers:          []string{},
				IncludeOnlyUsers:      []string{},
			},
		},
		Statistics: StatisticsConfig{
			EnableDetailedLogging:   true,
			LogIntervalEvents:       100,
			TrackCacheMetrics:       true,
			TrackPerformanceMetrics: true,
		},
		CEFVendor:  "Oracle",
		CEFProduct: "CloudInfrastructure",
		CEFVersion: "1.0",
	}
}

func createDefaultEventTypeMap() map[string]string {
	return map[string]string{
		"com.oraclecloud.ComputeApi.GetInstance":     "Get Instance",
		"com.oraclecloud.ComputeApi.LaunchInstance":  "Launch Instance",
		"com.oraclecloud.ComputeApi.TerminateInstance": "Terminate Instance",
		"com.oraclecloud.identityControlPlane.CreateUser": "Create User",
		"com.oraclecloud.identityControlPlane.UpdateUser": "Update User",
		"com.oraclecloud.identityControlPlane.DeleteUser": "Delete User",
		"com.oraclecloud.VirtualNetworkApi.CreateVcn": "Create VCN",
		"com.oraclecloud.VirtualNetworkApi.DeleteVcn": "Delete VCN",
	}
}

func saveFieldMapping(filename string, mapping FieldMapping) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(mapping, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

func saveEventTypeMap(filename string, eventMap map[string]string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(eventMap, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvOrIntDefault(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		var result int
		if _, err := fmt.Sscanf(value, "%d", &result); err == nil {
			return result
		}
	}
	return defaultValue
}

func getEnvOrBoolDefault(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		switch strings.ToLower(value) {
		case "true", "1", "yes", "y", "on":
			return true
		case "false", "0", "no", "n", "off":
			return false
		}
	}
	return defaultValue
}

// Event Cache Functions
func NewEventCache(maxSize int, windowDuration time.Duration) *EventCache {
	return &EventCache{
		processedEvents: make(map[string]time.Time),
		eventRing:       ring.New(maxSize),
		maxCacheSize:    maxSize,
		cacheWindow:     windowDuration,
	}
}

func (ec *EventCache) HasProcessed(eventID string) bool {
	ec.RLock()
	defer ec.RUnlock()
	_, exists := ec.processedEvents[eventID]
	return exists
}

func (ec *EventCache) MarkProcessed(eventID string) {
	ec.Lock()
	defer ec.Unlock()
	
	now := time.Now()
	if len(ec.processedEvents) >= ec.maxCacheSize {
		if ec.eventRing.Value != nil {
			if oldestID, ok := ec.eventRing.Value.(string); ok {
				delete(ec.processedEvents, oldestID)
			}
		}
	}
	
	ec.processedEvents[eventID] = now
	ec.eventRing.Value = eventID
	ec.eventRing = ec.eventRing.Next()
}

func (ec *EventCache) GetStats() EventCacheStats {
	ec.RLock()
	defer ec.RUnlock()
	
	return EventCacheStats{
		DuplicatesDetected: eventCacheStats.DuplicatesDetected,
		CacheHits:          eventCacheStats.CacheHits,
		CacheMisses:        eventCacheStats.CacheMisses,
		CacheSize:          len(ec.processedEvents),
	}
}

func (ec *EventCache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ec.Lock()
			now := time.Now()
			cutoff := now.Add(-ec.cacheWindow)
			
			for eventID, timestamp := range ec.processedEvents {
				if timestamp.Before(cutoff) {
					delete(ec.processedEvents, eventID)
				}
			}
			ec.Unlock()
			
		case <-ctx.Done():
			return
		}
	}
}

// Time-based Marker Functions
func loadTimeBasedMarker(filename string) TimeBasedMarker {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Error reading marker file %s: %v", filename, err)
		}
		return TimeBasedMarker{
			LastEventTime: time.Now().Add(-24 * time.Hour),
			LastEventID:   "",
			PollCount:     0,
		}
	}
	
	var marker TimeBasedMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		log.Printf("⚠️  Error parsing marker file, using defaults: %v", err)
		return TimeBasedMarker{
			LastEventTime: time.Now().Add(-24 * time.Hour),
			LastEventID:   "",
			PollCount:     0,
		}
	}
	
	log.Printf("📍 Loaded time-based marker: LastEventTime=%s, PollCount=%d", 
		marker.LastEventTime.Format(time.RFC3339), marker.PollCount)
	
	return marker
}

func saveTimeBasedMarker(filename string, marker TimeBasedMarker) error {
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal marker: %w", err)
	}
	
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for marker file: %w", err)
	}
	
	return ioutil.WriteFile(filename, data, 0644)
}

// Enhanced Filtering with Deduplication
func filterEventsWithDeduplication(events []OCIAuditEvent, filter EventFilter, stats StatisticsConfig) ([]OCIAuditEvent, int, int, int, int) {
	if filter.Mode == "all" && eventCache == nil {
		return events, 0, 0, 0, 0
	}
	
	var filteredEvents []OCIAuditEvent
	droppedCount := 0
	duplicateCount := 0
	localCacheHits := 0
	localCacheMisses := 0
	
	for _, event := range events {
		eventType := event.EventType
		eventKey := getEventDeduplicationKey(event)
		
		if eventCache != nil {
			if eventCache.HasProcessed(eventKey) {
				// CACHE HIT - it's a duplicate
				duplicateCount++
				eventCacheStats.DuplicatesDetected++
				eventCacheStats.CacheHits++
				localCacheHits++
				
				eventCache.RLock()
				processedTime, exists := eventCache.processedEvents[eventKey]
				eventCache.RUnlock()
				
				if exists {
					log.Printf("🔄 DUPLICATE: Key=%s, Type=%s, EventTime=%s, FirstProcessed=%s, Age=%v", 
						eventKey, eventType, 
						event.EventTime,
						processedTime.Format("2006-01-02T15:04:05"),
						time.Since(processedTime))
				}
				continue
			} else {
				// CACHE MISS - it's a new event
				eventCacheStats.CacheMisses++
				localCacheMisses++
			}
		}
		
		// Apply existing filtering logic
		if shouldProcessEvent(event, eventType, filter) {
			filteredEvents = append(filteredEvents, event)
		} else {
			droppedCount++
			if stats.EnableDetailedLogging {
				log.Printf("🚫 Filtered event type %s (Key: %s)", eventType, eventKey)
			}
		}
	}
	
	return filteredEvents, droppedCount, duplicateCount, localCacheHits, localCacheMisses
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}