package main

import (
	"container/ring"
	"context"
	"crypto"
	cryptorand "crypto/rand"
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
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// APIService represents a configured OCI API service
type APIService struct {
	Name                string            `json:"name"`
	Enabled             bool              `json:"enabled"`
	BaseURLTemplate     string            `json:"base_url_template"`
	APIVersion          string            `json:"api_version"`
	PollIntervalSeconds int               `json:"poll_interval_seconds"`
	Endpoints           map[string]string `json:"endpoints"`
	MarkerFile          string            `json:"marker_file"`
	Regions             []string          `json:"regions,omitempty"` // Multi-region support
}

// SimpleAPIEndpoint represents a simple API endpoint configuration
type SimpleAPIEndpoint struct {
	Name         string `json:"name"`
	URLTemplate  string `json:"url_template"`
	APIVersion   string `json:"api_version"`
	Enabled      bool   `json:"enabled"`
	PollInterval int    `json:"poll_interval"`
	MarkerFile   string `json:"marker_file"`
}

type RetryStrategy struct {
	ExponentialBackoff      bool              `json:"exponential_backoff"`
	BaseMultiplier          int               `json:"base_multiplier"`
	MaxDelaySeconds         int               `json:"max_delay_seconds"`
	JitterEnabled           bool              `json:"jitter_enabled"`
	RetryableStatusCodes    []int             `json:"retryable_status_codes"`
	NonRetryableStatusCodes []int             `json:"non_retryable_status_codes"`
	RateLimitHandling       RateLimitHandling `json:"rate_limit_handling"`
}

type RateLimitHandling struct {
	StatusCode            int  `json:"status_code"`
	UseExponentialBackoff bool `json:"use_exponential_backoff"`
	MaxBackoffSeconds     int  `json:"max_backoff_seconds"`
}

type Configuration struct {
	TenancyOCID          string   `json:"tenancy_ocid"`
	UserOCID             string   `json:"user_ocid"`
	KeyFingerprint       string   `json:"key_fingerprint"`
	PrivateKeyPath       string   `json:"private_key_path"`
	Region               string   `json:"region"`
	APIBaseURL           string   `json:"api_base_url"` // Legacy field for backward compatibility
	APIVersion           string   `json:"api_version"`  // Legacy field for backward compatibility
	SyslogProtocol       string   `json:"syslog_protocol"`
	SyslogServer         string   `json:"syslog_server"`
	SyslogPort           string   `json:"syslog_port"`
	LogLevel             string   `json:"log_level"`
	LogFile              string   `json:"log_file"`
	FetchInterval        int      `json:"fetch_interval"`
	ConnTimeout          int      `json:"conn_timeout"`
	MaxMsgSize           int      `json:"max_msg_size"`
	MarkerFile           string   `json:"marker_file"` // Legacy field for backward compatibility
	FieldMapFile         string   `json:"field_map_file"`
	EventMapFile         string   `json:"event_map_file"`
	Verbose              bool     `json:"verbose"`
	MaxRetries           int      `json:"max_retries"`
	RetryDelay           int      `json:"retry_delay"`
	HealthCheckPort      int      `json:"health_check_port"`
	TestMode             bool     `json:"test_mode"`
	ValidateMode         bool     `json:"validate_mode"`
	ShowVersion          bool     `json:"show_version"`
	EventCacheSize       int      `json:"event_cache_size"`
	EventCacheWindow     int      `json:"event_cache_window"`
	EnableEventCache     bool     `json:"enable_event_cache"`
	InitialLookbackHours int      `json:"initial_lookback_hours"`
	PollOverlapMinutes   int      `json:"poll_overlap_minutes"`
	MaxEventsPerPoll     int      `json:"max_events_per_poll"`
	CompartmentMode      string   `json:"compartment_mode"`
	CompartmentIDs       []string `json:"compartment_ids"`

	// Compartment refresh configuration
	CompartmentRefreshInterval int  `json:"compartment_refresh_interval"` // Minutes between compartment refreshes (0 = disabled)
	EnableCompartmentRefresh   bool `json:"enable_compartment_refresh"`   // Enable automatic compartment discovery

	// Retry strategy configuration
	RetryStrategy RetryStrategy `json:"retry_strategy,omitempty"`

	// New multi-endpoint configurations
	APIServices  []APIService        `json:"api_services,omitempty"`  // Service-based configuration
	APIEndpoints []SimpleAPIEndpoint `json:"api_endpoints,omitempty"` // Simple endpoint list configuration
}

type FieldMapping struct {
	OrderedFields          []string                   `json:"ordered_fields"`
	FieldMappings          map[string]string          `json:"field_mappings"`   // Legacy - for backward compatibility
	ServiceMappings        map[string]ServiceFieldMap `json:"service_mappings"` // New service-specific mappings
	Lookups                map[string]LookupConfig    `json:"lookups"`
	CacheInvalidationRules map[string][]string        `json:"cache_invalidation_rules"`
	EventFiltering         EventFilter                `json:"event_filtering"`
	Statistics             StatisticsConfig           `json:"statistics"`
	CEFVendor              string                     `json:"cef_vendor"`
	CEFProduct             string                     `json:"cef_product"`
	CEFVersion             string                     `json:"cef_version"`
}

type ServiceFieldMap struct {
	FieldMappings       map[string]string `json:"field_mappings"`
	NestedFieldMappings map[string]string `json:"nested_field_mappings"`
}

type EventFilter struct {
	Mode           string               `json:"mode"`
	ExcludedEvents []string             `json:"excluded_events"`
	IncludedEvents []string             `json:"included_events"`
	RateLimiting   map[string]RateLimit `json:"rate_limiting"`
	PriorityEvents []string             `json:"priority_events"`
	UserFiltering  UserFilter           `json:"user_filtering"`
}

type RateLimit struct {
	MaxPerHour int  `json:"max_per_hour"`
	Enabled    bool `json:"enabled"`
}

type UserFilter struct {
	ExcludeServiceAccounts bool     `json:"exclude_service_accounts"`
	ExcludeUsers           []string `json:"exclude_users"`
	IncludeOnlyUsers       []string `json:"include_only_users"`
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
	StartTime            time.Time
	LastSuccessfulRun    time.Time
	TotalEventsForwarded int64
	TotalEventsFiltered  int64
	TotalEventsDropped   int64
	TotalAPIRequests     int64
	FailedAPIRequests    int64
	TotalRetryAttempts   int64
	SuccessfulRecoveries int64
	SyslogReconnects     int64
	// Separated cache statistics for clarity
	EventCacheHits         int64 // Deduplication cache hits
	EventCacheMisses       int64 // Deduplication cache misses
	LookupCacheHits        int64 // Field lookup cache hits
	LookupCacheMisses      int64 // Field lookup cache misses
	LookupFailures         int64
	ChangeDetectionEvents  int64
	MarkerFileUpdates      int64
	CompartmentErrors      int64 // Track compartment access failures
	LastError              string
	LastErrorTime          time.Time
	LastMarker             string
	CurrentPollDuration    time.Duration
	AverageEventsPerSecond float64
	// Statistics tracking
	LastPeriodicLog    time.Time
	EventsSinceLastLog int64
}

type RateLimitTracker struct {
	sync.RWMutex
	EventCounts map[string][]time.Time
}

// OCI Audit Event structures
type OCIAuditEvent struct {
	EventType          string                 `json:"eventType"`
	CloudEventsVersion string                 `json:"cloudEventsVersion"`
	EventTypeVersion   string                 `json:"eventTypeVersion"`
	Source             string                 `json:"source"`
	EventID            string                 `json:"eventId"`
	EventTime          string                 `json:"eventTime"`
	ContentType        string                 `json:"contentType"`
	Data               map[string]interface{} `json:"data"`
	Extensions         map[string]interface{} `json:"extensions,omitempty"`
}

type OCICompartment struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	LifecycleState string `json:"lifecycleState"`
	TimeCreated    string `json:"timeCreated"`
}

// CloudGuard event structures
type CloudGuardProblem struct {
	ID            string                 `json:"id"`
	ProblemType   string                 `json:"problemType"`
	RiskLevel     string                 `json:"riskLevel"`
	Status        string                 `json:"status"`
	TimeCreated   string                 `json:"timeCreated"`
	TimeUpdated   string                 `json:"timeUpdated"`
	CompartmentId string                 `json:"compartmentId"`
	ResourceName  string                 `json:"resourceName"`
	ResourceId    string                 `json:"resourceId"`
	TargetId      string                 `json:"targetId"`
	DetectorId    string                 `json:"detectorId"`
	Description   string                 `json:"description"`
	Labels        []string               `json:"labels,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

type CloudGuardDetector struct {
	ID             string                 `json:"id"`
	DisplayName    string                 `json:"displayName"`
	Description    string                 `json:"description"`
	RiskLevel      string                 `json:"riskLevel"`
	ServiceType    string                 `json:"serviceType"`
	DetectorType   string                 `json:"detectorType"`
	LifecycleState string                 `json:"lifecycleState"`
	TimeCreated    string                 `json:"timeCreated"`
	TimeUpdated    string                 `json:"timeUpdated"`
	CompartmentId  string                 `json:"compartmentId"`
	IsEnabled      bool                   `json:"isEnabled"`
	Condition      string                 `json:"condition,omitempty"`
	Labels         []string               `json:"labels,omitempty"`
	DetectorRules  []DetectorRule         `json:"detectorRules,omitempty"`
	SystemTags     map[string]interface{} `json:"systemTags,omitempty"`
	DefinedTags    map[string]interface{} `json:"definedTags,omitempty"`
	FreeformTags   map[string]interface{} `json:"freeformTags,omitempty"`
}

type DetectorRule struct {
	DetectorRuleId   string          `json:"detectorRuleId"`
	DisplayName      string          `json:"displayName"`
	Description      string          `json:"description"`
	Recommendation   string          `json:"recommendation"`
	DataSourceId     string          `json:"dataSourceId"`
	EntitiesMapping  []EntityMapping `json:"entitiesMapping,omitempty"`
	LifecycleState   string          `json:"lifecycleState"`
	TimeCreated      string          `json:"timeCreated"`
	TimeUpdated      string          `json:"timeUpdated"`
	ServiceType      string          `json:"serviceType"`
	ResourceType     string          `json:"resourceType"`
	ManagedListTypes []string        `json:"managedListTypes,omitempty"`
}

type EntityMapping struct {
	DisplayName string `json:"displayName"`
	QueryField  string `json:"queryField"`
	EntityType  string `json:"entityType"`
	DataType    string `json:"dataType"`
}

type CloudGuardTarget struct {
	ID                      string                  `json:"id"`
	DisplayName             string                  `json:"displayName"`
	Description             string                  `json:"description"`
	CompartmentId           string                  `json:"compartmentId"`
	TargetResourceType      string                  `json:"targetResourceType"`
	TargetResourceId        string                  `json:"targetResourceId"`
	RecipeCount             int                     `json:"recipeCount"`
	LifecycleState          string                  `json:"lifecycleState"`
	LifeCycleDetails        string                  `json:"lifecycleDetails,omitempty"`
	TimeCreated             string                  `json:"timeCreated"`
	TimeUpdated             string                  `json:"timeUpdated"`
	InheritedByCompartments []string                `json:"inheritedByCompartments,omitempty"`
	TargetDetectorRecipes   []TargetDetectorRecipe  `json:"targetDetectorRecipes,omitempty"`
	TargetResponderRecipes  []TargetResponderRecipe `json:"targetResponderRecipes,omitempty"`
	SystemTags              map[string]interface{}  `json:"systemTags,omitempty"`
	DefinedTags             map[string]interface{}  `json:"definedTags,omitempty"`
	FreeformTags            map[string]interface{}  `json:"freeformTags,omitempty"`
}

// OCI Logging service structures
type OCILogGroup struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	Description    string `json:"description"`
	CompartmentId  string `json:"compartmentId"`
	LifecycleState string `json:"lifecycleState"`
}

type OCILogInfo struct {
	ID           string `json:"id"`
	DisplayName  string `json:"displayName"`
	LogType      string `json:"logType"`
	LogGroupName string `json:"logGroupName"`
	LogGroupId   string `json:"logGroupId"`
	IsEnabled    bool   `json:"isEnabled"`
	Source       struct {
		SourceType string `json:"sourceType"`
		Resource   string `json:"resource"`
	} `json:"source"`
}

// VCN Flow Log structures
type VCNFlowLog struct {
	ID            string                 `json:"id"`
	Time          string                 `json:"time"`
	Datetime      string                 `json:"datetime"`
	LogContent    VCNFlowLogContent      `json:"logContent"`
	Data          map[string]interface{} `json:"data"`
	Source        string                 `json:"source"`
	Type          string                 `json:"type"`
	Subject       string                 `json:"subject"`
	TenancyID     string                 `json:"oracle.tenancyId"`
	CompartmentID string                 `json:"oracle.compartmentId"`
}

type VCNFlowLogContent struct {
	Version       int    `json:"version"`
	Account       string `json:"account"`
	InterfaceID   string `json:"interfaceid"`
	SourceAddr    string `json:"srcaddr"`
	DestAddr      string `json:"dstaddr"`
	SourcePort    int    `json:"srcport"`
	DestPort      int    `json:"dstport"`
	Protocol      int    `json:"protocol"`
	Packets       int    `json:"packets"`
	Bytes         int    `json:"bytes"`
	WindowStart   int64  `json:"windowstart"`
	WindowEnd     int64  `json:"windowend"`
	Action        string `json:"action"`
	FlowState     string `json:"flowstate"`
	VNICID        string `json:"vnicid"`
	SubnetID      string `json:"subnetid"`
	VCNID         string `json:"vcnid"`
	CompartmentID string `json:"compartmentid"`
}

type TargetDetectorRecipe struct {
	Id                     string                  `json:"id"`
	DisplayName            string                  `json:"displayName"`
	Description            string                  `json:"description"`
	CompartmentId          string                  `json:"compartmentId"`
	DetectorRecipeId       string                  `json:"detectorRecipeId"`
	Owner                  string                  `json:"owner"`
	Detector               string                  `json:"detector"`
	LifecycleState         string                  `json:"lifecycleState"`
	TimeCreated            string                  `json:"timeCreated"`
	TimeUpdated            string                  `json:"timeUpdated"`
	EffectiveDetectorRules []EffectiveDetectorRule `json:"effectiveDetectorRules,omitempty"`
}

type TargetResponderRecipe struct {
	Id                      string                   `json:"id"`
	ResponderRecipeId       string                   `json:"responderRecipeId"`
	CompartmentId           string                   `json:"compartmentId"`
	DisplayName             string                   `json:"displayName"`
	Description             string                   `json:"description"`
	Owner                   string                   `json:"owner"`
	TimeCreated             string                   `json:"timeCreated"`
	TimeUpdated             string                   `json:"timeUpdated"`
	LifecycleState          string                   `json:"lifecycleState"`
	EffectiveResponderRules []EffectiveResponderRule `json:"effectiveResponderRules,omitempty"`
}

type EffectiveDetectorRule struct {
	DetectorRuleId   string                 `json:"detectorRuleId"`
	DisplayName      string                 `json:"displayName"`
	Description      string                 `json:"description"`
	Recommendation   string                 `json:"recommendation"`
	DataSourceId     string                 `json:"dataSourceId"`
	State            string                 `json:"state"`
	Details          map[string]interface{} `json:"details,omitempty"`
	ManagedListTypes []string               `json:"managedListTypes,omitempty"`
	TimeCreated      string                 `json:"timeCreated"`
	TimeUpdated      string                 `json:"timeUpdated"`
	LifecycleState   string                 `json:"lifecycleState"`
	LifecycleDetails string                 `json:"lifecycleDetails,omitempty"`
}

type EffectiveResponderRule struct {
	ResponderRuleId  string                 `json:"responderRuleId"`
	DisplayName      string                 `json:"displayName"`
	Description      string                 `json:"description"`
	Type             string                 `json:"type"`
	Policies         []string               `json:"policies,omitempty"`
	SupportedModes   []string               `json:"supportedModes,omitempty"`
	Details          map[string]interface{} `json:"details,omitempty"`
	TimeCreated      string                 `json:"timeCreated"`
	TimeUpdated      string                 `json:"timeUpdated"`
	LifecycleState   string                 `json:"lifecycleState"`
	LifecycleDetails string                 `json:"lifecycleDetails,omitempty"`
}

// Generic service event wrapper
type ServiceEvent struct {
	ServiceName string      `json:"serviceName"`
	EventType   string      `json:"eventType"`
	EventTime   string      `json:"eventTime"`
	EventID     string      `json:"eventId"`
	RawData     interface{} `json:"rawData"`
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
	LastEventTime time.Time               `json:"last_event_time"`
	LastEventID   string                  `json:"last_event_id"`
	PollCount     int64                   `json:"poll_count"`
	RegionMarkers map[string]RegionMarker `json:"region_markers,omitempty"`
}

type RegionMarker struct {
	LastEventTime time.Time `json:"last_event_time"`
	LastEventID   string    `json:"last_event_id"`
}

type OCIClient struct {
	httpClient *http.Client
	privateKey *rsa.PrivateKey
	config     *Configuration
}

var (
	serviceStats       = &ServiceStats{StartTime: time.Now()}
	rateLimitTracker   = &RateLimitTracker{EventCounts: make(map[string][]time.Time)}
	lookupCache        = &LookupCache{data: make(map[string]map[string]interface{})}
	ctx                context.Context
	cancel             context.CancelFunc
	ociClient          *OCIClient
	eventTypeMap       map[string]string
	eventCache         *EventCache
	eventCacheStats    = &EventCacheStats{}
	timeBasedMarker    = &TimeBasedMarker{}
	compartments       = &CompartmentManager{compartments: []OCICompartment{}} // Legacy single-region support
	regionCompartments = NewRegionCompartmentManager()                         // Multi-region support
	rateLimitState     = &RateLimitState{}                                     // Rate limit awareness
)

// RateLimitState tracks global rate limiting to coordinate across goroutines
type RateLimitState struct {
	sync.RWMutex
	lastRateLimit   time.Time
	backoffUntil    time.Time
	consecutiveHits int
}

// RecordRateLimit updates the global rate limit state
func (rls *RateLimitState) RecordRateLimit() {
	rls.Lock()
	defer rls.Unlock()

	rls.lastRateLimit = time.Now()
	rls.consecutiveHits++

	// Use progressive backoff based on consecutive hits
	backoffDuration := time.Duration(rls.consecutiveHits*30) * time.Second
	if backoffDuration > 10*time.Minute {
		backoffDuration = 10 * time.Minute
	}
	rls.backoffUntil = time.Now().Add(backoffDuration)
}

// RecordSuccess resets consecutive hits on successful API call
func (rls *RateLimitState) RecordSuccess() {
	rls.Lock()
	defer rls.Unlock()
	rls.consecutiveHits = 0
}

// ShouldBackoff returns true if we should avoid API calls due to rate limiting
func (rls *RateLimitState) ShouldBackoff() (bool, time.Duration) {
	rls.RLock()
	defer rls.RUnlock()

	if time.Now().Before(rls.backoffUntil) {
		remaining := time.Until(rls.backoffUntil)
		return true, remaining
	}
	return false, 0
}

// IsInRateLimitPeriod returns true if we've hit rate limits recently
func (rls *RateLimitState) IsInRateLimitPeriod() bool {
	rls.RLock()
	defer rls.RUnlock()

	// Consider us "in rate limit period" if we've hit limits in the last 5 minutes
	return time.Since(rls.lastRateLimit) < 5*time.Minute
}

// CompartmentManager provides thread-safe access to compartments
type CompartmentManager struct {
	sync.RWMutex
	compartments []OCICompartment
}

func (cm *CompartmentManager) Get() []OCICompartment {
	cm.RLock()
	defer cm.RUnlock()
	result := make([]OCICompartment, len(cm.compartments))
	copy(result, cm.compartments)
	return result
}

func (cm *CompartmentManager) Set(newCompartments []OCICompartment) {
	cm.Lock()
	defer cm.Unlock()
	cm.compartments = make([]OCICompartment, len(newCompartments))
	copy(cm.compartments, newCompartments)
}

func (cm *CompartmentManager) Count() int {
	cm.RLock()
	defer cm.RUnlock()
	return len(cm.compartments)
}

// RegionCompartmentManager provides thread-safe access to compartments per region
type RegionCompartmentManager struct {
	sync.RWMutex
	regionCompartments map[string][]OCICompartment
}

func NewRegionCompartmentManager() *RegionCompartmentManager {
	return &RegionCompartmentManager{
		regionCompartments: make(map[string][]OCICompartment),
	}
}

func (rcm *RegionCompartmentManager) GetForRegion(region string) []OCICompartment {
	rcm.RLock()
	defer rcm.RUnlock()
	compartments, exists := rcm.regionCompartments[region]
	if !exists {
		return []OCICompartment{}
	}
	result := make([]OCICompartment, len(compartments))
	copy(result, compartments)
	return result
}

func (rcm *RegionCompartmentManager) SetForRegion(region string, newCompartments []OCICompartment) {
	rcm.Lock()
	defer rcm.Unlock()
	rcm.regionCompartments[region] = make([]OCICompartment, len(newCompartments))
	copy(rcm.regionCompartments[region], newCompartments)
}

func (rcm *RegionCompartmentManager) CountForRegion(region string) int {
	rcm.RLock()
	defer rcm.RUnlock()
	compartments, exists := rcm.regionCompartments[region]
	if !exists {
		return 0
	}
	return len(compartments)
}

func (rcm *RegionCompartmentManager) GetAllRegions() []string {
	rcm.RLock()
	defer rcm.RUnlock()
	var regions []string
	for region := range rcm.regionCompartments {
		regions = append(regions, region)
	}
	return regions
}

func (rcm *RegionCompartmentManager) TotalCompartments() int {
	rcm.RLock()
	defer rcm.RUnlock()
	total := 0
	for _, compartments := range rcm.regionCompartments {
		total += len(compartments)
	}
	return total
}

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
		if err := runConnectionTests(config); err != nil {
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

	eventTypeMap = loadEventTypeMap(config.EventMapFile, config)

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

	// Load compartments only if needed by enabled services
	enabledServices := config.getEnabledServices()
	needsCompartments := false
	allRegions := make(map[string]bool)

	for _, service := range enabledServices {
		if service.Name == "audit" || service.Name == "cloudguard" {
			needsCompartments = true
			// Collect all regions from all services
			for _, region := range config.getServiceRegions(service) {
				allRegions[region] = true
			}
		}
	}

	if needsCompartments {
		for region := range allRegions {
			if err := loadOCICompartmentsForRegion(config, region); err != nil {
				log.Fatalf("❌ Failed to load compartments for region %s: %v", region, err)
			}
		}
		log.Printf("🏢 Loaded compartments across %d regions (total: %d compartments)",
			len(allRegions), regionCompartments.TotalCompartments())
	} else {
		log.Println("🏢 No compartment-scoped services enabled - skipping compartment enumeration")
	}

	log.Printf("✅ Successfully authenticated with OCI")

	log.Println("💾 Cache initialized")
	log.Printf("🗺️  Field mappings loaded (%d lookups)", len(fieldMapping.Lookups))
	log.Printf("📝 Event types loaded (%d types)", len(eventTypeMap))

	// Load the most recent marker from enabled services (or create new)
	timeBasedMarker := loadMostRecentServiceMarker(config)
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

	// Start compartment refresh goroutine if enabled
	if needsCompartments && config.EnableCompartmentRefresh && config.CompartmentRefreshInterval > 0 {
		go startCompartmentRefresh(config)
		log.Printf("🔄 Compartment refresh enabled: every %d minutes", config.CompartmentRefreshInterval)
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
				eventTypeMap = loadEventTypeMap(config.EventMapFile, config)
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
	// Simplified CLI - only essential flags
	configFile := flag.String("config", getEnvOrDefault("CONFIG_FILE", "oci-config.json"), "Path to JSON configuration file")
	testMode := flag.Bool("test", false, "Test connections and dependencies")
	validateMode := flag.Bool("validate", false, "Validate configuration and exit")
	showVersion := flag.Bool("version", false, "Show version information")
	verbose := flag.Bool("verbose", getEnvOrBoolDefault("VERBOSE", false), "Enable verbose output")

	flag.Parse()

	// Load from JSON configuration file
	config, err := loadConfigFromJSON(*configFile)
	if err != nil {
		log.Fatalf("❌ Failed to load config file %s: %v\n💡 Epimetheus now requires JSON configuration. Use --config to specify the path.", *configFile, err)
	}

	// Override only the essential CLI flags
	config.TestMode = *testMode
	config.ValidateMode = *validateMode
	config.ShowVersion = *showVersion
	config.Verbose = *verbose

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

	// Apply backward compatibility and default configurations
	config = *ensureBackwardCompatibility(&config)

	log.Printf("📋 Loaded configuration from %s", filename)
	return &config, nil
}

// ensureBackwardCompatibility ensures that configurations work with both old and new endpoint formats
func ensureBackwardCompatibility(config *Configuration) *Configuration {
	// If no new-style endpoints are configured but legacy fields exist, create default audit service
	if len(config.APIServices) == 0 && len(config.APIEndpoints) == 0 {
		// Create default audit service from legacy configuration
		auditService := APIService{
			Name:                "audit",
			Enabled:             true,
			BaseURLTemplate:     config.APIBaseURL,
			APIVersion:          config.APIVersion,
			PollIntervalSeconds: config.FetchInterval,
			Endpoints: map[string]string{
				"events":       "/auditEvents",
				"compartments": "/compartments",
			},
			MarkerFile: config.MarkerFile,
		}

		// Auto-generate base URL if not provided
		if auditService.BaseURLTemplate == "" {
			auditService.BaseURLTemplate = fmt.Sprintf("https://audit.%s.oraclecloud.com", config.Region)
		}
		if auditService.APIVersion == "" {
			auditService.APIVersion = "20190901"
		}
		if auditService.MarkerFile == "" {
			auditService.MarkerFile = "oci-audit-marker.json"
		}

		config.APIServices = []APIService{auditService}
	}

	// Set defaults for fields that may not be in JSON
	if config.CompartmentRefreshInterval == 0 {
		config.CompartmentRefreshInterval = 60 // Default 60 minutes
	}
	// EnableCompartmentRefresh defaults to true for new installations
	if !config.EnableCompartmentRefresh && config.CompartmentRefreshInterval > 0 {
		config.EnableCompartmentRefresh = true
	}

	return config
}

// getEnabledServices returns all enabled API services from configuration
func (c *Configuration) getEnabledServices() []APIService {
	var enabled []APIService
	for _, service := range c.APIServices {
		if service.Enabled {
			enabled = append(enabled, service)
		}
	}
	return enabled
}

// buildServiceURLForRegion constructs the full URL for a service endpoint in a specific region
func (c *Configuration) buildServiceURLForRegion(service APIService, endpointPath, region string) string {
	baseURL := strings.Replace(service.BaseURLTemplate, "{region}", region, -1)
	return fmt.Sprintf("%s/%s%s", baseURL, service.APIVersion, endpointPath)
}

// getServiceRegions returns the regions to monitor for a service
func (c *Configuration) getServiceRegions(service APIService) []string {
	if len(service.Regions) > 0 {
		return service.Regions
	}
	// Fall back to global region for backward compatibility
	return []string{c.Region}
}

func validateConfig(config *Configuration) error {
	// Check required fields
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

	// Enhanced validation for better error detection
	if config.FetchInterval < 10 {
		return fmt.Errorf("fetch interval must be at least 10 seconds")
	}
	if config.FetchInterval > 3600 {
		return fmt.Errorf("fetch interval should not exceed 3600 seconds (1 hour)")
	}

	// Validate syslog configuration
	if config.SyslogProtocol != "tcp" && config.SyslogProtocol != "udp" {
		return fmt.Errorf("syslog protocol must be 'tcp' or 'udp', got: %s", config.SyslogProtocol)
	}
	if config.SyslogPort == "" {
		return fmt.Errorf("syslog port is required")
	}

	// Validate compartment mode
	validCompartmentModes := []string{"all", "tenancy_only", "include", "exclude"}
	validMode := false
	for _, mode := range validCompartmentModes {
		if config.CompartmentMode == mode {
			validMode = true
			break
		}
	}
	if !validMode {
		return fmt.Errorf("compartment_mode must be one of: %v, got: %s", validCompartmentModes, config.CompartmentMode)
	}

	// Validate compartment IDs if using include/exclude modes
	if (config.CompartmentMode == "include" || config.CompartmentMode == "exclude") && len(config.CompartmentIDs) == 0 {
		return fmt.Errorf("compartment_ids cannot be empty when compartment_mode is '%s'", config.CompartmentMode)
	}

	// Validate retry configuration
	if config.MaxRetries < 0 || config.MaxRetries > 10 {
		return fmt.Errorf("max_retries must be between 0 and 10, got: %d", config.MaxRetries)
	}
	if config.RetryDelay < 1 || config.RetryDelay > 60 {
		return fmt.Errorf("retry_delay must be between 1 and 60 seconds, got: %d", config.RetryDelay)
	}

	// Validate cache configuration
	if config.EventCacheSize < 0 || config.EventCacheSize > 1000000 {
		return fmt.Errorf("event_cache_size must be between 0 and 1000000, got: %d", config.EventCacheSize)
	}
	if config.EventCacheWindow < 0 || config.EventCacheWindow > 86400 {
		return fmt.Errorf("event_cache_window must be between 0 and 86400 seconds (24 hours), got: %d", config.EventCacheWindow)
	}

	// Validate compartment refresh configuration
	if config.CompartmentRefreshInterval < 0 || config.CompartmentRefreshInterval > 1440 {
		return fmt.Errorf("compartment_refresh_interval must be between 0 and 1440 minutes (24 hours), got: %d", config.CompartmentRefreshInterval)
	}
	if config.EnableCompartmentRefresh && config.CompartmentRefreshInterval == 0 {
		return fmt.Errorf("compartment_refresh_interval cannot be 0 when enable_compartment_refresh is true")
	}

	// Validate API services configuration
	if len(config.APIServices) > 0 {
		for i, service := range config.APIServices {
			if service.Name == "" {
				return fmt.Errorf("api_services[%d]: service name cannot be empty", i)
			}
			if service.BaseURLTemplate == "" {
				return fmt.Errorf("api_services[%d]: base_url_template cannot be empty for service '%s'", i, service.Name)
			}
			if service.APIVersion == "" {
				return fmt.Errorf("api_services[%d]: api_version cannot be empty for service '%s'", i, service.Name)
			}
			if service.PollIntervalSeconds < 10 || service.PollIntervalSeconds > 3600 {
				return fmt.Errorf("api_services[%d]: poll_interval_seconds must be between 10 and 3600 seconds for service '%s', got: %d",
					i, service.Name, service.PollIntervalSeconds)
			}
		}
	}

	// Validate private key file exists and is readable
	if _, err := os.Stat(config.PrivateKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("private key file does not exist: %s", config.PrivateKeyPath)
	}

	// Validate region format (basic check)
	if len(config.Region) < 3 || !strings.Contains(config.Region, "-") {
		return fmt.Errorf("region format appears invalid: %s (expected format like 'us-ashburn-1')", config.Region)
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
	log.Printf("🚀 Starting OCI Multi-Service Event Forwarder v1.0.0")
	log.Printf("📋 PID: %d", os.Getpid())

	// Log enabled services
	enabledServices := config.getEnabledServices()
	if len(enabledServices) > 0 {
		log.Printf("🔧 Enabled Services:")
		for _, service := range enabledServices {
			log.Printf("  - %s: %s (poll: %ds)", service.Name, strings.Replace(service.BaseURLTemplate, "{region}", config.Region, -1), service.PollIntervalSeconds)
		}
	} else {
		log.Printf("⚠️  No API services configured - using legacy single audit endpoint")
		log.Printf("🔐 API: %s", config.APIBaseURL)
	}

	log.Printf("🏢 Tenancy: %s", config.TenancyOCID)
	log.Printf("🌍 Region: %s", config.Region)
	log.Printf("📡 Syslog: %s:%s (%s)", config.SyslogServer, config.SyslogPort, config.SyslogProtocol)
	log.Printf("⏱️  Base Interval: %ds", config.FetchInterval)
	log.Printf("🗺️  Field Map: %s", config.FieldMapFile)
	log.Printf("📝 Event Map: %s", config.EventMapFile)

	if config.EnableCompartmentRefresh && config.CompartmentRefreshInterval > 0 {
		log.Printf("🔄 Compartment Refresh: every %d minutes", config.CompartmentRefreshInterval)
	} else {
		log.Printf("🔄 Compartment Refresh: disabled")
	}
}

func runConnectionTests(config *Configuration) error {
	// Function now expects *Configuration pointer (consistent with other functions)
	log.Println("🔍 Testing configuration and connections...")

	log.Print("  Testing OCI API authentication... ")
	client, err := NewOCIClient(config) // NewOCIClient already expects *Configuration
	if err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	ociClient = client
	log.Println("✅ SUCCESS")

	log.Print("  Testing OCI API connectivity... ")
	if err := testOCIAPI(config); err != nil { // testOCIAPI expects *Configuration
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing Syslog connectivity... ")
	writer, err := NewSyslogWriter(config.SyslogProtocol,
		fmt.Sprintf("%s:%s", config.SyslogServer, config.SyslogPort), config) // NewSyslogWriter expects *Configuration
	if err != nil {
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	writer.Close()
	log.Println("✅ SUCCESS")

	log.Print("  Testing configuration files... ")
	if err := testConfigFiles(config); err != nil { // testConfigFiles expects *Configuration
		log.Printf("❌ FAILED: %v", err)
		return err
	}
	log.Println("✅ SUCCESS")

	log.Print("  Testing file permissions... ")
	if err := testFilePermissions(config); err != nil { // testFilePermissions expects *Configuration
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
	signature, err := rsa.SignPKCS1v15(cryptorand.Reader, c.privateKey, crypto.SHA256, hashed[:])
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

func loadOCICompartmentsForRegion(config *Configuration, region string) error {
	// Always include the tenancy root compartment
	tenancyCompartment := OCICompartment{
		ID:             config.TenancyOCID,
		Name:           fmt.Sprintf("root (%s)", region),
		Description:    fmt.Sprintf("Root tenancy compartment in %s", region),
		LifecycleState: "ACTIVE",
		TimeCreated:    time.Now().Format(time.RFC3339),
	}
	allCompartments := []OCICompartment{tenancyCompartment}

	// Load sub-compartments if needed
	if config.CompartmentMode != "tenancy_only" {
		if err := loadSubCompartmentsForRegion(config.TenancyOCID, config, region, &allCompartments); err != nil {
			return err
		}
	}

	// Apply filtering
	filteredCompartments := filterCompartments(allCompartments, config)

	// Store in region-specific compartment manager
	regionCompartments.SetForRegion(region, filteredCompartments)

	// Also update legacy compartments manager if this is the primary region
	if region == config.Region {
		compartments.Set(filteredCompartments)
	}

	log.Printf("🏢 Region %s: Loaded %d compartments for monitoring", region, len(filteredCompartments))
	if config.Verbose {
		for _, comp := range filteredCompartments {
			log.Printf("  - %s (%s) [%s]", comp.Name, comp.ID, comp.LifecycleState)
		}
	}

	return nil
}

func loadSubCompartmentsForRegion(compartmentID string, config *Configuration, region string, allCompartments *[]OCICompartment) error {
	return loadSubCompartmentsWithVisitedForRegion(compartmentID, config, region, make(map[string]bool), allCompartments)
}

func loadSubCompartmentsWithVisitedForRegion(compartmentID string, config *Configuration, region string, visited map[string]bool, allCompartments *[]OCICompartment) error {
	// Cycle detection - prevent infinite recursion
	if visited[compartmentID] {
		log.Printf("⚠️  Compartment cycle detected in region %s, skipping %s", region, compartmentID)
		return nil
	}
	visited[compartmentID] = true

	// Use retry logic for compartment API calls
	compartmentsList, err := fetchCompartmentsWithRetry(config, compartmentID, region)
	if err != nil {
		return err
	}

	// Add delay between compartment API calls to respect Oracle's rate limits
	if len(*allCompartments) > 1 { // Skip delay for first call (root compartment)
		time.Sleep(2 * time.Second)
	}

	*allCompartments = append(*allCompartments, compartmentsList...)

	// Recursively load sub-compartments
	for _, comp := range compartmentsList {
		if err := loadSubCompartmentsWithVisitedForRegion(comp.ID, config, region, visited, allCompartments); err != nil {
			// Track compartment errors for monitoring
			serviceStats.Lock()
			serviceStats.CompartmentErrors++
			serviceStats.Unlock()

			log.Printf("❌ Failed to load sub-compartments for %s (%s): %v", comp.Name, comp.ID, err)

			// For critical compartment errors, we should consider failing the entire load
			// but for now, continue with partial results and track the error
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
	// Test with a simple compartment list request using retry logic
	_, err := fetchCompartmentsWithRetry(config, config.TenancyOCID, config.Region)
	return err
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

func startHealthCheckServer(port int) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		serviceStats.RLock()

		// Get cache stats if available
		var cacheStats EventCacheStats
		if eventCache != nil {
			cacheStats = eventCache.GetStats()
		}

		// Determine actual health status based on system state
		healthStatus := "healthy"
		var healthIssues []string
		httpStatus := http.StatusOK

		// Check if we've had recent API activity
		timeSinceLastRun := time.Since(serviceStats.LastSuccessfulRun)
		if timeSinceLastRun > 2*time.Hour {
			healthIssues = append(healthIssues, "no_recent_api_activity")
			healthStatus = "degraded"
		}

		// Check API failure rate
		if serviceStats.TotalAPIRequests > 0 {
			failureRate := float64(serviceStats.FailedAPIRequests) / float64(serviceStats.TotalAPIRequests)
			if failureRate > 0.5 {
				healthIssues = append(healthIssues, "high_api_failure_rate")
				healthStatus = "unhealthy"
				httpStatus = http.StatusServiceUnavailable
			} else if failureRate > 0.25 {
				healthIssues = append(healthIssues, "elevated_api_failure_rate")
				healthStatus = "degraded"
			}
		}

		// Check syslog reconnection frequency
		if serviceStats.SyslogReconnects > 10 {
			healthIssues = append(healthIssues, "frequent_syslog_reconnects")
			healthStatus = "degraded"
		}

		// Check compartment errors
		if serviceStats.CompartmentErrors > 5 {
			healthIssues = append(healthIssues, "compartment_access_issues")
			healthStatus = "degraded"
		}

		// Check for recent errors
		if !serviceStats.LastErrorTime.IsZero() && time.Since(serviceStats.LastErrorTime) < 30*time.Minute {
			healthIssues = append(healthIssues, "recent_errors")
			if time.Since(serviceStats.LastErrorTime) < 5*time.Minute {
				healthStatus = "unhealthy"
				httpStatus = http.StatusServiceUnavailable
			} else {
				healthStatus = "degraded"
			}
		}

		// Check if we're processing events (should have some activity)
		if serviceStats.TotalEventsForwarded == 0 && time.Since(serviceStats.StartTime) > 1*time.Hour {
			healthIssues = append(healthIssues, "no_events_processed")
			healthStatus = "degraded"
		}

		status := map[string]interface{}{
			"status":              healthStatus,
			"health_issues":       healthIssues,
			"uptime":              time.Since(serviceStats.StartTime).String(),
			"last_successful_run": serviceStats.LastSuccessfulRun.Format(time.RFC3339),
			"time_since_last_run": timeSinceLastRun.String(),
			"total_events":        serviceStats.TotalEventsForwarded,
			"total_filtered":      serviceStats.TotalEventsFiltered,
			"total_dropped":       serviceStats.TotalEventsDropped,
			"total_api_requests":  serviceStats.TotalAPIRequests,
			"failed_api_requests": serviceStats.FailedAPIRequests,
			"api_failure_rate": func() float64 {
				if serviceStats.TotalAPIRequests > 0 {
					return float64(serviceStats.FailedAPIRequests) / float64(serviceStats.TotalAPIRequests)
				}
				return 0.0
			}(),
			"retry_attempts":            serviceStats.TotalRetryAttempts,
			"successful_recoveries":     serviceStats.SuccessfulRecoveries,
			"syslog_reconnects":         serviceStats.SyslogReconnects,
			"event_cache_hits":          serviceStats.EventCacheHits,
			"event_cache_misses":        serviceStats.EventCacheMisses,
			"lookup_cache_hits":         serviceStats.LookupCacheHits,
			"lookup_cache_misses":       serviceStats.LookupCacheMisses,
			"lookup_failures":           serviceStats.LookupFailures,
			"change_detection_events":   serviceStats.ChangeDetectionEvents,
			"marker_file_updates":       serviceStats.MarkerFileUpdates,
			"compartment_errors":        serviceStats.CompartmentErrors,
			"last_error":                serviceStats.LastError,
			"last_error_time":           serviceStats.LastErrorTime.Format(time.RFC3339),
			"average_events_per_second": serviceStats.AverageEventsPerSecond,
			"compartments_monitored":    compartments.Count(),
			"event_cache": map[string]interface{}{
				"duplicates_detected": cacheStats.DuplicatesDetected,
				"cache_hits":          cacheStats.CacheHits,
				"cache_misses":        cacheStats.CacheMisses,
				"cache_size":          cacheStats.CacheSize,
			},
		}
		serviceStats.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpStatus)
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
		fmt.Fprintf(w, "oci_audit_forwarder_event_cache_hits %d\n", serviceStats.EventCacheHits)
		fmt.Fprintf(w, "oci_audit_forwarder_event_cache_misses %d\n", serviceStats.EventCacheMisses)
		fmt.Fprintf(w, "oci_audit_forwarder_lookup_cache_hits %d\n", serviceStats.LookupCacheHits)
		fmt.Fprintf(w, "oci_audit_forwarder_lookup_cache_misses %d\n", serviceStats.LookupCacheMisses)
		fmt.Fprintf(w, "oci_audit_forwarder_compartment_errors %d\n", serviceStats.CompartmentErrors)
		fmt.Fprintf(w, "oci_audit_forwarder_compartments_monitored %d\n", compartments.Count())

		// Add health status as a metric (1 = healthy, 0.5 = degraded, 0 = unhealthy)
		healthValue := 1.0
		timeSinceLastRun := time.Since(serviceStats.LastSuccessfulRun)
		if timeSinceLastRun > 2*time.Hour || serviceStats.CompartmentErrors > 5 || serviceStats.SyslogReconnects > 10 {
			healthValue = 0.5
		}
		if serviceStats.TotalAPIRequests > 0 {
			failureRate := float64(serviceStats.FailedAPIRequests) / float64(serviceStats.TotalAPIRequests)
			if failureRate > 0.5 || (!serviceStats.LastErrorTime.IsZero() && time.Since(serviceStats.LastErrorTime) < 5*time.Minute) {
				healthValue = 0.0
			}
		}
		fmt.Fprintf(w, "oci_audit_forwarder_health_status %f\n", healthValue)

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

	// Get all enabled services
	enabledServices := config.getEnabledServices()
	if len(enabledServices) == 0 {
		log.Printf("⚠️  No enabled API services configured")
		return marker, nil
	}

	var allEvents []ServiceEvent
	newMarker := marker
	newMarker.PollCount++

	// Poll each enabled service
	for _, service := range enabledServices {
		log.Printf("🔍 Polling service: %s", service.Name)

		serviceEvents, err := fetchServiceEventsWithRetry(config, service, marker, &totalRetryErrors, &recoveries)
		if err != nil {
			numErrors++
			log.Printf("❌ Error fetching events from service %s: %v", service.Name, err)
			continue // Continue with other services
		}

		allEvents = append(allEvents, serviceEvents...)
		if len(serviceEvents) > 0 {
			log.Printf("✅ Service %s: fetched %d events", service.Name, len(serviceEvents))
		}
	}

	// Update marker with current time
	newMarker.LastEventTime = time.Now()

	pollEnd := time.Now()

	if len(allEvents) > 0 {
		// Use enhanced filtering with deduplication
		filteredEvents, droppedCount, duplicateCount, eventCacheHits, eventCacheMisses := filterServiceEventsWithDeduplication(allEvents, fieldMapping.EventFiltering, fieldMapping.Statistics, config)
		totalEventsFiltered += droppedCount
		totalDuplicates += duplicateCount

		if len(filteredEvents) > 0 {
			forwarded, dropped, _, lookupStats, changeStats, err := forwardServiceEventsWithStats(
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

		// Track event cache stats separately from lookup cache stats (conditionally based on config)
		if fieldMapping.Statistics.TrackCacheMetrics {
			cacheHits += eventCacheHits
			cacheMisses += eventCacheMisses
		}
	}

	// Update region markers and save for each enabled service
	for _, service := range enabledServices {
		markerFile := service.MarkerFile
		if markerFile == "" {
			markerFile = fmt.Sprintf("oci-%s-marker.json", service.Name)
		}

		// Load existing marker to preserve region data
		existingMarker := loadTimeBasedMarker(markerFile)

		// Initialize region markers map if needed
		if existingMarker.RegionMarkers == nil {
			existingMarker.RegionMarkers = make(map[string]RegionMarker)
		}

		// Update region-specific markers based on events processed
		regions := config.getServiceRegions(service)
		for _, region := range regions {
			regionMarker := RegionMarker{
				LastEventTime: newMarker.LastEventTime,
				LastEventID:   newMarker.LastEventID,
			}

			// If we had region-specific events, update the marker for that region
			// For now, we use the global newMarker time, but in future we could
			// track per-region last event times more precisely
			existingMarker.RegionMarkers[region] = regionMarker
		}

		// Update global marker fields
		existingMarker.LastEventTime = newMarker.LastEventTime
		existingMarker.LastEventID = newMarker.LastEventID
		existingMarker.PollCount = newMarker.PollCount

		if err := saveTimeBasedMarker(markerFile, existingMarker); err != nil {
			log.Printf("⚠️  Warning: Error saving marker file for service %s: %v", service.Name, err)
		} else {
			serviceStats.Lock()
			serviceStats.MarkerFileUpdates++
			serviceStats.Unlock()

			// Log successful marker save with region info
			log.Printf("💾 Saved %s marker: %s (Poll #%d) with %d regions to %s",
				service.Name, existingMarker.LastEventTime.Format("2006-01-02 15:04:05"), existingMarker.PollCount, len(existingMarker.RegionMarkers), markerFile)
		}
	}

	var periodStart, periodEnd int64
	if len(allEvents) > 0 {
		// Find the chronologically earliest and latest events (not just first/last in array)
		var earliestTime, latestTime time.Time
		var foundFirst bool

		for _, event := range allEvents {
			if eventTime, err := time.Parse(time.RFC3339, event.EventTime); err == nil {
				if !foundFirst {
					earliestTime = eventTime
					latestTime = eventTime
					foundFirst = true
				} else {
					if eventTime.Before(earliestTime) {
						earliestTime = eventTime
					}
					if eventTime.After(latestTime) {
						latestTime = eventTime
					}
				}
			}
		}

		if foundFirst {
			periodStart = earliestTime.Unix()
			periodEnd = latestTime.Unix()
		} else {
			// Fallback if no events could be parsed
			periodStart = pollStart.Unix()
			periodEnd = pollEnd.Unix()
		}
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
		serviceStats.LastSuccessfulRun = pollEnd
		serviceStats.TotalEventsForwarded += int64(totalEventsProcessed)
		serviceStats.TotalEventsFiltered += int64(totalEventsFiltered)
		serviceStats.TotalEventsDropped += int64(totalEventsDropped)
		serviceStats.EventCacheHits += int64(cacheHits)
		serviceStats.EventCacheMisses += int64(cacheMisses)
		serviceStats.LookupFailures += int64(lookupFailures)
		serviceStats.ChangeDetectionEvents += int64(changeDetectionEvents)
		serviceStats.TotalRetryAttempts += int64(totalRetryErrors)
		serviceStats.SuccessfulRecoveries += int64(recoveries)

		// Track performance metrics conditionally based on configuration
		if fieldMapping.Statistics.TrackPerformanceMetrics {
			serviceStats.CurrentPollDuration = pollEnd.Sub(pollStart)
			serviceStats.AverageEventsPerSecond = eventsPerSecond
		}

		serviceStats.Unlock()
	}

	// Enhanced summary with event cache effectiveness details
	eventCacheEffectiveness := "N/A"
	if cacheHits+cacheMisses > 0 {
		eventCacheEffectiveness = fmt.Sprintf("%.1f%%", float64(cacheHits)/float64(cacheHits+cacheMisses)*100)
	}

	var cacheSizeInfo string
	if eventCache != nil {
		eventCache.RLock()
		cacheSizeInfo = fmt.Sprintf(", CacheSize=%d", len(eventCache.processedEvents))
		eventCache.RUnlock()
	}

	log.Printf("📊 Poll #%d [%d-%d]: Fetched=%d, Duplicates=%d (%.1f%%), Filtered=%d, Forwarded=%d, Dropped=%d | "+
		"Rate=%.2f events/sec, EventCache=%s, H/M=%d/%d%s | Errors=%d, Retries=%d, Recoveries=%d | Next=%s",
		newMarker.PollCount, periodStart, periodEnd,
		len(allEvents), totalDuplicates,
		func() float64 {
			if len(allEvents) > 0 {
				return float64(totalDuplicates) / float64(len(allEvents)) * 100
			} else {
				return 0.0
			}
		}(),
		totalEventsFiltered, totalEventsProcessed, totalEventsDropped,
		eventsPerSecond, eventCacheEffectiveness, cacheHits, cacheMisses, cacheSizeInfo,
		numErrors, totalRetryErrors, recoveries,
		newMarker.LastEventTime.Add(-time.Duration(config.PollOverlapMinutes)*time.Minute).Format("15:04:05"))
	return newMarker, nil
}

// Generic service event fetching with smart retry logic
func fetchServiceEventsWithRetry(config *Configuration, service APIService, marker TimeBasedMarker, totalRetryErrors *int, recoveries *int) ([]ServiceEvent, error) {
	var lastErr error
	var lastStatusCode int

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := calculateRetryDelay(attempt-1, lastStatusCode, config)

			if lastStatusCode == config.RetryStrategy.RateLimitHandling.StatusCode {
				log.Printf("🔄 Rate limit detected (%d), retry attempt %d/%d for service %s after exponential backoff: %v",
					lastStatusCode, attempt, config.MaxRetries, service.Name, delay)
			} else {
				log.Printf("🔄 Retry attempt %d/%d for service %s after %v",
					attempt, config.MaxRetries, service.Name, delay)
			}

			time.Sleep(delay)
		}

		events, statusCode, err := fetchServiceEventsWithStatus(config, service, marker)
		if err == nil {
			if attempt > 0 {
				*recoveries++
			}
			return events, nil
		}

		*totalRetryErrors++
		lastErr = err
		lastStatusCode = statusCode

		// Check if we should retry based on status code
		if statusCode > 0 && !shouldRetryStatusCode(statusCode, config) {
			log.Printf("❌ Non-retryable error %d for service %s: %v", statusCode, service.Name, err)
			return nil, err
		}

		log.Printf("❌ API request attempt %d failed for service %s (status %d): %v", attempt+1, service.Name, statusCode, err)
	}

	return nil, fmt.Errorf("all retry attempts failed for service %s, last error: %w", service.Name, lastErr)
}

// Check if a status code should be retried based on configuration
func shouldRetryStatusCode(statusCode int, config *Configuration) bool {
	// Check non-retryable status codes first
	for _, nonRetryable := range config.RetryStrategy.NonRetryableStatusCodes {
		if statusCode == nonRetryable {
			return false
		}
	}

	// Check retryable status codes
	for _, retryable := range config.RetryStrategy.RetryableStatusCodes {
		if statusCode == retryable {
			return true
		}
	}

	// Default: retry 5xx server errors, don't retry 4xx client errors
	return statusCode >= 500
}

// Calculate retry delay with exponential backoff and jitter
func calculateRetryDelay(attempt int, statusCode int, config *Configuration) time.Duration {
	baseDelay := time.Duration(config.RetryDelay) * time.Second

	// Check if this is a rate limit error that should use exponential backoff
	isRateLimit := statusCode == config.RetryStrategy.RateLimitHandling.StatusCode
	useExponential := config.RetryStrategy.ExponentialBackoff || (isRateLimit && config.RetryStrategy.RateLimitHandling.UseExponentialBackoff)

	var delay time.Duration
	if useExponential {
		// Exponential backoff: base * multiplier^attempt
		multiplier := config.RetryStrategy.BaseMultiplier
		if multiplier <= 0 {
			multiplier = 2 // Default multiplier
		}

		exponentialDelay := baseDelay
		for i := 0; i < attempt; i++ {
			exponentialDelay *= time.Duration(multiplier)
		}
		delay = exponentialDelay

		// Apply max delay limit
		maxDelay := time.Duration(config.RetryStrategy.MaxDelaySeconds) * time.Second
		if isRateLimit && config.RetryStrategy.RateLimitHandling.MaxBackoffSeconds > 0 {
			maxDelay = time.Duration(config.RetryStrategy.RateLimitHandling.MaxBackoffSeconds) * time.Second
		}

		if maxDelay > 0 && delay > maxDelay {
			delay = maxDelay
		}
	} else {
		// Linear backoff (original behavior)
		delay = baseDelay
	}

	// Add jitter if enabled
	if config.RetryStrategy.JitterEnabled && delay > 0 {
		jitter := time.Duration(rand.Int63n(int64(delay) / 4)) // Up to 25% jitter
		delay += jitter
	}

	return delay
}

// Fetch compartments with smart retry logic using exponential backoff
func fetchCompartmentsWithRetry(config *Configuration, compartmentID, region string) ([]OCICompartment, error) {
	var lastErr error
	var lastStatusCode int

	for attempt := 0; attempt <= config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := calculateRetryDelay(attempt-1, lastStatusCode, config)

			if lastStatusCode == config.RetryStrategy.RateLimitHandling.StatusCode {
				log.Printf("🔄 Rate limit detected (%d), retry attempt %d/%d for compartments in region %s after exponential backoff: %v",
					lastStatusCode, attempt, config.MaxRetries, region, delay)
			} else {
				log.Printf("🔄 Retry attempt %d/%d for compartments in region %s after %v",
					attempt, config.MaxRetries, region, delay)
			}

			time.Sleep(delay)
		}

		compartments, statusCode, err := fetchCompartmentsFromAPI(compartmentID, region)
		if err == nil {
			// Record successful API call
			rateLimitState.RecordSuccess()
			return compartments, nil
		}

		lastErr = err
		lastStatusCode = statusCode

		// Record rate limit hits globally for coordination with compartment refresh
		if statusCode == 429 {
			rateLimitState.RecordRateLimit()
		}

		// Check if we should retry based on status code
		if !shouldRetryStatusCode(statusCode, config) {
			log.Printf("❌ Non-retryable error %d for compartments in region %s: %v", statusCode, region, err)
			return nil, err
		}

		log.Printf("❌ Compartment API request attempt %d failed in region %s (status %d): %v", attempt+1, region, statusCode, err)
	}

	// If all retries failed and we hit rate limits, suggest configuration review
	if lastStatusCode == 429 {
		log.Printf("💡 Suggestion: Consider reducing API call frequency:")
		log.Printf("   - Increase compartment_refresh_interval (current: %d minutes)", config.CompartmentRefreshInterval)
		log.Printf("   - Increase fetch_interval (current: %d seconds)", config.FetchInterval)
		log.Printf("   - Reduce number of regions being monitored")
		log.Printf("   - Use compartment_mode='tenancy_only' to avoid recursive compartment loading")
	}

	return nil, fmt.Errorf("all retry attempts failed for compartments in region %s, last error: %w", region, lastErr)
}

// Make the actual compartment API call
func fetchCompartmentsFromAPI(compartmentID, region string) ([]OCICompartment, int, error) {
	apiURL := fmt.Sprintf("https://identity.%s.oraclecloud.com/20160918/compartments", region)
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, 0, err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("lifecycleState", "ACTIVE")
	q.Set("limit", "1000")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, 0, err
	}

	if err := ociClient.signRequest(req); err != nil {
		return nil, 0, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	statusCode := resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		// Enhanced logging for rate limit responses
		if statusCode == 429 {
			log.Printf("🚫 Oracle Rate Limit Hit - Compartments API in region %s:", region)
			log.Printf("   Status: %d", statusCode)
			log.Printf("   Response Body: %s", string(body))
			log.Printf("   🔄 Using configured exponential backoff strategy")
		}

		return nil, statusCode, fmt.Errorf("compartments request failed: %d - %s", statusCode, string(body))
	}

	var compartmentsList []OCICompartment
	if err := json.Unmarshal(body, &compartmentsList); err != nil {
		return nil, statusCode, fmt.Errorf("failed to parse compartments response: %w", err)
	}

	return compartmentsList, statusCode, nil
}

// Extract HTTP status code from error message (for backward compatibility)
func extractStatusCodeFromError(err error) int {
	if err == nil {
		return 200
	}

	errStr := err.Error()

	// Look for patterns like "failed: 429 -" or "returned status 404:"
	patterns := []string{
		"failed: ",
		"returned status ",
		"status code ",
		"HTTP ",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(errStr, pattern); idx != -1 {
			start := idx + len(pattern)
			if start < len(errStr) {
				// Extract next 3 characters and try to parse as status code
				end := start + 3
				if end > len(errStr) {
					end = len(errStr)
				}

				statusStr := ""
				for i := start; i < end; i++ {
					char := errStr[i]
					if char >= '0' && char <= '9' {
						statusStr += string(char)
					} else {
						break
					}
				}

				if len(statusStr) == 3 {
					if statusCode, err := strconv.Atoi(statusStr); err == nil {
						return statusCode
					}
				}
			}
		}
	}

	// Default to 500 for unknown errors (retryable)
	return 500
}

// Fetch events from a specific service with status code extraction
func fetchServiceEventsWithStatus(config *Configuration, service APIService, marker TimeBasedMarker) ([]ServiceEvent, int, error) {
	events, err := fetchServiceEvents(config, service, marker)
	statusCode := extractStatusCodeFromError(err)
	return events, statusCode, err
}

// Fetch events from a specific service
func fetchServiceEvents(config *Configuration, service APIService, marker TimeBasedMarker) ([]ServiceEvent, error) {
	switch service.Name {
	case "audit":
		return fetchAuditServiceEvents(config, service, marker)
	case "cloudguard":
		return fetchCloudGuardServiceEvents(config, service, marker)
	case "logging":
		return fetchVCNFlowLogServiceEvents(config, service, marker)
	default:
		return nil, fmt.Errorf("unsupported service: %s", service.Name)
	}
}

// Fetch audit events - now region-aware
func fetchAuditServiceEvents(config *Configuration, service APIService, marker TimeBasedMarker) ([]ServiceEvent, error) {
	var allServiceEvents []ServiceEvent

	// Calculate time window
	var startTime time.Time
	endTime := time.Now()

	if marker.LastEventTime.IsZero() || marker.PollCount == 0 {
		startTime = endTime.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
	} else {
		overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
		startTime = marker.LastEventTime.Add(-overlapDuration)
	}

	// Get regions to poll for this service
	regions := config.getServiceRegions(service)

	log.Printf("🔍 Fetching audit events from %d regions: Start=%s, End=%s",
		len(regions), startTime.Format("2006-01-02T15:04:05"), endTime.Format("2006-01-02T15:04:05"))

	// Poll each region
	for _, region := range regions {
		log.Printf("🌍 Polling audit events in region: %s", region)

		// Get region-specific compartments
		currentCompartments := regionCompartments.GetForRegion(region)
		if len(currentCompartments) == 0 {
			log.Printf("⚠️  No compartments available for audit service in region %s - skipping", region)
			continue
		}

		// Use region-specific marker time if available
		regionStartTime := startTime
		if marker.RegionMarkers != nil {
			if regionMarker, exists := marker.RegionMarkers[region]; exists && !regionMarker.LastEventTime.IsZero() {
				overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
				regionStartTime = regionMarker.LastEventTime.Add(-overlapDuration)
			}
		}

		// Fetch from all compartments in this region
		for _, compartment := range currentCompartments {
			events, err := fetchCompartmentAuditEventsForRegion(config, service, compartment.ID, regionStartTime, endTime, region)
			if err != nil {
				// Track compartment access errors
				serviceStats.Lock()
				serviceStats.CompartmentErrors++
				serviceStats.Unlock()

				log.Printf("❌ Failed to fetch audit events for compartment %s (%s) in region %s: %v", compartment.Name, compartment.ID, region, err)
				continue
			}

			// Convert to ServiceEvents
			for _, event := range events {
				serviceEvent := ServiceEvent{
					ServiceName: "audit",
					EventType:   event.EventType,
					EventTime:   event.EventTime,
					EventID:     event.EventID,
					RawData:     event,
				}
				allServiceEvents = append(allServiceEvents, serviceEvent)
			}
		}

		log.Printf("🔍 Region %s: collected %d audit events", region, len(allServiceEvents))
	}

	return allServiceEvents, nil
}

// Fetch VCN Flow Log events from OCI Logging service
func fetchVCNFlowLogServiceEvents(config *Configuration, service APIService, marker TimeBasedMarker) ([]ServiceEvent, error) {
	var allServiceEvents []ServiceEvent

	// Calculate time window
	var startTime time.Time
	endTime := time.Now()

	if marker.LastEventTime.IsZero() || marker.PollCount == 0 {
		startTime = endTime.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
	} else {
		overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
		startTime = marker.LastEventTime.Add(-overlapDuration)
	}

	// Get regions to poll for this service
	regions := config.getServiceRegions(service)

	log.Printf("🌊 Fetching VCN Flow Logs from %d regions: Start=%s, End=%s",
		len(regions), startTime.Format("2006-01-02T15:04:05"), endTime.Format("2006-01-02T15:04:05"))

	// Poll each region for VCN flow logs
	for _, region := range regions {
		log.Printf("🌍 Polling VCN Flow Logs in region: %s", region)

		// Use region-specific marker time if available
		regionStartTime := startTime
		if marker.RegionMarkers != nil {
			if regionMarker, exists := marker.RegionMarkers[region]; exists && !regionMarker.LastEventTime.IsZero() {
				overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
				regionStartTime = regionMarker.LastEventTime.Add(-overlapDuration)
			}
		}

		// Fetch VCN flow logs for this region
		flowLogs, err := fetchVCNFlowLogsForRegion(config, service, regionStartTime, endTime, region)
		if err != nil {
			serviceStats.Lock()
			serviceStats.CompartmentErrors++
			serviceStats.Unlock()
			log.Printf("❌ Failed to fetch VCN flow logs for region %s: %v", region, err)
			continue
		}

		// Convert VCN flow logs to ServiceEvents
		for _, flowLog := range flowLogs {
			serviceEvent := ServiceEvent{
				ServiceName: "logging",
				EventType:   "VCNFlowLog",
				EventTime:   flowLog.Time,
				EventID:     flowLog.ID,
				RawData:     flowLog,
			}
			allServiceEvents = append(allServiceEvents, serviceEvent)
		}

		log.Printf("🌊 Region %s: collected %d VCN flow log entries", region, len(flowLogs))
	}

	return allServiceEvents, nil
}

// Fetch CloudGuard events - now region-aware with full endpoint support
func fetchCloudGuardServiceEvents(config *Configuration, service APIService, marker TimeBasedMarker) ([]ServiceEvent, error) {
	var allServiceEvents []ServiceEvent

	// Calculate time window
	var startTime time.Time
	endTime := time.Now()

	if marker.LastEventTime.IsZero() || marker.PollCount == 0 {
		startTime = endTime.Add(-time.Duration(config.InitialLookbackHours) * time.Hour)
	} else {
		overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
		startTime = marker.LastEventTime.Add(-overlapDuration)
	}

	// Get regions to poll for this service
	regions := config.getServiceRegions(service)

	log.Printf("🔍 Fetching CloudGuard data from %d regions: Start=%s, End=%s",
		len(regions), startTime.Format("2006-01-02T15:04:05"), endTime.Format("2006-01-02T15:04:05"))

	// Poll each region for all CloudGuard endpoints
	for _, region := range regions {
		log.Printf("🌍 Polling CloudGuard endpoints in region: %s", region)

		// Get region-specific compartments
		currentCompartments := regionCompartments.GetForRegion(region)
		if len(currentCompartments) == 0 {
			log.Printf("⚠️  No compartments available for CloudGuard service in region %s - skipping", region)
			continue
		}

		// Use region-specific marker time if available
		regionStartTime := startTime
		if marker.RegionMarkers != nil {
			if regionMarker, exists := marker.RegionMarkers[region]; exists && !regionMarker.LastEventTime.IsZero() {
				overlapDuration := time.Duration(config.PollOverlapMinutes) * time.Minute
				regionStartTime = regionMarker.LastEventTime.Add(-overlapDuration)
			}
		}

		var regionTotalEvents int

		// Fetch from all compartments in this region
		for _, compartment := range currentCompartments {
			// 1. Fetch CloudGuard Problems (security incidents)
			problems, err := fetchCompartmentCloudGuardProblemsForRegion(config, service, compartment.ID, regionStartTime, endTime, region)
			if err != nil {
				serviceStats.Lock()
				serviceStats.CompartmentErrors++
				serviceStats.Unlock()
				log.Printf("❌ Failed to fetch CloudGuard problems for compartment %s (%s) in region %s: %v", compartment.Name, compartment.ID, region, err)
			} else {
				// Convert problems to ServiceEvents
				for _, problem := range problems {
					serviceEvent := ServiceEvent{
						ServiceName: "cloudguard",
						EventType:   "CloudGuardProblem." + problem.ProblemType,
						EventTime:   problem.TimeCreated,
						EventID:     problem.ID,
						RawData:     problem,
					}
					allServiceEvents = append(allServiceEvents, serviceEvent)
				}
				regionTotalEvents += len(problems)
			}

			// 2. Fetch CloudGuard Detectors (security rules/policies)
			detectors, err := fetchCompartmentCloudGuardDetectorsForRegion(config, service, compartment.ID, regionStartTime, endTime, region)
			if err != nil {
				serviceStats.Lock()
				serviceStats.CompartmentErrors++
				serviceStats.Unlock()
				log.Printf("❌ Failed to fetch CloudGuard detectors for compartment %s (%s) in region %s: %v", compartment.Name, compartment.ID, region, err)
			} else {
				// Convert detectors to ServiceEvents
				for _, detector := range detectors {
					// Use TimeUpdated for recent changes, fallback to TimeCreated
					eventTime := detector.TimeUpdated
					if eventTime == "" {
						eventTime = detector.TimeCreated
					}

					serviceEvent := ServiceEvent{
						ServiceName: "cloudguard",
						EventType:   "CloudGuardDetector." + detector.DetectorType,
						EventTime:   eventTime,
						EventID:     detector.ID,
						RawData:     detector,
					}
					allServiceEvents = append(allServiceEvents, serviceEvent)
				}
				regionTotalEvents += len(detectors)
			}

			// 3. Fetch CloudGuard Targets (monitored resources)
			targets, err := fetchCompartmentCloudGuardTargetsForRegion(config, service, compartment.ID, regionStartTime, endTime, region)
			if err != nil {
				serviceStats.Lock()
				serviceStats.CompartmentErrors++
				serviceStats.Unlock()
				log.Printf("❌ Failed to fetch CloudGuard targets for compartment %s (%s) in region %s: %v", compartment.Name, compartment.ID, region, err)
			} else {
				// Convert targets to ServiceEvents
				for _, target := range targets {
					// Use TimeUpdated for recent changes, fallback to TimeCreated
					eventTime := target.TimeUpdated
					if eventTime == "" {
						eventTime = target.TimeCreated
					}

					serviceEvent := ServiceEvent{
						ServiceName: "cloudguard",
						EventType:   "CloudGuardTarget." + target.TargetResourceType,
						EventTime:   eventTime,
						EventID:     target.ID,
						RawData:     target,
					}
					allServiceEvents = append(allServiceEvents, serviceEvent)
				}
				regionTotalEvents += len(targets)
			}

			// Log compartment summary if we found events
			if regionTotalEvents > 0 {
				log.Printf("🔍 Compartment %s in region %s: %d problems, %d detectors, %d targets",
					compartment.Name, region, len(problems), len(detectors), len(targets))
			}
		}

		log.Printf("🔍 Region %s: collected %d total CloudGuard events", region, regionTotalEvents)
	}

	return allServiceEvents, nil
}

// Fetch audit events for a specific compartment in a specific region
func fetchCompartmentAuditEventsForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, region string) ([]OCIAuditEvent, error) {
	var allEvents []OCIAuditEvent
	var nextPage string

	for {
		events, nextPageToken, err := fetchCompartmentAuditEventsPageForRegion(config, service, compartmentID, startTime, endTime, nextPage, region)
		if err != nil {
			return nil, err
		}

		allEvents = append(allEvents, events...)

		if nextPageToken == "" {
			break
		}
		nextPage = nextPageToken

		if len(allEvents) > config.MaxEventsPerPoll {
			log.Printf("⚠️  Warning: Hit max events limit (%d) for audit compartment %s in region %s", config.MaxEventsPerPoll, compartmentID, region)
			break
		}
	}

	return allEvents, nil
}

// Fetch audit events page for a specific region
func fetchCompartmentAuditEventsPageForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, pageToken, region string) ([]OCIAuditEvent, string, error) {
	apiURL := config.buildServiceURLForRegion(service, "/auditEvents", region)
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

	nextPage := resp.Header.Get("opc-next-page")
	return events, nextPage, nil
}

// Fetch CloudGuard problems for a specific compartment in a specific region
func fetchCompartmentCloudGuardProblemsForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, region string) ([]CloudGuardProblem, error) {
	var allProblems []CloudGuardProblem
	var nextPage string

	for {
		problems, nextPageToken, err := fetchCompartmentCloudGuardProblemsPageForRegion(config, service, compartmentID, startTime, endTime, nextPage, region)
		if err != nil {
			return nil, err
		}

		allProblems = append(allProblems, problems...)

		if nextPageToken == "" {
			break
		}
		nextPage = nextPageToken

		if len(allProblems) > config.MaxEventsPerPoll {
			log.Printf("⚠️  Warning: Hit max events limit (%d) for CloudGuard compartment %s in region %s", config.MaxEventsPerPoll, compartmentID, region)
			break
		}
	}

	return allProblems, nil
}

// Fetch CloudGuard problems page for a specific region
func fetchCompartmentCloudGuardProblemsPageForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, pageToken, region string) ([]CloudGuardProblem, string, error) {
	apiURL := config.buildServiceURLForRegion(service, "/problems", region)
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, "", err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("timeCreatedGreaterThanOrEqualTo", startTime.Format(time.RFC3339))
	q.Set("timeCreatedLessThan", endTime.Format(time.RFC3339))
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
		return nil, "", fmt.Errorf("CloudGuard problems request failed: %d - %s", resp.StatusCode, string(body))
	}

	// CloudGuard API returns problems in a "items" array
	var response struct {
		Items []CloudGuardProblem `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", fmt.Errorf("failed to parse CloudGuard problems response: %w", err)
	}

	nextPage := resp.Header.Get("opc-next-page")
	return response.Items, nextPage, nil
}

// Fetch CloudGuard detectors for a specific compartment in a specific region
func fetchCompartmentCloudGuardDetectorsForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, region string) ([]CloudGuardDetector, error) {
	var allDetectors []CloudGuardDetector
	var nextPage string

	for {
		detectors, nextPageToken, err := fetchCompartmentCloudGuardDetectorsPageForRegion(config, service, compartmentID, startTime, endTime, nextPage, region)
		if err != nil {
			return nil, err
		}

		allDetectors = append(allDetectors, detectors...)

		if nextPageToken == "" {
			break
		}
		nextPage = nextPageToken

		if len(allDetectors) > config.MaxEventsPerPoll {
			log.Printf("⚠️  Warning: Hit max events limit (%d) for CloudGuard detectors compartment %s in region %s", config.MaxEventsPerPoll, compartmentID, region)
			break
		}
	}

	return allDetectors, nil
}

// Fetch CloudGuard detectors page for a specific region
func fetchCompartmentCloudGuardDetectorsPageForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, pageToken, region string) ([]CloudGuardDetector, string, error) {
	apiURL := config.buildServiceURLForRegion(service, "/detectors", region)
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, "", err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("timeCreatedGreaterThanOrEqualTo", startTime.Format(time.RFC3339))
	q.Set("timeCreatedLessThan", endTime.Format(time.RFC3339))
	q.Set("limit", "1000")
	q.Set("lifecycleState", "ACTIVE") // Only get active detectors

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
		return nil, "", fmt.Errorf("CloudGuard detectors request failed: %d - %s", resp.StatusCode, string(body))
	}

	// CloudGuard API returns detectors in a "items" array
	var response struct {
		Items []CloudGuardDetector `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", fmt.Errorf("failed to parse CloudGuard detectors response: %w", err)
	}

	nextPage := resp.Header.Get("opc-next-page")
	return response.Items, nextPage, nil
}

// Fetch CloudGuard targets for a specific compartment in a specific region
func fetchCompartmentCloudGuardTargetsForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, region string) ([]CloudGuardTarget, error) {
	var allTargets []CloudGuardTarget
	var nextPage string

	for {
		targets, nextPageToken, err := fetchCompartmentCloudGuardTargetsPageForRegion(config, service, compartmentID, startTime, endTime, nextPage, region)
		if err != nil {
			return nil, err
		}

		allTargets = append(allTargets, targets...)

		if nextPageToken == "" {
			break
		}
		nextPage = nextPageToken

		if len(allTargets) > config.MaxEventsPerPoll {
			log.Printf("⚠️  Warning: Hit max events limit (%d) for CloudGuard targets compartment %s in region %s", config.MaxEventsPerPoll, compartmentID, region)
			break
		}
	}

	return allTargets, nil
}

// Fetch CloudGuard targets page for a specific region
func fetchCompartmentCloudGuardTargetsPageForRegion(config *Configuration, service APIService, compartmentID string, startTime, endTime time.Time, pageToken, region string) ([]CloudGuardTarget, string, error) {
	apiURL := config.buildServiceURLForRegion(service, "/targets", region)
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, "", err
	}

	q := u.Query()
	q.Set("compartmentId", compartmentID)
	q.Set("timeCreatedGreaterThanOrEqualTo", startTime.Format(time.RFC3339))
	q.Set("timeCreatedLessThan", endTime.Format(time.RFC3339))
	q.Set("limit", "1000")
	q.Set("lifecycleState", "ACTIVE") // Only get active targets

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
		return nil, "", fmt.Errorf("CloudGuard targets request failed: %d - %s", resp.StatusCode, string(body))
	}

	// CloudGuard API returns targets in a "items" array
	var response struct {
		Items []CloudGuardTarget `json:"items"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", fmt.Errorf("failed to parse CloudGuard targets response: %w", err)
	}

	nextPage := resp.Header.Get("opc-next-page")
	return response.Items, nextPage, nil
}

// Fetch VCN Flow Logs for a specific region using OCI Logging service
func fetchVCNFlowLogsForRegion(config *Configuration, service APIService, startTime, endTime time.Time, region string) ([]VCNFlowLog, error) {
	// First, discover what log groups are available
	logGroups, err := discoverLogGroups(config, service, region)
	if err != nil {
		log.Printf("⚠️  Could not discover log groups: %v", err)
		// Continue with generic search as fallback
	} else {
		log.Printf("🔍 Discovered %d log groups in region %s:", len(logGroups), region)
		for _, group := range logGroups {
			log.Printf("  - %s (ID: %s)", group.DisplayName, group.ID)
		}
	}

	// Try to find logs within the discovered log groups
	availableLogs, err := discoverLogsInGroups(config, service, region, logGroups)
	if err != nil {
		log.Printf("⚠️  Could not discover logs: %v", err)
	} else {
		log.Printf("🔍 Discovered %d logs across all groups:", len(availableLogs))
		for _, logInfo := range availableLogs {
			log.Printf("  - %s (Group: %s, Type: %s)", logInfo.DisplayName, logInfo.LogGroupName, logInfo.LogType)
		}
	}

	// Now do a broad search to see what log entries are actually available
	return searchAvailableLogs(config, service, startTime, endTime, region, availableLogs)
}

// Discover available log groups in a region
func discoverLogGroups(config *Configuration, service APIService, region string) ([]OCILogGroup, error) {
	// Build the API URL for listing log groups
	apiURL := config.buildServiceURLForRegion(service, "/logGroups", region)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if err := ociClient.signRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list log groups request failed: %d - %s", resp.StatusCode, string(body))
	}

	var logGroups []OCILogGroup
	if err := json.Unmarshal(body, &logGroups); err != nil {
		return nil, fmt.Errorf("failed to parse log groups response: %w", err)
	}

	return logGroups, nil
}

// Discover logs within log groups
func discoverLogsInGroups(config *Configuration, service APIService, region string, logGroups []OCILogGroup) ([]OCILogInfo, error) {
	var allLogs []OCILogInfo

	for _, group := range logGroups {
		// Build the API URL for listing logs in this group
		apiURL := config.buildServiceURLForRegion(service, fmt.Sprintf("/logGroups/%s/logs", group.ID), region)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			continue // Skip this group
		}

		if err := ociClient.signRequest(req); err != nil {
			continue // Skip this group
		}

		resp, err := ociClient.httpClient.Do(req)
		if err != nil {
			continue // Skip this group
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("⚠️  Could not list logs in group %s: %d - %s", group.DisplayName, resp.StatusCode, string(body))
			continue // Skip this group
		}

		var groupLogs []OCILogInfo
		if err := json.Unmarshal(body, &groupLogs); err != nil {
			continue // Skip this group
		}

		// Add group information to each log
		for i := range groupLogs {
			groupLogs[i].LogGroupName = group.DisplayName
			groupLogs[i].LogGroupId = group.ID
		}

		allLogs = append(allLogs, groupLogs...)
	}

	return allLogs, nil
}

// Search for available logs with targeted or broad queries
func searchAvailableLogs(config *Configuration, service APIService, startTime, endTime time.Time, region string, availableLogs []OCILogInfo) ([]VCNFlowLog, error) {
	var searchQueries []string

	// If we discovered specific logs, create targeted queries
	if len(availableLogs) > 0 {
		vcnFlowLogsFound := false
		for _, logInfo := range availableLogs {
			// Look for VCN Flow Logs specifically
			if strings.Contains(strings.ToLower(logInfo.DisplayName), "flow") ||
				strings.Contains(strings.ToLower(logInfo.LogType), "flow") ||
				logInfo.Source.SourceType == "OCISERVICE" {

				searchQueries = append(searchQueries, fmt.Sprintf("search \"%s\" | head 50", logInfo.DisplayName))
				vcnFlowLogsFound = true
			}
		}

		// If we found potential VCN flow logs, also add a broader VCN search
		if vcnFlowLogsFound {
			searchQueries = append(searchQueries, "search \"*/vcnflowlog/*\" | head 50")
		}
	}

	// Fallback to broad searches if no specific logs found
	if len(searchQueries) == 0 {
		searchQueries = []string{
			"search \"*/vcnflowlog/*\" | head 50",
			"search \"*flow*\" | head 50",
			"search \"*\" | head 20", // Most general fallback
		}
	}

	log.Printf("🔍 Trying %d search queries for VCN Flow Logs", len(searchQueries))

	// Try each search query until we get results
	for i, query := range searchQueries {
		log.Printf("🔍 Search attempt %d: %s", i+1, query)

		flowLogs, err := executeLogSearch(config, service, startTime, endTime, region, query)
		if err != nil {
			log.Printf("⚠️  Search attempt %d failed: %v", i+1, err)
			continue // Try next query
		}

		if len(flowLogs) > 0 {
			log.Printf("✅ Found %d VCN flow log entries with query: %s", len(flowLogs), query)
			return flowLogs, nil
		}

		log.Printf("ℹ️  Search attempt %d returned no results", i+1)
	}

	log.Printf("⚠️  No VCN flow logs found with any search strategy")
	return []VCNFlowLog{}, nil
}

// Execute a specific log search query
func executeLogSearch(config *Configuration, service APIService, startTime, endTime time.Time, region, searchQuery string) ([]VCNFlowLog, error) {
	searchRequest := map[string]interface{}{
		"timeStart":     startTime.Format(time.RFC3339),
		"timeEnd":       endTime.Format(time.RFC3339),
		"searchQuery":   searchQuery,
		"isReturnField": true,
	}

	requestBody, err := json.Marshal(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search request: %w", err)
	}

	apiURL := config.buildServiceURLForRegion(service, "/logs/actions/searchLogs", region)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(string(requestBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	if err := ociClient.signRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	resp, err := ociClient.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log search failed: %d - %s", resp.StatusCode, string(body))
	}

	// Try to parse as VCN flow logs response
	var searchResponse struct {
		Data struct {
			Results []map[string]interface{} `json:"results"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &searchResponse); err != nil {
		// If parsing fails, log the structure for debugging
		log.Printf("🔍 Response structure (first 500 chars): %.500s", string(body))
		return nil, fmt.Errorf("failed to parse log search response: %w", err)
	}

	var flowLogs []VCNFlowLog
	for _, result := range searchResponse.Data.Results {
		// Try to convert each result to a VCN Flow Log
		if flowLog := convertToVCNFlowLog(result); flowLog != nil {
			flowLogs = append(flowLogs, *flowLog)
		}
	}

	return flowLogs, nil
}

// Convert a generic log result to VCN Flow Log structure
func convertToVCNFlowLog(logResult map[string]interface{}) *VCNFlowLog {
	// This is a best-effort conversion - VCN flow logs may have various formats
	flowLog := &VCNFlowLog{}

	// Map basic fields
	if id, ok := logResult["id"].(string); ok {
		flowLog.ID = id
	}
	if timeStr, ok := logResult["time"].(string); ok {
		flowLog.Time = timeStr
	}
	if datetime, ok := logResult["datetime"].(string); ok {
		flowLog.Datetime = datetime
	}
	if source, ok := logResult["source"].(string); ok {
		flowLog.Source = source
	}
	if logType, ok := logResult["type"].(string); ok {
		flowLog.Type = logType
	}
	if subject, ok := logResult["subject"].(string); ok {
		flowLog.Subject = subject
	}
	if tenancyID, ok := logResult["oracle.tenancyId"].(string); ok {
		flowLog.TenancyID = tenancyID
	}
	if compartmentID, ok := logResult["oracle.compartmentId"].(string); ok {
		flowLog.CompartmentID = compartmentID
	}

	// Try to extract log content - this varies by log format
	if logContent, ok := logResult["logContent"]; ok {
		if contentMap, ok := logContent.(map[string]interface{}); ok {
			flowLog.LogContent = convertToVCNFlowLogContent(contentMap)
		}
	}

	// Store raw data for debugging
	flowLog.Data = logResult

	// Only return if we have minimum required fields
	if flowLog.ID != "" || flowLog.Time != "" {
		return flowLog
	}

	return nil
}

// Convert log content map to VCN Flow Log Content structure
func convertToVCNFlowLogContent(contentMap map[string]interface{}) VCNFlowLogContent {
	content := VCNFlowLogContent{}

	if version, ok := contentMap["version"].(float64); ok {
		content.Version = int(version)
	}
	if account, ok := contentMap["account"].(string); ok {
		content.Account = account
	}
	if interfaceID, ok := contentMap["interfaceid"].(string); ok {
		content.InterfaceID = interfaceID
	}
	if srcAddr, ok := contentMap["srcaddr"].(string); ok {
		content.SourceAddr = srcAddr
	}
	if dstAddr, ok := contentMap["dstaddr"].(string); ok {
		content.DestAddr = dstAddr
	}
	if srcPort, ok := contentMap["srcport"].(float64); ok {
		content.SourcePort = int(srcPort)
	}
	if dstPort, ok := contentMap["dstport"].(float64); ok {
		content.DestPort = int(dstPort)
	}
	if protocol, ok := contentMap["protocol"].(float64); ok {
		content.Protocol = int(protocol)
	}
	if packets, ok := contentMap["packets"].(float64); ok {
		content.Packets = int(packets)
	}
	if bytes, ok := contentMap["bytes"].(float64); ok {
		content.Bytes = int(bytes)
	}
	if windowStart, ok := contentMap["windowstart"].(float64); ok {
		content.WindowStart = int64(windowStart)
	}
	if windowEnd, ok := contentMap["windowend"].(float64); ok {
		content.WindowEnd = int64(windowEnd)
	}
	if action, ok := contentMap["action"].(string); ok {
		content.Action = action
	}
	if flowState, ok := contentMap["flowstate"].(string); ok {
		content.FlowState = flowState
	}
	if vnicID, ok := contentMap["vnicid"].(string); ok {
		content.VNICID = vnicID
	}
	if subnetID, ok := contentMap["subnetid"].(string); ok {
		content.SubnetID = subnetID
	}
	if vcnID, ok := contentMap["vcnid"].(string); ok {
		content.VCNID = vcnID
	}
	if compartmentID, ok := contentMap["compartmentid"].(string); ok {
		content.CompartmentID = compartmentID
	}

	return content
}

// Helper function to determine flow direction based on IP addresses
func determineFlowDirection(flowContent VCNFlowLogContent) string {
	srcAddr := flowContent.SourceAddr
	dstAddr := flowContent.DestAddr

	// Check if source is private RFC 1918 address
	srcPrivate := isPrivateIP(srcAddr)
	dstPrivate := isPrivateIP(dstAddr)

	if srcPrivate && !dstPrivate {
		return "outbound"
	} else if !srcPrivate && dstPrivate {
		return "inbound"
	} else if srcPrivate && dstPrivate {
		return "internal"
	} else {
		return "external"
	}
}

// Check if IP address is in private RFC 1918 ranges
func isPrivateIP(ipStr string) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, rangeStr := range privateRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Convert protocol number to protocol name
func getProtocolName(protocol int) string {
	protocolMap := map[int]string{
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		47:  "GRE",
		50:  "ESP",
		51:  "AH",
		58:  "ICMPv6",
		132: "SCTP",
	}

	if name, exists := protocolMap[protocol]; exists {
		return name
	}
	return fmt.Sprintf("Protocol-%d", protocol)
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
		// Check auth type for service account patterns
		if authType, exists := identity["authType"].(string); exists {
			// OCI service account auth types
			if authType == "natv" || authType == "InstancePrincipal" || authType == "ResourcePrincipal" {
				return true
			}
		}

		// Check principal type for service accounts
		if principalType, exists := identity["type"].(string); exists {
			principalTypeLower := strings.ToLower(principalType)
			if principalTypeLower == "instance" || principalTypeLower == "resource" ||
				strings.Contains(principalTypeLower, "service") {
				return true
			}
		}

		// Check principal name patterns for service accounts
		if principalName, exists := identity["principalName"].(string); exists {
			principalNameLower := strings.ToLower(principalName)
			// Service accounts often have specific naming patterns
			servicePatterns := []string{
				"instanceprincipal",
				"service_account",
				"system_user",
				"automation",
				"robot",
				"service-",
				"svc-",
				"system-",
				"auto-",
			}

			for _, pattern := range servicePatterns {
				if strings.Contains(principalNameLower, pattern) {
					return true
				}
			}
		}

		// Check if principal ID follows service account patterns (typically have specific OCID formats)
		if principalId, exists := identity["principalId"].(string); exists {
			// Instance principals have specific OCID format: ocid1.instance.oc1.*
			if strings.Contains(principalId, "ocid1.instance.") ||
				strings.Contains(principalId, "ocid1.dynamicgroup.") ||
				strings.Contains(principalId, "ocid1.fnfunc.") {
				return true
			}
		}
	}

	// Check event source for service-related activity
	sourceLower := strings.ToLower(event.Source)
	serviceSourcePatterns := []string{
		"core", "identity", "database", "objectstorage",
		"loadbalancer", "dns", "email", "functions",
		"streaming", "apigateway", "ons", "monitoring",
		"autoscaling", "resourcemanager", "datacatalog",
		"integration", "analytics", "blockchain", "mysql",
	}

	for _, pattern := range serviceSourcePatterns {
		if strings.Contains(sourceLower, pattern) {
			// Additional check to avoid false positives - look for admin/user activity
			if strings.Contains(sourceLower, "console") || strings.Contains(sourceLower, "cli") {
				return false
			}
			return true
		}
	}

	return false
}

// Forward service events with stats
func forwardServiceEventsWithStats(events []ServiceEvent, config *Configuration,
	fieldMapping FieldMapping, syslogWriter *SyslogWriter) (int, int, CacheStats, LookupStats, ChangeStats, error) {

	var forwarded, dropped int
	var cacheStats CacheStats
	var lookupStats LookupStats
	var changeStats ChangeStats

	for _, event := range events {
		eventKey := getServiceEventDeduplicationKey(event)

		enrichedEvent := enrichServiceEvent(event)
		cacheStats.Hits++     // Placeholder for now
		lookupStats.Success++ // Placeholder for now

		cefMessage := formatServiceEventAsCEF(enrichedEvent, fieldMapping)
		syslogMessage := formatSyslogMessage("oci-multi-forwarder", cefMessage)

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
				log.Printf("❌ Failed to forward %s event Key=%s after reconnect: %v", event.ServiceName, eventKey, err)
				continue
			}
		}

		// Mark as processed AFTER successful forwarding
		if eventCache != nil {
			eventCache.MarkProcessed(eventKey)
		}

		forwarded++
	}

	// Add summary logging for forwarding results with statistics configuration
	if forwarded > 0 {
		// Track events for periodic logging
		serviceStats.Lock()
		serviceStats.EventsSinceLastLog += int64(forwarded)

		// Check if we should do periodic detailed logging based on statistics config
		shouldLogPeriodic := false
		if fieldMapping.Statistics.EnableDetailedLogging {
			if fieldMapping.Statistics.LogIntervalEvents > 0 && serviceStats.EventsSinceLastLog >= int64(fieldMapping.Statistics.LogIntervalEvents) {
				shouldLogPeriodic = true
				serviceStats.EventsSinceLastLog = 0
				serviceStats.LastPeriodicLog = time.Now()
			}
		}
		serviceStats.Unlock()

		if shouldLogPeriodic {
			log.Printf("📊 DETAILED STATS: Forwarded %d events (%d dropped) from %d total events | Cache: %d/%d | Lookups: %d/%d",
				forwarded, dropped, len(events), cacheStats.Hits, cacheStats.Misses, lookupStats.Success, lookupStats.Failures)
		} else {
			log.Printf("📤 Forwarded %d events (%d dropped) from %d total events", forwarded, dropped, len(events))
		}
	}

	return forwarded, dropped, cacheStats, lookupStats, changeStats, nil
}

// Enrich service event for forwarding
func enrichServiceEvent(event ServiceEvent) map[string]interface{} {
	enriched := map[string]interface{}{
		"serviceName": event.ServiceName,
		"eventKey":    getServiceEventDeduplicationKey(event),
		"eventType":   event.EventType,
		"eventId":     event.EventID,
		"eventTime":   event.EventTime,
	}

	// Add service-specific enrichment
	switch event.ServiceName {
	case "audit":
		if auditEvent, ok := event.RawData.(OCIAuditEvent); ok {
			enriched["source"] = auditEvent.Source
			enriched["cloudEventsVersion"] = auditEvent.CloudEventsVersion
			enriched["contentType"] = auditEvent.ContentType

			if auditEvent.Data != nil {
				for k, v := range auditEvent.Data {
					enriched[k] = v
				}
			}
		}
	case "cloudguard":
		if problem, ok := event.RawData.(CloudGuardProblem); ok {
			// Core CloudGuard Problem fields
			enriched["problemType"] = problem.ProblemType
			enriched["riskLevel"] = problem.RiskLevel
			enriched["status"] = problem.Status
			enriched["compartmentId"] = problem.CompartmentId
			enriched["resourceName"] = problem.ResourceName
			enriched["resourceId"] = problem.ResourceId
			enriched["targetId"] = problem.TargetId
			enriched["detectorId"] = problem.DetectorId
			enriched["description"] = problem.Description
			enriched["timeCreated"] = problem.TimeCreated
			enriched["timeUpdated"] = problem.TimeUpdated

			// Add labels as a joined string
			if len(problem.Labels) > 0 {
				enriched["labels"] = strings.Join(problem.Labels, ",")
			}

			// Add details as individual fields with "details." prefix to match nested mapping
			if problem.Details != nil {
				enriched["details"] = make(map[string]interface{})
				for k, v := range problem.Details {
					enriched["details"].(map[string]interface{})[k] = v
					// Also add as top-level field for easier CEF mapping
					enriched[fmt.Sprintf("detail_%s", k)] = v
				}
			}

			// Add computed fields for CEF severity mapping
			switch strings.ToUpper(problem.RiskLevel) {
			case "CRITICAL":
				enriched["severityLevel"] = 10
			case "HIGH":
				enriched["severityLevel"] = 8
			case "MEDIUM":
				enriched["severityLevel"] = 6
			case "LOW":
				enriched["severityLevel"] = 4
			default:
				enriched["severityLevel"] = 5
			}
		} else if detector, ok := event.RawData.(CloudGuardDetector); ok {
			// Core CloudGuard Detector fields
			enriched["detectorId"] = detector.ID
			enriched["displayName"] = detector.DisplayName
			enriched["description"] = detector.Description
			enriched["riskLevel"] = detector.RiskLevel
			enriched["serviceType"] = detector.ServiceType
			enriched["detectorType"] = detector.DetectorType
			enriched["lifecycleState"] = detector.LifecycleState
			enriched["timeCreated"] = detector.TimeCreated
			enriched["timeUpdated"] = detector.TimeUpdated
			enriched["compartmentId"] = detector.CompartmentId
			enriched["isEnabled"] = detector.IsEnabled
			enriched["condition"] = detector.Condition

			// Add labels as a joined string
			if len(detector.Labels) > 0 {
				enriched["labels"] = strings.Join(detector.Labels, ",")
			}

			// Add detector rules count
			enriched["detectorRulesCount"] = len(detector.DetectorRules)

			// Add computed fields for CEF severity mapping based on risk level
			switch strings.ToUpper(detector.RiskLevel) {
			case "CRITICAL":
				enriched["severityLevel"] = 10
			case "HIGH":
				enriched["severityLevel"] = 8
			case "MEDIUM":
				enriched["severityLevel"] = 6
			case "LOW":
				enriched["severityLevel"] = 4
			default:
				enriched["severityLevel"] = 5
			}
		} else if target, ok := event.RawData.(CloudGuardTarget); ok {
			// Core CloudGuard Target fields
			enriched["targetId"] = target.ID
			enriched["displayName"] = target.DisplayName
			enriched["description"] = target.Description
			enriched["compartmentId"] = target.CompartmentId
			enriched["targetResourceType"] = target.TargetResourceType
			enriched["targetResourceId"] = target.TargetResourceId
			enriched["recipeCount"] = target.RecipeCount
			enriched["lifecycleState"] = target.LifecycleState
			enriched["lifecycleDetails"] = target.LifeCycleDetails
			enriched["timeCreated"] = target.TimeCreated
			enriched["timeUpdated"] = target.TimeUpdated

			// Add inherited compartments as comma-separated string
			if len(target.InheritedByCompartments) > 0 {
				enriched["inheritedByCompartments"] = strings.Join(target.InheritedByCompartments, ",")
			}

			// Add recipe counts
			enriched["detectorRecipesCount"] = len(target.TargetDetectorRecipes)
			enriched["responderRecipesCount"] = len(target.TargetResponderRecipes)

			// Targets are configuration items, so lower severity by default
			enriched["severityLevel"] = 3
		}
	case "logging":
		if vcnFlowLog, ok := event.RawData.(VCNFlowLog); ok {
			// Core VCN Flow Log fields
			enriched["sourceAddr"] = vcnFlowLog.LogContent.SourceAddr
			enriched["destAddr"] = vcnFlowLog.LogContent.DestAddr
			enriched["sourcePort"] = vcnFlowLog.LogContent.SourcePort
			enriched["destPort"] = vcnFlowLog.LogContent.DestPort
			enriched["protocol"] = vcnFlowLog.LogContent.Protocol
			enriched["packets"] = vcnFlowLog.LogContent.Packets
			enriched["bytes"] = vcnFlowLog.LogContent.Bytes
			enriched["action"] = vcnFlowLog.LogContent.Action
			enriched["flowState"] = vcnFlowLog.LogContent.FlowState
			enriched["vnicId"] = vcnFlowLog.LogContent.VNICID
			enriched["subnetId"] = vcnFlowLog.LogContent.SubnetID
			enriched["vcnId"] = vcnFlowLog.LogContent.VCNID
			enriched["compartmentId"] = vcnFlowLog.LogContent.CompartmentID
			enriched["interfaceId"] = vcnFlowLog.LogContent.InterfaceID
			enriched["windowStart"] = vcnFlowLog.LogContent.WindowStart
			enriched["windowEnd"] = vcnFlowLog.LogContent.WindowEnd
			enriched["version"] = vcnFlowLog.LogContent.Version
			enriched["account"] = vcnFlowLog.LogContent.Account

			// Add Oracle-specific fields
			enriched["tenancyId"] = vcnFlowLog.TenancyID
			enriched["source"] = vcnFlowLog.Source
			enriched["type"] = vcnFlowLog.Type
			enriched["subject"] = vcnFlowLog.Subject

			// Add computed fields for better analysis
			enriched["direction"] = determineFlowDirection(vcnFlowLog.LogContent)
			enriched["protocolName"] = getProtocolName(vcnFlowLog.LogContent.Protocol)

			// Flow logs are typically low severity unless denied
			if vcnFlowLog.LogContent.Action == "REJECT" || vcnFlowLog.LogContent.Action == "DROP" {
				enriched["severityLevel"] = 6 // Medium - blocked traffic
			} else {
				enriched["severityLevel"] = 3 // Low - allowed traffic
			}
		}
	}

	// Add event type name if available
	if eventName, exists := eventTypeMap[event.EventType]; exists {
		enriched["eventTypeName"] = eventName
	}

	return enriched
}

// Format service event as CEF
func formatServiceEventAsCEF(event map[string]interface{}, fieldMapping FieldMapping) string {
	serviceName := fmt.Sprintf("%v", event["serviceName"])
	eventType := fmt.Sprintf("%v", event["eventType"])
	eventName := fmt.Sprintf("%s Event", strings.Title(serviceName))

	if name, exists := eventTypeMap[eventType]; exists {
		eventName = name
	}

	var severity int
	if serviceName == "cloudguard" {
		// CloudGuard severity based on risk level
		if riskLevel, exists := event["riskLevel"].(string); exists {
			switch strings.ToUpper(riskLevel) {
			case "CRITICAL":
				severity = 10
			case "HIGH":
				severity = 8
			case "MEDIUM":
				severity = 6
			case "LOW":
				severity = 4
			default:
				severity = 5
			}
		} else {
			severity = 7 // Default for CloudGuard
		}
	} else {
		severity = mapEventTypeToSeverity(eventType)
	}

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

	// Get service-specific field mappings
	var serviceFieldMappings map[string]string
	if serviceMap, exists := fieldMapping.ServiceMappings[serviceName]; exists {
		serviceFieldMappings = serviceMap.FieldMappings
	} else {
		// Fall back to legacy field mappings for backward compatibility
		serviceFieldMappings = fieldMapping.FieldMappings
	}

	// Apply service-specific field mappings
	for sourceKey, targetKey := range serviceFieldMappings {
		if value, exists := event[sourceKey]; exists && value != nil {
			extensions[targetKey] = sanitizeCEFValue(fmt.Sprintf("%v", value))
		}
	}

	// Handle nested field mappings for the service (like identity.principalName)
	if serviceMap, exists := fieldMapping.ServiceMappings[serviceName]; exists {
		for nestedKey, targetKey := range serviceMap.NestedFieldMappings {
			if value := getNestedValue(event, nestedKey); value != nil {
				extensions[targetKey] = sanitizeCEFValue(fmt.Sprintf("%v", value))
			}
		}
	}

	// Add unmapped fields (not in service-specific mappings)
	for k, v := range event {
		if !isMappedField(k, serviceFieldMappings) && v != nil {
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

// getNestedValue retrieves a nested field value using dot notation (e.g., "identity.principalName")
func getNestedValue(event map[string]interface{}, fieldPath string) interface{} {
	parts := strings.Split(fieldPath, ".")
	current := event

	for i, part := range parts {
		if i == len(parts)-1 {
			// Last part - return the value
			return current[part]
		}

		// Navigate deeper into the nested structure
		if nested, ok := current[part].(map[string]interface{}); ok {
			current = nested
		} else {
			return nil // Path doesn't exist
		}
	}

	return nil
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

func loadEventTypeMap(filename string, config *Configuration) map[string]string {
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

	// Parse as generic JSON first to enable dynamic service discovery
	var rawEventMap map[string]interface{}
	if err := json.Unmarshal(data, &rawEventMap); err != nil {
		log.Printf("❌ Error parsing event type mapping file: %v", err)
		return make(map[string]string)
	}

	// Get enabled services from configuration
	enabledServices := config.getEnabledServices()
	if len(enabledServices) == 0 {
		log.Printf("⚠️  No enabled services found in configuration")
		return make(map[string]string)
	}

	// Get all available sections from the event map file
	availableSections := make([]string, 0, len(rawEventMap))
	for sectionName := range rawEventMap {
		if !strings.HasPrefix(sectionName, "_") { // Skip comment sections
			availableSections = append(availableSections, sectionName)
		}
	}

	log.Printf("🔍 Discovered event map sections: %v", availableSections)

	// Dynamic multi-service parsing - match enabled services to available sections
	combinedMap := make(map[string]string)
	serviceCounts := make(map[string]int)

	for _, service := range enabledServices {
		// Try multiple matching patterns for service name to section name
		potentialSections := []string{
			service.Name + "_events",   // e.g., "audit" -> "audit_events"
			service.Name + "_problems", // e.g., "cloudguard" -> "cloudguard_problems"
			service.Name + "_logs",     // e.g., "logging" -> "vcn_flow_logs" (partial match)
			service.Name,               // e.g., "audit" -> "audit"
		}

		// Also check if any section contains the service name
		for _, sectionName := range availableSections {
			if strings.Contains(sectionName, service.Name) {
				potentialSections = append(potentialSections, sectionName)
			}
		}

		foundSection := ""
		for _, potentialSection := range potentialSections {
			if _, exists := rawEventMap[potentialSection]; exists {
				foundSection = potentialSection
				break
			}
		}

		if foundSection != "" {
			if sectionData, sectionExists := rawEventMap[foundSection]; sectionExists {
				if eventSection, ok := sectionData.(map[string]interface{}); ok {
					count := 0
					for eventType, eventName := range eventSection {
						// Skip comments
						if strings.HasPrefix(eventType, "_") {
							continue
						}
						if eventNameStr, ok := eventName.(string); ok {
							combinedMap[eventType] = eventNameStr
							count++
						}
					}
					serviceCounts[service.Name] = count
					log.Printf("✅ Matched service '%s' to section '%s' (%d events)", service.Name, foundSection, count)
				}
			}
		} else {
			log.Printf("⚠️  No matching event section found for enabled service: %s", service.Name)
		}
	}

	// Log the results dynamically
	if len(combinedMap) > 0 {
		var logParts []string
		for serviceName, count := range serviceCounts {
			if count > 0 {
				logParts = append(logParts, fmt.Sprintf("%d %s", count, serviceName))
			}
		}
		log.Printf("📝 Loaded multi-service event types: %s", strings.Join(logParts, ", "))
		return combinedMap
	}

	// Fall back to legacy format
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
		Lookups:                map[string]LookupConfig{},
		CacheInvalidationRules: map[string][]string{},
		EventFiltering: EventFilter{
			Mode:           "exclude",
			ExcludedEvents: []string{},
			IncludedEvents: []string{},
			RateLimiting:   map[string]RateLimit{},
			PriorityEvents: []string{},
			UserFiltering: UserFilter{
				ExcludeServiceAccounts: false,
				ExcludeUsers:           []string{},
				IncludeOnlyUsers:       []string{},
			},
		},
		Statistics: StatisticsConfig{
			EnableDetailedLogging:   false, // Reduced noise - enable via config if needed
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
		"com.oraclecloud.ComputeApi.GetInstance":          "Get Instance",
		"com.oraclecloud.ComputeApi.LaunchInstance":       "Launch Instance",
		"com.oraclecloud.ComputeApi.TerminateInstance":    "Terminate Instance",
		"com.oraclecloud.identityControlPlane.CreateUser": "Create User",
		"com.oraclecloud.identityControlPlane.UpdateUser": "Update User",
		"com.oraclecloud.identityControlPlane.DeleteUser": "Delete User",
		"com.oraclecloud.VirtualNetworkApi.CreateVcn":     "Create VCN",
		"com.oraclecloud.VirtualNetworkApi.DeleteVcn":     "Delete VCN",
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

// Load the most recent marker from all enabled services
func loadMostRecentServiceMarker(config *Configuration) TimeBasedMarker {
	var mostRecentMarker TimeBasedMarker
	var foundValidMarker bool

	enabledServices := config.getEnabledServices()

	for _, service := range enabledServices {
		markerFile := service.MarkerFile
		if markerFile == "" {
			markerFile = fmt.Sprintf("oci-%s-marker.json", service.Name)
		}

		marker := loadTimeBasedMarker(markerFile)

		// If this is the first valid marker or it's more recent
		if !foundValidMarker || (!marker.LastEventTime.IsZero() && marker.LastEventTime.After(mostRecentMarker.LastEventTime)) {
			mostRecentMarker = marker
			foundValidMarker = true
			log.Printf("📍 Found marker for %s service: %s (Poll #%d)",
				service.Name, marker.LastEventTime.Format("2006-01-02 15:04:05"), marker.PollCount)
		}
	}

	// If no valid markers found, check legacy marker as fallback
	if !foundValidMarker && config.MarkerFile != "" {
		legacyMarker := loadTimeBasedMarker(config.MarkerFile)
		if !legacyMarker.LastEventTime.IsZero() {
			log.Printf("📍 Using legacy marker as fallback: %s (Poll #%d)",
				legacyMarker.LastEventTime.Format("2006-01-02 15:04:05"), legacyMarker.PollCount)
			return legacyMarker
		}
	}

	// If still no marker, create default
	if !foundValidMarker {
		log.Printf("🆕 No existing markers found - creating fresh marker")
		mostRecentMarker = TimeBasedMarker{
			LastEventTime: time.Now().Add(-24 * time.Hour),
			LastEventID:   "",
			PollCount:     0,
		}
	}

	return mostRecentMarker
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

// Periodic compartment refresh goroutine with adaptive scheduling
func startCompartmentRefresh(config *Configuration) {
	baseInterval := time.Duration(config.CompartmentRefreshInterval) * time.Minute
	currentInterval := baseInterval
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	log.Printf("🔄 Starting compartment refresh: base interval %v", baseInterval)

	for {
		select {
		case <-ticker.C:
			// Determine if we should adjust the refresh interval based on rate limiting
			newInterval := calculateCompartmentRefreshInterval(baseInterval, config)

			if newInterval != currentInterval {
				log.Printf("🔄 Adjusting compartment refresh interval: %v → %v (rate limiting adaptation)", currentInterval, newInterval)
				currentInterval = newInterval
				ticker.Stop()
				ticker = time.NewTicker(currentInterval)
			}

			refreshCompartments(config)

		case <-ctx.Done():
			return
		}
	}
}

// Calculate adaptive compartment refresh interval based on rate limiting
func calculateCompartmentRefreshInterval(baseInterval time.Duration, config *Configuration) time.Duration {
	// If no rate limiting issues, use base interval
	if shouldBackoff, remaining := rateLimitState.ShouldBackoff(); shouldBackoff {
		// During active backoff, extend interval to at least backoff + 30s buffer
		extendedInterval := remaining + (30 * time.Second)
		if extendedInterval > baseInterval {
			return extendedInterval
		}
	}

	// If we're in rate limit period but not actively backing off
	if rateLimitState.IsInRateLimitPeriod() {
		// Get configured max backoff from retry strategy
		maxBackoff := time.Duration(config.RetryStrategy.RateLimitHandling.MaxBackoffSeconds) * time.Second
		if maxBackoff == 0 {
			maxBackoff = 120 * time.Second // Default fallback
		}

		// Use the larger of: base interval or max backoff period + 30s buffer
		adaptiveInterval := maxBackoff + (30 * time.Second)
		if adaptiveInterval > baseInterval {
			log.Printf("🔄 Rate limiting detected: extending compartment refresh interval from %v to %v", baseInterval, adaptiveInterval)
			return adaptiveInterval
		}
	}

	// If we have consecutive hits, be increasingly conservative
	rateLimitState.RLock()
	consecutiveHits := rateLimitState.consecutiveHits
	rateLimitState.RUnlock()

	if consecutiveHits > 0 {
		// Progressive backoff: base * (1 + consecutiveHits * 0.5)
		multiplier := 1.0 + float64(consecutiveHits)*0.5
		if multiplier > 4.0 { // Cap at 4x the base interval
			multiplier = 4.0
		}
		adaptiveInterval := time.Duration(float64(baseInterval) * multiplier)

		if adaptiveInterval > baseInterval {
			log.Printf("🔄 Consecutive rate limits (%d): extending compartment refresh interval from %v to %v", consecutiveHits, baseInterval, adaptiveInterval)
			return adaptiveInterval
		}
	}

	return baseInterval
}

// Refresh compartments and detect changes - now multi-region aware with smarter rate limiting
func refreshCompartments(config *Configuration) {
	// The adaptive scheduling should prevent us from getting here during backoff periods,
	// but double-check as a safety mechanism
	if shouldBackoff, remaining := rateLimitState.ShouldBackoff(); shouldBackoff {
		log.Printf("⏸️  Emergency skip: compartment refresh called during active backoff (remaining: %v)", remaining)
		return
	}

	log.Printf("🔄 Refreshing compartments across all regions...")

	// Determine all regions that need compartment refresh (same logic as startup)
	enabledServices := config.getEnabledServices()
	allRegions := make(map[string]bool)

	for _, service := range enabledServices {
		if service.Name == "audit" || service.Name == "cloudguard" {
			// Collect all regions from all services that need compartments
			for _, region := range config.getServiceRegions(service) {
				allRegions[region] = true
			}
		}
	}

	if len(allRegions) == 0 {
		log.Printf("⚠️  No regions need compartment refresh - skipping")
		return
	}

	// Store current compartments for change detection
	totalCurrentCount := regionCompartments.TotalCompartments()
	var globalNewCompartments []OCICompartment

	// Refresh compartments for each region
	for region := range allRegions {
		if config.Verbose {
			log.Printf("🔄 Refreshing compartments for region: %s", region)
		}

		// Get current compartments for this region
		currentRegionCompartments := regionCompartments.GetForRegion(region)
		currentRegionIDs := make(map[string]OCICompartment)
		for _, comp := range currentRegionCompartments {
			currentRegionIDs[comp.ID] = comp
		}

		// Load fresh compartments for this region (same as startup logic)
		tenancyCompartment := OCICompartment{
			ID:             config.TenancyOCID,
			Name:           fmt.Sprintf("root (%s)", region),
			Description:    fmt.Sprintf("Root tenancy compartment in %s", region),
			LifecycleState: "ACTIVE",
			TimeCreated:    time.Now().Format(time.RFC3339),
		}
		allCompartments := []OCICompartment{tenancyCompartment}

		// Load sub-compartments if needed
		if config.CompartmentMode != "tenancy_only" {
			if err := loadSubCompartmentsForRegion(config.TenancyOCID, config, region, &allCompartments); err != nil {
				log.Printf("❌ Failed to refresh compartments for region %s: %v", region, err)
				continue // Continue with other regions
			}
		}

		// Apply filtering
		filteredCompartments := filterCompartments(allCompartments, config)

		// Detect new compartments in this region
		var regionNewCompartments []OCICompartment
		for _, comp := range filteredCompartments {
			if _, exists := currentRegionIDs[comp.ID]; !exists {
				regionNewCompartments = append(regionNewCompartments, comp)
				globalNewCompartments = append(globalNewCompartments, comp)
			}
		}

		// Update region-specific compartments
		regionCompartments.SetForRegion(region, filteredCompartments)

		// Also update legacy compartments manager if this is the primary region
		if region == config.Region {
			compartments.Set(filteredCompartments)
		}

		if len(regionNewCompartments) > 0 {
			log.Printf("🆕 Region %s: Discovered %d new compartments", region, len(regionNewCompartments))
			if config.Verbose {
				for _, comp := range regionNewCompartments {
					log.Printf("  + %s (%s) [%s]", comp.Name, comp.ID, comp.LifecycleState)
				}
			}
		}

		log.Printf("🔄 Region %s: %d compartments refreshed (%d new)", region, len(filteredCompartments), len(regionNewCompartments))
	}

	// Global summary
	totalNewCount := regionCompartments.TotalCompartments()

	if len(globalNewCompartments) > 0 {
		log.Printf("🆕 Global Discovery: %d new compartments across %d regions", len(globalNewCompartments), len(allRegions))
		if !config.Verbose {
			// Show summary if not already shown in verbose mode
			for _, comp := range globalNewCompartments {
				log.Printf("  + %s (%s) [%s]", comp.Name, comp.ID, comp.LifecycleState)
			}
		}
	}

	if totalNewCount != totalCurrentCount {
		log.Printf("🔄 Total compartment count changed: %d → %d across %d regions", totalCurrentCount, totalNewCount, len(allRegions))
	} else {
		log.Printf("🔄 Compartment refresh complete: %d compartments across %d regions (no changes)", totalNewCount, len(allRegions))
	}
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

// Enhanced Filtering with Deduplication for Service Events
func filterServiceEventsWithDeduplication(events []ServiceEvent, filter EventFilter, stats StatisticsConfig, config *Configuration) ([]ServiceEvent, int, int, int, int) {
	if filter.Mode == "all" && eventCache == nil {
		return events, 0, 0, 0, 0
	}

	var filteredEvents []ServiceEvent
	droppedCount := 0
	duplicateCount := 0
	localCacheHits := 0
	localCacheMisses := 0

	for _, event := range events {
		eventType := event.EventType
		eventKey := getServiceEventDeduplicationKey(event)

		if eventCache != nil {
			if eventCache.HasProcessed(eventKey) {
				// CACHE HIT - it's a duplicate
				duplicateCount++
				eventCacheStats.DuplicatesDetected++
				eventCacheStats.CacheHits++
				localCacheHits++

				// Only log duplicates in verbose mode or for troubleshooting
				if config.Verbose {
					eventCache.RLock()
					processedTime, exists := eventCache.processedEvents[eventKey]
					eventCache.RUnlock()

					if exists {
						log.Printf("🔄 DUPLICATE: Key=%s, Service=%s, Type=%s, EventTime=%s, FirstProcessed=%s, Age=%v",
							eventKey, event.ServiceName, eventType,
							event.EventTime,
							processedTime.Format("2006-01-02T15:04:05"),
							time.Since(processedTime))
					}
				}
				continue
			} else {
				// CACHE MISS - it's a new event
				eventCacheStats.CacheMisses++
				localCacheMisses++
			}
		}

		// Apply service event filtering logic
		if shouldProcessServiceEvent(event, eventType, filter) {
			filteredEvents = append(filteredEvents, event)

			// Verbose logging for new events (only when debugging cache issues)
			if config.Verbose {
				log.Printf("✅ NEW EVENT: Key=%s, Service=%s, Type=%s, EventTime=%s",
					eventKey, event.ServiceName, eventType, event.EventTime)
			}
		} else {
			droppedCount++
			if stats.EnableDetailedLogging && config.Verbose {
				log.Printf("🚫 Filtered %s event type %s (Key: %s)", event.ServiceName, eventType, eventKey)
			}
		}
	}

	return filteredEvents, droppedCount, duplicateCount, localCacheHits, localCacheMisses
}

// Create deduplication key for ServiceEvent
func getServiceEventDeduplicationKey(event ServiceEvent) string {
	var keyParts []string

	// Always include service name, event type, and event ID
	keyParts = append(keyParts, fmt.Sprintf("svc%s", event.ServiceName))
	keyParts = append(keyParts, fmt.Sprintf("t%s", event.EventType))
	keyParts = append(keyParts, fmt.Sprintf("id%s", event.EventID))

	// For additional uniqueness, add truncated timestamp (to the minute) to handle edge cases
	// but avoid exact timestamp issues with overlapping polls
	if parsedTime, err := time.Parse(time.RFC3339, event.EventTime); err == nil {
		truncatedTime := parsedTime.Truncate(time.Minute)
		keyParts = append(keyParts, fmt.Sprintf("min%s", truncatedTime.Format("2006010215:04")))
	} else {
		// Fallback to exact time if parsing fails
		keyParts = append(keyParts, fmt.Sprintf("time%s", event.EventTime))
	}

	return strings.Join(keyParts, "|")
}

// Service event filtering logic
func shouldProcessServiceEvent(event ServiceEvent, eventType string, filter EventFilter) bool {
	// Check priority events first (highest precedence)
	for _, priority := range filter.PriorityEvents {
		if eventType == priority {
			// Even priority events must pass rate limiting
			return passesRateLimit(eventType, filter.RateLimiting)
		}
	}

	// For CloudGuard events, check risk level but still apply all filters
	if event.ServiceName == "cloudguard" {
		if event.RawData != nil {
			// Handle CloudGuard Problems (security incidents)
			if problem, ok := event.RawData.(CloudGuardProblem); ok {
				// High/Critical problems get preference but still must pass rate limiting
				isHighRisk := problem.RiskLevel == "HIGH" || problem.RiskLevel == "CRITICAL"
				if isHighRisk {
					// Still apply rate limiting to high-risk events
					if !passesRateLimit(eventType, filter.RateLimiting) {
						return false
					}
					// High risk events bypass include/exclude but not rate limits
					return true
				}
			} else if detector, ok := event.RawData.(CloudGuardDetector); ok {
				// Handle CloudGuard Detectors (security rules/policies)
				// Critical/High risk detectors are important configuration changes
				isHighRisk := detector.RiskLevel == "HIGH" || detector.RiskLevel == "CRITICAL"
				if isHighRisk {
					if !passesRateLimit(eventType, filter.RateLimiting) {
						return false
					}
					// High risk detector changes bypass include/exclude filters
					return true
				}
			} else if _, ok := event.RawData.(CloudGuardTarget); ok {
				// Handle CloudGuard Targets (monitored resources)
				// Targets are configuration changes, always important to track
				// Still apply rate limiting
				if !passesRateLimit(eventType, filter.RateLimiting) {
					return false
				}
				// Target configuration changes are always significant
				return true
			}
		}
	}

	// For audit events, use existing logic which includes rate limiting
	if event.ServiceName == "audit" {
		if event.RawData != nil {
			if auditEvent, ok := event.RawData.(OCIAuditEvent); ok {
				return shouldProcessEvent(auditEvent, eventType, filter)
			}
		}
	}

	// Apply rate limiting to all other events
	if !passesRateLimit(eventType, filter.RateLimiting) {
		return false
	}

	// Apply include/exclude filtering
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
