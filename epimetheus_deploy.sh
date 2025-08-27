#!/bin/bash

#===============================================================================
# Epimetheus OCI Multi-Service Event Forwarder Deployment Script
# 
# This script automatically downloads, compiles, and deploys the Epimetheus
# OCI Multi-Service Event Forwarder with support for:
# - OCI Audit Events
# - OCI Cloud Guard Problems  
# - Additional OCI services (configurable)
#
# Features proper systemd configuration, security hardening, and multi-service
# architecture with individual service configuration and state management.
#
# Requirements: Ubuntu 22.04 LTS (Go will be installed from apt)
# Usage: sudo ./epimetheus_deploy.sh
#===============================================================================

set -euo pipefail

# Configuration
SERVICE_NAME="epimetheus"
SERVICE_USER="oci-user"
SERVICE_GROUP="oci-user"
BINARY_PATH="/usr/local/bin/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
CONFIG_FILE="${CONFIG_DIR}/oci-config.json"
FIELD_MAP_FILE="${CONFIG_DIR}/oci_field_map_multi.json"
EVENT_MAP_FILE="${CONFIG_DIR}/oci-event-map-multi.json"
MARKER_DIR="${CONFIG_DIR}/markers"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_REPO_URL="https://raw.githubusercontent.com/SlickHenry/Epimetheus/refs/heads/main"
TEMP_DIR="/tmp/${SERVICE_NAME}-deploy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo $0'"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    log_step "Checking system compatibility..."
    
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
    
    # Check Ubuntu version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            log_warn "This script is designed for Ubuntu. Your system: $ID"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    log_info "System compatibility check passed"
}

# Install Go if not present
install_go() {
    log_step "Checking Go installation..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go is already installed (version: $GO_VERSION)"
        return 0
    fi
    
    log_info "Installing Go from Ubuntu repositories..."
    
    # Update package lists
    apt-get update
    
    # Install Go and required dependencies
    apt-get install -y golang-go wget curl build-essential
    
    # Verify installation
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go installed successfully (version: $GO_VERSION)"
    else
        log_error "Go installation failed"
        exit 1
    fi
}

# Create service user and group
create_service_user() {
    log_step "Creating service user and group..."
    
    # Create group if it doesn't exist
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
        log_info "Created group: $SERVICE_GROUP"
    else
        log_info "Group $SERVICE_GROUP already exists"
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system \
                --gid "$SERVICE_GROUP" \
                --create-home \
                --home-dir "/var/lib/$SERVICE_USER" \
                --shell /usr/sbin/nologin \
                --comment "Epimetheus OCI Multi-Service Event Forwarder service user" \
                "$SERVICE_USER"
        log_info "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

# Download and compile the application
download_and_compile() {
    log_step "Downloading and compiling application..."
    
    # Create temporary directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Download source code
    log_info "Downloading source code..."
    curl -fsSL "${GITHUB_REPO_URL}/oci.go" -o oci.go
    
    # Initialize Go module
    log_info "Initializing Go module..."
    export GOPATH="/tmp/go"
    export GOCACHE="/tmp/go-cache"
    
    go mod init epimetheus
    go mod tidy
    
    # Compile the application
    log_info "Compiling application..."
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o "${SERVICE_NAME}" oci.go
    
    # Verify compilation
    if [[ ! -f "$SERVICE_NAME" ]]; then
        log_error "Compilation failed - binary not found"
        exit 1
    fi
    
    # Check if binary is executable
    if [[ ! -x "$SERVICE_NAME" ]]; then
        chmod +x "$SERVICE_NAME"
    fi
    
    log_info "Application compiled successfully"
}

# Setup directories and permissions
setup_directories() {
    log_step "Setting up directories and permissions..."
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    chown root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    # Create marker directory for multi-service marker files
    mkdir -p "$MARKER_DIR"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$MARKER_DIR"
    chmod 750 "$MARKER_DIR"
    
    # Create log file and set permissions
    touch "$LOG_FILE"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    # Create service user home directory
    mkdir -p "/var/lib/$SERVICE_USER"
    chown "$SERVICE_USER:$SERVICE_GROUP" "/var/lib/$SERVICE_USER"
    chmod 750 "/var/lib/$SERVICE_USER"
    
    log_info "Directories and permissions configured"
}

# Install binary
install_binary() {
    log_step "Installing binary..."
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Copy binary to system location
    cp "$TEMP_DIR/$SERVICE_NAME" "$BINARY_PATH"
    chown root:root "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    
    log_info "Binary installed to $BINARY_PATH"
}

# Download and install configuration files
install_configuration() {
    log_step "Installing configuration files..."
    
    # Download oci-config.json if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "Downloading multi-service OCI configuration..."
        curl -fsSL "${GITHUB_REPO_URL}/oci-config.json" -o "$CONFIG_FILE"
        
        # Set permissions
        chown root:"$SERVICE_GROUP" "$CONFIG_FILE"
        chmod 640 "$CONFIG_FILE"
        
        log_warn "Multi-service OCI configuration installed. You MUST edit $CONFIG_FILE before starting the service!"
    else
        log_info "OCI configuration file already exists: $CONFIG_FILE"
    fi
    
    # Download oci_field_map_multi.json if it doesn't exist
    if [[ ! -f "$FIELD_MAP_FILE" ]]; then
        log_info "Downloading multi-service OCI field mapping configuration..."
        curl -fsSL "${GITHUB_REPO_URL}/oci_field_map_multi.json" -o "$FIELD_MAP_FILE"
        
        # Set permissions
        chown root:"$SERVICE_GROUP" "$FIELD_MAP_FILE"
        chmod 640 "$FIELD_MAP_FILE"
        
        log_info "Multi-service OCI field mapping configuration installed: $FIELD_MAP_FILE"
    else
        log_info "Field mapping file already exists: $FIELD_MAP_FILE"
    fi
    
    # Download oci-event-map-multi.json if it doesn't exist
    if [[ ! -f "$EVENT_MAP_FILE" ]]; then
        log_info "Downloading multi-service OCI event mapping configuration..."
        curl -fsSL "${GITHUB_REPO_URL}/oci-event-map-multi.json" -o "$EVENT_MAP_FILE"
        
        # Set permissions
        chown root:"$SERVICE_GROUP" "$EVENT_MAP_FILE"
        chmod 640 "$EVENT_MAP_FILE"
        
        log_info "Multi-service OCI event mapping configuration installed: $EVENT_MAP_FILE"
    else
        log_info "Event mapping file already exists: $EVENT_MAP_FILE"
    fi
    
    # Create initial marker files for enabled services
    log_info "Setting up marker directory for multi-service markers..."
    
    # Create sample marker files (the application will manage these)
    for service in audit cloudguard; do
        marker_file="$MARKER_DIR/oci_${service}_marker.json"
        if [[ ! -f "$marker_file" ]]; then
            echo '{"last_event_time":"'$(date -d '24 hours ago' -Iseconds)'","last_event_id":"","poll_count":0}' > "$marker_file"
            chown "$SERVICE_USER:$SERVICE_GROUP" "$marker_file"
            chmod 640 "$marker_file"
            log_info "Created initial ${service} marker file: $marker_file"
        fi
    done
}

# Create systemd service file
create_systemd_service() {
    log_step "Creating systemd service..."
    
    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=Epimetheus - OCI Multi-Service Event Forwarder
Documentation=https://github.com/SlickHenry/Epimetheus
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=$BINARY_PATH --config $CONFIG_FILE
ExecStartPre=/usr/bin/test -f $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID

WorkingDirectory=$CONFIG_DIR
Restart=always
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
SyslogIdentifier=$SERVICE_NAME

# Environment file for credential overrides
EnvironmentFile=-$CONFIG_DIR/environment

# Security settings - hardened service
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$CONFIG_DIR /var/log /var/lib/$SERVICE_USER
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectHostname=true
ProtectClock=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryAccounting=true
MemoryMax=512M

# Environment
Environment=GOMAXPROCS=2
Environment=CONFIG_FILE=$CONFIG_FILE

[Install]
WantedBy=multi-user.target
EOF
    
    # Set proper permissions on service file
    chmod 644 "$SYSTEMD_SERVICE_FILE"
    
    log_info "Systemd service file created: $SYSTEMD_SERVICE_FILE"
}

# Create environment file template
create_environment_file() {
    log_step "Creating environment configuration template..."
    
    cat > "$CONFIG_DIR/environment" << EOF
# Epimetheus OCI Multi-Service Event Forwarder Environment Configuration
# 
# This file provides credential overrides and optional environment-based configuration
# Most configuration should be done in oci-config.json
# 
# REQUIRED - OCI API Credentials (override JSON config values)
OCI_TENANCY_OCID=ocid1.tenancy.oc1..aaaaaaaaexample
OCI_USER_OCID=ocid1.user.oc1..aaaaaaaaexample
OCI_KEY_FINGERPRINT=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
OCI_PRIVATE_KEY_PATH=/etc/epimetheus/oci_api_key.pem

# REQUIRED - OCI Region (override JSON config)
OCI_REGION=us-phoenix-1

# REQUIRED - Syslog Configuration (override JSON config)
SYSLOG_SERVER=your-siem-server.com
SYSLOG_PORT=514
SYSLOG_PROTOCOL=tcp

# Optional - Global Overrides for JSON Configuration
# Uncomment and modify as needed:
#
# FETCH_INTERVAL=300
# HEALTH_CHECK_PORT=8080
# COMPARTMENT_MODE=all
# COMPARTMENT_IDS=ocid1.compartment.oc1..aaa,ocid1.compartment.oc1..bbb
# ENABLE_EVENT_CACHE=true
# EVENT_CACHE_SIZE=10000
# EVENT_CACHE_WINDOW=3600
# INITIAL_LOOKBACK_HOURS=24
# POLL_OVERLAP_MINUTES=5
# MAX_EVENTS_PER_POLL=1000
# ENABLE_COMPARTMENT_REFRESH=true
# COMPARTMENT_REFRESH_INTERVAL=60
# LOG_LEVEL=info
# VERBOSE=false

# Multi-Service Configuration:
# Primary configuration is in $CONFIG_FILE
# This includes enabled services (audit, cloudguard), field mappings, 
# event filtering, statistics settings, and per-service configurations.
EOF
    
    # Set permissions
    chown root:"$SERVICE_GROUP" "$CONFIG_DIR/environment"
    chmod 640 "$CONFIG_DIR/environment"
    
    log_info "Environment configuration template created: $CONFIG_DIR/environment"
}

# Setup logrotate
setup_logrotate() {
    log_step "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
$LOG_FILE {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_USER $SERVICE_GROUP
    postrotate
        /bin/systemctl reload-or-restart $SERVICE_NAME >/dev/null 2>&1 || true
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

# Enable and start service
enable_service() {
    log_step "Configuring systemd service..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log_info "Service enabled for automatic startup"
    log_warn "Service is NOT started yet. You must configure the environment file first!"
}

# Cleanup temporary files
cleanup() {
    log_step "Cleaning up temporary files..."
    
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Clean Go cache
    if [[ -d "/tmp/go-cache" ]]; then
        rm -rf "/tmp/go-cache"
    fi
    
    if [[ -d "/tmp/go" ]]; then
        rm -rf "/tmp/go"
    fi
    
    log_info "Cleanup completed"
}

# Display post-installation instructions
show_instructions() {
    echo
    echo "======================================================================"
    log_info "Epimetheus OCI Multi-Service Event Forwarder installation completed successfully!"
    echo "======================================================================"
    echo
    echo "🎯 MULTI-SERVICE ARCHITECTURE:"
    echo "   This installation supports multiple OCI services (Audit, CloudGuard, etc.)"
    echo "   Configure services individually in the JSON config file."
    echo
    echo "📝 CONFIGURATION STEPS:"
    echo
    echo "1. Configure environment variables (optional overrides):"
    echo "   sudo nano $CONFIG_DIR/environment"
    echo
    echo "2. ⭐ PRIMARY CONFIGURATION - Edit JSON config file:"
    echo "   sudo nano $CONFIG_FILE"
    echo "   - Set OCI credentials (tenancy_ocid, user_ocid, key_fingerprint, private_key_path)"
    echo "   - Set region and syslog server details" 
    echo "   - Enable/disable services in 'api_services' section"
    echo "   - Configure polling intervals and service-specific settings"
    echo "   - Customize event filtering, field mappings, and statistics"
    echo
    echo "3. Copy your OCI private key file to the path specified in JSON config"
    echo
    echo "4. Place your OCI private key file:"
    echo "   sudo cp /path/to/your/oci_api_key.pem $CONFIG_DIR/"
    echo "   sudo chown root:$SERVICE_GROUP $CONFIG_DIR/oci_api_key.pem"
    echo "   sudo chmod 640 $CONFIG_DIR/oci_api_key.pem"
    echo
    echo "5. Test the configuration:"
    echo "   sudo -u $SERVICE_USER $BINARY_PATH --config $CONFIG_FILE --validate"
    echo
    echo "6. Test connections:"
    echo "   sudo -u $SERVICE_USER $BINARY_PATH --config $CONFIG_FILE --test"
    echo
    echo "7. Start the service:"
    echo "   sudo systemctl start $SERVICE_NAME"
    echo
    echo "8. Check service status:"
    echo "   sudo systemctl status $SERVICE_NAME"
    echo
    echo "9. View logs:"
    echo "   sudo journalctl -u $SERVICE_NAME -f"
    echo "   tail -f $LOG_FILE"
    echo
    echo "10. Health check endpoints (once running):"
    echo "    curl http://localhost:8080/health    # Detailed health with service status"
    echo "    curl http://localhost:8080/metrics   # Prometheus-compatible metrics"
    echo
    echo "⚡ SIMPLIFIED CLI INTERFACE:"
    echo "   --config FILE    (JSON configuration file path)"
    echo "   --test          (test connections and exit)"
    echo "   --validate      (validate configuration and exit)"
    echo "   --version       (show version and exit)"
    echo "   --verbose       (enable verbose output)"
    echo
    echo "   All other configuration is now managed via JSON config file."
    echo
    echo "🔧 SERVICE MANAGEMENT:"
    echo "    sudo systemctl start $SERVICE_NAME     # Start service"
    echo "    sudo systemctl stop $SERVICE_NAME      # Stop service"
    echo "    sudo systemctl restart $SERVICE_NAME   # Restart service"
    echo "    sudo systemctl status $SERVICE_NAME    # Check status"
    echo "    sudo systemctl reload $SERVICE_NAME    # Reload config (SIGHUP)"
    echo
    echo "📁 CONFIGURATION FILES:"
    echo "- Environment/Credentials: $CONFIG_DIR/environment"
    echo "- Multi-Service Config: $CONFIG_FILE"
    echo "- Field Mapping: $FIELD_MAP_FILE"
    echo "- Event Mapping: $EVENT_MAP_FILE"
    echo "- Service Markers: $MARKER_DIR/oci_*_marker.json"
    echo "- Log File: $LOG_FILE"
    echo "- Binary: $BINARY_PATH"
    echo
    echo "⚙️  ADVANCED MULTI-SERVICE CONFIGURATION:"
    echo "- Edit $CONFIG_FILE 'api_services' section to enable/disable services"
    echo "- Each service can have different polling intervals and endpoints"
    echo "- Service-specific field mappings in $FIELD_MAP_FILE"
    echo "- Service-specific event type mappings in $EVENT_MAP_FILE"
    echo "- Individual marker files track state per service"
    echo "- Statistics can be configured per service or globally"
    echo "- Rate limiting and filtering can be applied per event type"
    echo
    echo "🛡️  SUPPORTED SERVICES:"
    echo "- audit: OCI Audit Events (standard audit trail)"
    echo "- cloudguard: OCI Cloud Guard Problems (security findings)"
    echo "- Additional services can be added via configuration"
    echo
    echo "🔍 TROUBLESHOOTING:"
    echo "- Check logs for specific service connection issues"
    echo "- Verify enabled services have proper API endpoints configured"
    echo "- Each service creates its own marker file for state tracking"
    echo "- Health endpoint shows per-service statistics and errors"
    echo "- Use 'verbose' logging for detailed multi-service debugging"
    echo
    echo "🔐 REQUIRED OCI IAM POLICIES:"
    echo "  Allow group <YourGroup> to read audit-events in tenancy"
    echo "  Allow group <YourGroup> to read compartments in tenancy"
    echo "  Allow group <YourGroup> to read cloud-guard-problems in tenancy"
    echo "  Allow group <YourGroup> to read cloud-guard-detectors in tenancy"
    echo
    echo "🎉 PRODUCTION READY:"
    echo "   This version includes all critical fixes and enterprise features:"
    echo "   - Multi-service architecture with conditional loading"
    echo "   - Enhanced error handling and compartment recursion protection"
    echo "   - Comprehensive statistics and health monitoring"  
    echo "   - Rate limiting applied to all event types including priority events"
    echo "   - Service-specific field mappings and event filtering"
    echo "   - Robust deduplication with overlapping poll protection"
    echo
    echo "======================================================================"
}

# Main execution
main() {
    echo "======================================================================"
    echo "Epimetheus OCI Multi-Service Event Forwarder Deployment Script"
    echo "======================================================================"
    echo
    
    # Trap to ensure cleanup on exit
    trap cleanup EXIT
    
    check_root
    check_system
    install_go
    create_service_user
    download_and_compile
    setup_directories
    install_binary
    install_configuration
    create_environment_file
    create_systemd_service
    setup_logrotate
    enable_service
    
    show_instructions
}

# Run main function
main "$@"
