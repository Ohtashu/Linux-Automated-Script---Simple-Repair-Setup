#!/bin/bash

#############################################################################
# Linux System Integrity Checker & Auto-Repair Script
# Supports: Ubuntu/Debian, Arch Linux, Fedora
# Checks: APT/DNF/Pacman packages, Snap, Flatpak, Kernel, Drivers, Storage
#############################################################################

# Disable exit on error for better error handling
set -uo pipefail

# Timeout settings (in seconds)
COMMAND_TIMEOUT=300  # 5 minutes default
PACKAGE_CHECK_TIMEOUT=1800  # 30 minutes for package integrity checks
UPDATE_TIMEOUT=600  # 10 minutes for updates
DRIVE_CHECK_TIMEOUT=3600  # 60 minutes for drive checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Counters
TOTAL_ISSUES=0
TOTAL_FIXED=0
TOTAL_FAILED=0
STUCK_OPERATIONS=0
DRIVE_ISSUES=0
DRIVE_FIXED=0
DETECTED_DRIVES=""

# Distribution detection (set globally)
DISTRO=""
DISTRO_FAMILY=""

# Log file
LOG_FILE="/var/log/system-integrity-check-$(date +%Y%m%d-%H%M%S).log"

# PID tracking for cleanup
CHILD_PIDS=()

# Trap for cleanup on script exit
trap cleanup EXIT INT TERM

#############################################################################
# Cleanup and Error Handling
#############################################################################

cleanup() {
    local exit_code=$?
    
    # Kill any remaining child processes
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            print_warning "Cleaning up stuck process: $pid"
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    
    # Clear the PID array
    CHILD_PIDS=()
    
    if [ $exit_code -ne 0 ]; then
        print_error "Script exited with error code: $exit_code"
        echo "Check log file for details: $LOG_FILE"
    fi
}

handle_error() {
    local line_no=$1
    local error_msg="${2:-Unknown error}"
    
    print_error "Error at line $line_no: $error_msg"
    echo "[ERROR] Line $line_no: $error_msg" >> "$LOG_FILE"
    
    # Don't exit, just log and continue
    return 1
}

# Set up error handling
set -E
trap 'handle_error ${LINENO} "${BASH_COMMAND}"' ERR

#############################################################################
# Helper Functions
#############################################################################

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    echo "[SUCCESS] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    echo "[ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
    echo "[WARNING] $1" >> "$LOG_FILE"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
    echo "[INFO] $1" >> "$LOG_FILE"
}

print_user_friendly() {
    echo -e "${CYAN}👤 $1${NC}"
    echo "[USER-INFO] $1" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Enhanced distribution detection
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

# Detect distribution family (Debian-based, Fedora-based, Arch-based)
detect_distro_family() {
    local distro_id=$(detect_distro)
    
    # Debian-based distributions
    case "$distro_id" in
        ubuntu|debian|linuxmint|pop|elementary|deepin|kali|parrot|raspbian|mx|antiX|devuan|puredyne|trisquel|zorin)
            echo "debian"
            ;;
        # Fedora-based distributions
        fedora|rhel|centos|rocky|almalinux|oracle|scientific|clearos|amazon|alibaba|alios|anolis|opencloudos|qilin|sailfishos)
            echo "fedora"
            ;;
        # Arch-based distributions
        arch|manjaro|endeavouros|garuda|artix|arcolinux|archcraft|archlabs|archman|blendos|cachyos|chimeraos|holoiso|instantos|namib|obarun|rebornos|steamos|vanilla|venom|zeninstaller)
            echo "arch"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

notify_user() {
    local title="$1"
    local message="$2"
    
    # Try to notify logged-in users
    for user in $(who | awk '{print $1}' | sort -u); do
        sudo -u "$user" DISPLAY=:0 notify-send "$title" "$message" 2>/dev/null || true
    done
}

# Execute command with timeout and progress monitoring
run_with_timeout() {
    local timeout=$1
    shift
    local cmd="$@"
    local start_time=$(date +%s)
    local last_output_time=$start_time
    local output_check_interval=30  # Check for output every 30 seconds
    
    print_info "Running: $cmd (timeout: ${timeout}s)"
    
    # Create temporary files for output
    local stdout_file=$(mktemp)
    local stderr_file=$(mktemp)
    
    # Run command in background
    eval "$cmd" > "$stdout_file" 2> "$stderr_file" &
    local cmd_pid=$!
    CHILD_PIDS+=($cmd_pid)
    
    # Monitor the process
    while kill -0 $cmd_pid 2>/dev/null; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Check if command exceeded timeout
        if [ $elapsed -gt $timeout ]; then
            print_error "Command timed out after ${elapsed}s: $cmd"
            kill -TERM $cmd_pid 2>/dev/null || true
            sleep 2
            kill -KILL $cmd_pid 2>/dev/null || true
            
            # Remove from tracked PIDs
            CHILD_PIDS=("${CHILD_PIDS[@]/$cmd_pid}")
            
            STUCK_OPERATIONS=$((STUCK_OPERATIONS + 1))
            rm -f "$stdout_file" "$stderr_file"
            return 124  # Timeout exit code
        fi
        
        # Check for new output (signs of progress)
        if [ -s "$stdout_file" ] || [ -s "$stderr_file" ]; then
            last_output_time=$current_time
        else
            # Check if stuck (no output for extended period)
            local silence_duration=$((current_time - last_output_time))
            if [ $silence_duration -gt 120 ]; then  # 2 minutes of silence
                print_warning "No output for ${silence_duration}s, command may be stuck..."
            fi
        fi
        
        # Show progress indicator every 10 seconds
        if [ $((elapsed % 10)) -eq 0 ] && [ $elapsed -gt 0 ]; then
            echo -ne "\r⏳ Running for ${elapsed}s..."
        fi
        
        sleep 1
    done
    
    echo -ne "\r"  # Clear progress line
    
    # Get exit code
    wait $cmd_pid
    local exit_code=$?
    
    # Remove from tracked PIDs
    CHILD_PIDS=("${CHILD_PIDS[@]/$cmd_pid}")
    
    # Display output
    if [ -s "$stdout_file" ]; then
        cat "$stdout_file" | tee -a "$LOG_FILE"
    fi
    if [ -s "$stderr_file" ]; then
        cat "$stderr_file" | tee -a "$LOG_FILE" >&2
    fi
    
    # Cleanup temp files
    rm -f "$stdout_file" "$stderr_file"
    
    return $exit_code
}

# Wrapper for critical operations with retry logic
run_with_retry() {
    local max_attempts=3
    local attempt=1
    local timeout=$1
    shift
    local cmd="$@"
    
    while [ $attempt -le $max_attempts ]; do
        print_info "Attempt $attempt/$max_attempts"
        
        if run_with_timeout $timeout "$cmd"; then
            return 0
        else
            local exit_code=$?
            
            if [ $exit_code -eq 124 ]; then
                print_warning "Command timed out on attempt $attempt"
            else
                print_warning "Command failed with exit code $exit_code on attempt $attempt"
            fi
            
            if [ $attempt -lt $max_attempts ]; then
                local wait_time=$((attempt * 5))
                print_info "Waiting ${wait_time}s before retry..."
                sleep $wait_time
            fi
        fi
        
        attempt=$((attempt + 1))
    done
    
    print_error "Command failed after $max_attempts attempts: $cmd"
    return 1
}

#############################################################################
# Preflight / Bug-Check Utilities
#############################################################################

require_cmd_or_warn() {
    local cmd="$1"
    local hint="${2:-}"
    if command -v "$cmd" &>/dev/null; then
        return 0
    fi
    print_warning "Missing command: $cmd ${hint:+($hint)}"
    return 1
}

preflight_checks() {
    print_header "Preflight Checks"

    # Basic required tools used throughout the script
    require_cmd_or_warn "timeout" "usually in coreutils"
    require_cmd_or_warn "lsblk" "usually in util-linux"
    require_cmd_or_warn "findmnt" "usually in util-linux"

    # Distro-specific package manager sanity
    case "${DISTRO_FAMILY:-unknown}" in
        arch)
            require_cmd_or_warn "pacman" ""
            ;;
        debian)
            require_cmd_or_warn "apt-get" ""
            require_cmd_or_warn "dpkg" ""
            ;;
        fedora)
            require_cmd_or_warn "rpm" ""
            ;;
    esac

    # Flatpak is optional, but we warn if the checks/install paths will use it
    if command -v flatpak &>/dev/null; then
        if ! flatpak remote-list 2>/dev/null | awk '{print $1}' | grep -qx "flathub"; then
            print_warning "Flatpak is installed but flathub remote is not configured yet (setup will add it)."
        fi
    fi
}

#############################################################################
# Debian/Ubuntu Package System Check
#############################################################################

check_debian_packages() {
    print_header "Checking Debian/Ubuntu Package Integrity"
    
    if ! command -v dpkg &> /dev/null; then
        print_warning "dpkg not found, skipping Debian package check"
        return
    fi
    
    # Update package lists
    print_info "Updating package lists..."
    if run_with_retry $UPDATE_TIMEOUT "apt-get update"; then
        print_success "Package lists updated"
    else
        print_error "Failed to update package lists after multiple attempts"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    # Upgrade packages
    print_info "Upgrading packages..."
    if run_with_retry $UPDATE_TIMEOUT "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"; then
        print_success "Packages upgraded successfully"
    else
        print_error "Failed to upgrade packages"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    print_info "Scanning installed packages for corruption..."
    
    # Check for broken packages
    local broken_packages=$(dpkg -l | grep -E "^..[HUF]" | awk '{print $2}' || true)
    
    if [ -n "$broken_packages" ]; then
        print_warning "Found broken packages:"
        echo "$broken_packages"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        print_info "Attempting to repair broken packages..."
        if run_with_retry $COMMAND_TIMEOUT "dpkg --configure -a && apt-get install -f -y"; then
            print_success "Broken packages repaired"
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        else
            print_error "Failed to repair some packages"
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    else
        print_success "No broken packages found"
    fi
    
    # Verify package integrity
    print_info "Verifying package file integrity (this may take a while)..."
    
    # Check if debsums is installed
    if ! command -v debsums &> /dev/null; then
        print_warning "debsums not installed, installing it now..."
        run_with_timeout $COMMAND_TIMEOUT "apt-get install -y debsums" || {
            print_error "Failed to install debsums"
            return 1
        }
    fi
    
    local corrupted_count=0
    local corrupted_packages=()
    
    # First pass: identify all corrupted packages with timeout
    print_info "Scanning packages for file corruption..."
    local package_count=$(dpkg -l | grep '^ii' | wc -l)
    local current=0
    
    while IFS= read -r package; do
        current=$((current + 1))
        
        # Show progress every 50 packages
        if [ $((current % 50)) -eq 0 ]; then
            echo -ne "\r⏳ Checked $current/$package_count packages..."
        fi
        
        # Check package with timeout
        if ! timeout 30 debsums -s "$package" 2>/dev/null; then
            corrupted_packages+=("$package")
        fi
    done < <(dpkg -l | grep '^ii' | awk '{print $2}')
    
    echo -ne "\r"  # Clear progress line
    print_success "Scanned $package_count packages"
    
    # Second pass: repair corrupted packages
    if [ ${#corrupted_packages[@]} -gt 0 ]; then
        print_warning "Found ${#corrupted_packages[@]} corrupted package(s)"
        
        for package in "${corrupted_packages[@]}"; do
            print_warning "Corrupted files found in package: $package"
            corrupted_count=$((corrupted_count + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            # Attempt to reinstall with timeout
            print_info "Reinstalling $package..."
            if run_with_timeout $COMMAND_TIMEOUT "apt-get install --reinstall -y $package"; then
                print_success "Successfully reinstalled $package"
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
                
                # Verify the fix
                if timeout 30 debsums -s "$package" 2>/dev/null; then
                    print_success "Verification passed for $package"
                else
                    print_warning "Package reinstalled but verification still shows issues"
                fi
            else
                print_error "Failed to reinstall $package"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
            echo ""
        done
    fi
    
    if [ $corrupted_count -eq 0 ]; then
        print_success "All package files verified successfully"
    fi
}

#############################################################################
# Arch Linux Package System Check
#############################################################################

check_arch_packages() {
    print_header "Checking Arch Linux Package Integrity"
    
    if ! command -v pacman &> /dev/null; then
        print_warning "pacman not found, skipping Arch package check"
        return
    fi
    
    # Update package database and upgrade
    print_info "Updating package database..."
    if run_with_retry $UPDATE_TIMEOUT "pacman -Sy --noconfirm"; then
        print_success "Package database updated"
    else
        print_error "Failed to update package database"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    print_info "Upgrading packages..."
    if run_with_retry $UPDATE_TIMEOUT "pacman -Su --noconfirm"; then
        print_success "Packages upgraded successfully"
    else
        print_error "Failed to upgrade packages"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    print_info "Checking package database..."
    
    # Check package database integrity
    if ! run_with_timeout $COMMAND_TIMEOUT "pacman -Dk"; then
        print_warning "Package database issues detected"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        print_info "Attempting to repair package database..."
        if run_with_retry $COMMAND_TIMEOUT "pacman -Sy --noconfirm"; then
            print_success "Package database repaired"
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        else
            print_error "Failed to repair package database"
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    fi
    
    # Verify installed packages
    print_info "Verifying installed packages..."
    # pacman -Qk outputs: "package-name: /path/to/file (status)"
    # Extract package names (first field before colon) from lines with warnings/errors
    # Filter out common false positives (optional files, moved files, cache files)
    local corrupted_packages=$(timeout 1800 pacman -Qk 2>&1 | grep -E "warning|error" | \
        grep -vE "\.pyc$|\.pyo$|\.cache|\.log$|LICENSE|dictionaries|hyphenation|rust-objcopy|libonnxruntime|\.tmp" | \
        sed 's/:.*//' | sort -u || true)
    
    if [ -n "$corrupted_packages" ]; then
        print_warning "Found potentially corrupted packages:"
        echo "$corrupted_packages"
        
        while IFS= read -r package; do
            [ -z "$package" ] && continue  # Skip empty lines
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            print_info "Reinstalling $package..."
            
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $package" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Successfully reinstalled $package"
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
                
                # Verify if issue persists after reinstall
                sleep 1
                if pacman -Qk "$package" 2>&1 | grep -qE "warning|error"; then
                    print_warning "Package $package still shows issues after reinstall (may be false positive)"
                fi
            else
                print_error "Failed to reinstall $package"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        done <<< "$corrupted_packages"
    else
        print_success "All packages verified successfully"
    fi
}

#############################################################################
# Fedora/RHEL Package System Check
#############################################################################

check_fedora_packages() {
    print_header "Checking Fedora/RHEL Package Integrity"
    
    if ! command -v dnf &> /dev/null && ! command -v rpm &> /dev/null; then
        print_warning "dnf/rpm not found, skipping Fedora package check"
        return
    fi
    
    # Update and upgrade packages
    if command -v dnf &> /dev/null; then
        print_info "Checking for package updates..."
        if run_with_timeout $COMMAND_TIMEOUT "dnf check-update"; then
            print_info "No updates available"
        else
            print_info "Updates available, upgrading packages..."
            if run_with_retry $UPDATE_TIMEOUT "dnf upgrade -y"; then
                print_success "Packages upgraded successfully"
            else
                print_error "Failed to upgrade packages"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        fi
    fi
    
    print_info "Verifying RPM database..."
    
    # Verify RPM database
    if ! run_with_timeout $COMMAND_TIMEOUT "rpm --rebuilddb"; then
        print_warning "RPM database issues detected"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    # Check for problems
    print_info "Checking for package problems..."
    if command -v dnf &> /dev/null; then
        if run_with_timeout $COMMAND_TIMEOUT "dnf check" 2>&1 | grep -q "Error"; then
            print_warning "Package issues detected"
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            print_info "Attempting to repair..."
            if run_with_retry $COMMAND_TIMEOUT "dnf check"; then
                print_success "Package issues resolved"
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            else
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        fi
    fi
    
    # Verify package integrity
    print_info "Verifying package files (this may take a while)..."
    local corrupted_count=0
    local package_count=$(rpm -qa | wc -l)
    local current=0
    
    while IFS= read -r package; do
        current=$((current + 1))
        
        # Show progress every 50 packages
        if [ $((current % 50)) -eq 0 ]; then
            echo -ne "\r⏳ Checked $current/$package_count packages..."
        fi
        
        if ! timeout 30 rpm -V "$package" 2>/dev/null; then
            print_warning "Corrupted files in package: $package"
            corrupted_count=$((corrupted_count + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            if command -v dnf &> /dev/null; then
                print_info "Reinstalling $package..."
                if run_with_timeout $COMMAND_TIMEOUT "dnf reinstall -y $package"; then
                    print_success "Successfully reinstalled $package"
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                else
                    print_error "Failed to reinstall $package"
                    TOTAL_FAILED=$((TOTAL_FAILED + 1))
                fi
            fi
        fi
    done < <(rpm -qa)
    
    echo -ne "\r"  # Clear progress line
    print_success "Scanned $package_count packages"
    
    if [ $corrupted_count -eq 0 ]; then
        print_success "All package files verified successfully"
    fi
}

#############################################################################
# Snap Package Check
#############################################################################

check_snap_packages() {
    print_header "Checking Snap Packages"
    
    if ! command -v snap &> /dev/null; then
        print_warning "Snap not installed, skipping snap check"
        return
    fi
    
    print_info "Updating snap packages..."
    if run_with_retry $UPDATE_TIMEOUT "snap refresh"; then
        print_success "Snap packages updated"
    else
        print_error "Failed to update snap packages"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    print_info "Checking snap health..."
    local broken_snaps=$(snap list 2>&1 | grep -i "broken\|error" || true)
    
    if [ -n "$broken_snaps" ]; then
        print_warning "Found problematic snaps:"
        echo "$broken_snaps"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        # Try to repair
        print_info "Attempting to repair snaps..."
        if run_with_timeout $COMMAND_TIMEOUT "snap repair"; then
            print_success "Snap repair completed"
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        else
            print_error "Snap repair failed"
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    else
        print_success "All snap packages healthy"
    fi
}

#############################################################################
# Flatpak Package Check
#############################################################################

check_flatpak_packages() {
    print_header "Checking Flatpak Packages"
    
    if ! command -v flatpak &> /dev/null; then
        print_warning "Flatpak not installed, skipping flatpak check"
        return
    fi
    
    print_info "Updating flatpak packages..."
    if run_with_retry $UPDATE_TIMEOUT "flatpak update -y"; then
        print_success "Flatpak packages updated"
    else
        print_error "Failed to update flatpak packages"
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    print_info "Repairing flatpak user installation..."
    if run_with_timeout $COMMAND_TIMEOUT "flatpak repair --user"; then
        print_success "Flatpak user installation repaired"
    else
        print_warning "Flatpak user repair had issues"
    fi
    
    print_info "Repairing flatpak system installation..."
    if run_with_timeout $COMMAND_TIMEOUT "flatpak repair --system"; then
        print_success "Flatpak system installation repaired"
    else
        print_warning "Flatpak system repair had issues"
    fi
}

#############################################################################
# Filesystem Check
#############################################################################

check_filesystem() {
    print_header "Checking Filesystem Integrity"
    
    print_info "Checking root filesystem (read-only check)..."
    
    # Get root filesystem device
    local root_device=$(findmnt -n -o SOURCE /)
    
    if [ -n "$root_device" ]; then
        print_info "Root device: $root_device"
        
        # Schedule fsck on next boot for ext filesystems
        if file -sL "$root_device" | grep -q "ext[2-4]"; then
            print_warning "Scheduling filesystem check on next reboot..."
            touch /forcefsck
            print_info "Filesystem will be checked on next reboot"
        fi
    fi
    
    # Check for filesystem errors in logs
    if dmesg | grep -i "filesystem error\|ext[2-4]-fs error" | tail -5; then
        print_warning "Filesystem errors detected in system log"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    fi
}

#############################################################################
# Kernel Module Check
#############################################################################

check_kernel_modules() {
    print_header "Checking Kernel Modules"
    
    print_info "Verifying kernel module dependencies..."
    
    if depmod -a 2>&1 | tee -a "$LOG_FILE"; then
        print_success "Kernel module dependencies updated"
    else
        print_error "Failed to update kernel module dependencies"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
    
    # Check for module load errors
    print_info "Checking for module loading errors..."
    local module_errors=$(dmesg | grep -i "module.*error\|failed to load" | tail -10 || true)
    
    if [ -n "$module_errors" ]; then
        print_warning "Kernel module errors detected:"
        echo "$module_errors" | head -5
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    else
        print_success "No kernel module errors detected"
    fi
}

#############################################################################
# System Libraries Check
#############################################################################

check_system_libraries() {
    print_header "Checking System Libraries"
    
    print_info "Updating dynamic linker cache..."
    
    if ldconfig 2>&1 | tee -a "$LOG_FILE"; then
        print_success "Dynamic linker cache updated"
    else
        print_error "Failed to update linker cache"
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        TOTAL_FAILED=$((TOTAL_FAILED + 1))
    fi
}

#############################################################################
# Drive Health Check and Repair
#############################################################################

explain_drive_type() {
    local drive_type=$1
    
    if [ "$drive_type" = "ssd" ]; then
        print_user_friendly "This is an SSD (Solid State Drive) - a fast modern storage device with no moving parts."
        print_user_friendly "SSDs need regular 'TRIM' operations to maintain their speed and lifespan."
    elif [ "$drive_type" = "hdd" ]; then
        print_user_friendly "This is an HDD (Hard Disk Drive) - a traditional storage device with spinning disks."
        print_user_friendly "HDDs can develop 'bad sectors' (damaged areas) that need to be marked and avoided."
    else
        print_user_friendly "This is a standard storage device."
    fi
}

get_drive_type() {
    local device=$1
    local base_device=$(basename "$device" | sed 's/[0-9]*$//')
    
    # Check if it's a rotating device (HDD = 1, SSD = 0)
    if [ -f "/sys/block/$base_device/queue/rotational" ]; then
        local rotational=$(cat "/sys/block/$base_device/queue/rotational" 2>/dev/null)
        if [ "$rotational" = "0" ]; then
            echo "ssd"
        else
            echo "hdd"
        fi
    else
        echo "unknown"
    fi
}

check_smart_available() {
    local device=$1
    
    if ! command -v smartctl &> /dev/null; then
        print_warning "SMART monitoring tools not installed. Installing smartmontools..."
        
        case "$DISTRO" in
            ubuntu|debian|linuxmint|pop)
                apt-get install -y smartmontools 2>&1 | tee -a "$LOG_FILE" || return 1
                ;;
            arch|manjaro|endeavouros)
                pacman -S --noconfirm smartmontools 2>&1 | tee -a "$LOG_FILE" || return 1
                ;;
            fedora|rhel|centos|rocky|almalinux)
                dnf install -y smartmontools 2>&1 | tee -a "$LOG_FILE" || return 1
                ;;
        esac
    fi
    
    return 0
}

check_drive_health() {
    print_header "Checking Storage Drive Health"
    
    print_user_friendly "Now checking your storage drives (hard disks and SSDs) for any problems..."
    print_user_friendly "This is like taking your drive to the doctor for a checkup!"
    
    # Get all physical drives (not partitions) and store globally
    DETECTED_DRIVES=$(lsblk -d -n -o NAME,TYPE | grep "disk" | awk '{print $1}')
    
    if [ -z "$DETECTED_DRIVES" ]; then
        print_warning "No drives found to check"
        return
    fi
    
    for drive in $DETECTED_DRIVES; do
        local device="/dev/$drive"
        echo ""
        print_header "Checking Drive: $device"
        
        # Determine drive type
        local drive_type=$(get_drive_type "$device")
        explain_drive_type "$drive_type"
        
        # Check SMART capability
        if ! check_smart_available "$device"; then
            print_warning "Could not install SMART tools, skipping detailed health check for $device"
            continue
        fi
        
        # Basic SMART health check
        print_info "Running health diagnostics on $device..."
        print_user_friendly "Checking if the drive reports any problems..."
        
        if timeout 120 smartctl -H "$device" &>/dev/null; then
            local smart_status=$(smartctl -H "$device" 2>/dev/null | grep -i "SMART overall-health" | awk '{print $NF}')
            
            if echo "$smart_status" | grep -qi "PASSED\|OK"; then
                print_success "Drive $device reports healthy status!"
                print_user_friendly "Good news! This drive says it's feeling healthy."
            else
                print_error "Drive $device may have health issues!"
                print_user_friendly "Warning! This drive is reporting some concerns. We'll investigate further."
                DRIVE_ISSUES=$((DRIVE_ISSUES + 1))
            fi
        fi
        
        # Check for bad sectors (HDD) or wear (SSD)
        if [ "$drive_type" = "hdd" ]; then
            check_hdd_bad_sectors "$device"
        elif [ "$drive_type" = "ssd" ]; then
            check_ssd_trim "$device"
            check_ssd_wear "$device"
        fi
    done
}

check_ssd_trim() {
    local device=$1
    
    print_info "Checking TRIM support on SSD: $device"
    print_user_friendly "Checking if TRIM is enabled for optimal SSD performance..."
    
    # Check if TRIM is enabled
    if hdparm -I "$device" 2>/dev/null | grep -qi "TRIM supported"; then
        print_info "TRIM is supported by this SSD"
        
        # Check if filesystem supports TRIM
        local mount_point=$(findmnt -n -o TARGET "$device" 2>/dev/null | head -1)
        if [ -n "$mount_point" ]; then
            local fstype=$(findmnt -n -o FSTYPE "$device" 2>/dev/null | head -1)
            if [ "$fstype" = "ext4" ] || [ "$fstype" = "btrfs" ] || [ "$fstype" = "xfs" ] || [ "$fstype" = "f2fs" ]; then
                print_success "Filesystem $fstype supports TRIM"
                
                # Try to run fstrim
                if command -v fstrim &> /dev/null; then
                    print_info "Running TRIM on $mount_point..."
                    if run_with_timeout $COMMAND_TIMEOUT "fstrim -v $mount_point" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "TRIM completed successfully"
                        DRIVE_FIXED=$((DRIVE_FIXED + 1))
                    else
                        print_warning "TRIM operation had issues"
                    fi
                fi
            fi
        fi
    else
        print_warning "TRIM not supported or not enabled for $device"
    fi
}

check_ssd_wear() {
    local device=$1
    
    print_info "Checking SSD wear level on: $device"
    print_user_friendly "Checking how much of your SSD's lifespan has been used..."
    
    # Check for wear level indicator (if available)
    local wear_level=$(smartctl -A "$device" 2>/dev/null | grep -iE "Wear_Leveling_Count|Media_Wearout_Indicator|Wear_Level|Percent_Lifetime_Remain" | head -1)
    
    if [ -n "$wear_level" ]; then
        local wear_value=$(echo "$wear_level" | awk '{print $10}')
        if [ -n "$wear_value" ] && [ "$wear_value" -lt 10 ]; then
            print_warning "SSD wear level is low: $wear_value% remaining"
            print_user_friendly "Your SSD has used most of its lifespan. Consider backing up your data and replacing the drive soon."
            DRIVE_ISSUES=$((DRIVE_ISSUES + 1))
        else
            print_success "SSD wear level is acceptable"
        fi
    else
        print_info "Wear level information not available for this SSD"
    fi
}

check_hdd_bad_sectors() {
    local device=$1
    
    print_info "Checking for bad sectors on HDD: $device"
    print_user_friendly "Scanning for damaged areas on your hard drive..."
    print_user_friendly "Think of this like checking a road for potholes."
    
    # Check for reallocated sectors (sign of bad sectors)
    local reallocated=$(smartctl -A "$device" 2>/dev/null | grep -i "Reallocated_Sector" | awk '{print $10}')
    local pending=$(smartctl -A "$device" 2>/dev/null | grep -i "Current_Pending_Sector" | awk '{print $10}')
    
    if [ -n "$reallocated" ] && [ "$reallocated" -gt 0 ]; then
        print_warning "Found $reallocated reallocated sectors on $device"
        print_user_friendly "The drive has found and marked $reallocated bad spots to avoid using them."
        DRIVE_ISSUES=$((DRIVE_ISSUES + 1))
    fi
    
    if [ -n "$pending" ] && [ "$pending" -gt 0 ]; then
        print_warning "Found $pending pending sectors that may be bad on $device"
        print_user_friendly "There are $pending suspicious spots that need attention."
        DRIVE_ISSUES=$((DRIVE_ISSUES + 1))
        
        # Attempt to force reallocation by running a read test
        print_info "Attempting to fix bad sectors on $device..."
        print_user_friendly "Trying to repair or mark these bad spots automatically..."
        print_user_friendly "The drive will move your data away from damaged areas to safe spots."
        
        # Use badblocks in non-destructive mode to force sector reallocation
        if run_with_timeout $DRIVE_CHECK_TIMEOUT "badblocks -nsv $device" 2>&1 | tee -a "$LOG_FILE"; then
            print_success "Bad sector repair process completed for $device"
            print_user_friendly "Done! The drive has been instructed to avoid problem areas."
            DRIVE_FIXED=$((DRIVE_FIXED + 1))
        else
            print_error "Could not complete bad sector repair for $device"
            print_user_friendly "The repair didn't complete. You may want to backup your data soon."
            print_user_friendly "Consider replacing this drive if you see this message often."
        fi
    else
        print_success "No bad sectors detected on $device"
        print_user_friendly "Great! No damaged spots found on this drive."
    fi
}

#############################################################################
# Desktop Environment / Window Manager Detection
#############################################################################

detect_desktop_environment() {
    local de=""
    
    # Check for desktop environment
    if [ -n "${XDG_CURRENT_DESKTOP:-}" ]; then
        de=$(echo "$XDG_CURRENT_DESKTOP" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')
    elif [ -n "${DESKTOP_SESSION:-}" ]; then
        de=$(echo "$DESKTOP_SESSION" | tr '[:upper:]' '[:lower:]')
    elif [ -n "${GDMSESSION:-}" ]; then
        de=$(echo "$GDMSESSION" | tr '[:upper:]' '[:lower:]')
    fi
    
    # Additional checks
    if [ -z "$de" ] || [ "$de" = "default" ]; then
        # Check running processes
        if pgrep -x "gnome-session" > /dev/null; then
            de="gnome"
        elif pgrep -x "kwin" > /dev/null || pgrep -x "plasmashell" > /dev/null; then
            de="kde"
        elif pgrep -x "xfce4-session" > /dev/null; then
            de="xfce"
        elif pgrep -x "lxde-session" > /dev/null; then
            de="lxde"
        elif pgrep -x "mate-session" > /dev/null; then
            de="mate"
        elif pgrep -x "cinnamon-session" > /dev/null; then
            de="cinnamon"
        elif pgrep -x "cosmic" > /dev/null || pgrep -x "cosmic-session" > /dev/null; then
            de="cosmic"
        fi
    fi
    
    # Window manager detection if no DE found
    if [ -z "$de" ] || [ "$de" = "default" ]; then
        if pgrep -x "i3" > /dev/null; then
            de="i3"
        elif pgrep -x "sway" > /dev/null; then
            de="sway"
        elif pgrep -x "dwm" > /dev/null; then
            de="dwm"
        elif pgrep -x "awesome" > /dev/null; then
            de="awesome"
        elif pgrep -x "openbox" > /dev/null; then
            de="openbox"
        elif pgrep -x "bspwm" > /dev/null; then
            de="bspwm"
        elif pgrep -x "herbstluftwm" > /dev/null; then
            de="herbstluftwm"
        fi
    fi
    
    echo "${de:-unknown}"
}

#############################################################################
# Arch Linux Setup Functions
#############################################################################

# Ask a yes/no question (defaults to yes)
prompt_yes_no() {
    local prompt="$1"
    local default_yes="${2:-true}"
    local reply=""
    while true; do
        if [ "$default_yes" = "true" ]; then
            echo -ne "${YELLOW}${prompt} [Y/n]: ${NC}"
        else
            echo -ne "${YELLOW}${prompt} [y/N]: ${NC}"
        fi
        read -r reply || reply=""
        reply=$(echo "${reply:-}" | tr '[:upper:]' '[:lower:]')
        if [ -z "$reply" ]; then
            [ "$default_yes" = "true" ] && return 0 || return 1
        fi
        case "$reply" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) print_warning "Please answer y or n." ;;
        esac
    done
}

# Create/replace a sysctl setting in a sysctl.d drop-in file
ensure_sysctl_setting() {
    local key="$1"
    local value="$2"
    local file="${3:-/etc/sysctl.d/99-linux-integrity-repair.conf}"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
    sysctl -w "${key}=${value}" &>/dev/null || true
}

# Ensure a limits.d line exists (domain type item value)
ensure_limits_line() {
    local domain="$1"
    local ltype="$2"
    local item="$3"
    local value="$4"
    local file="${5:-/etc/security/limits.d/99-linux-integrity-repair.conf}"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    local line="${domain} ${ltype} ${item} ${value}"
    if ! grep -qF "$line" "$file"; then
        echo "$line" >> "$file"
    fi
}

# Check if pacman package is available in repos
pacman_package_available() {
    pacman -Si "$1" &>/dev/null
}

# Check if Flatpak app is installed
check_flatpak_app_installed() {
    local app=$1
    if command -v flatpak &> /dev/null; then
        flatpak list --app --columns=application 2>/dev/null | grep -q "^$app$" && return 0
    fi
    return 1
}

# Check if Flatpak app exists in flathub
check_flatpak_app_available() {
    if command -v flatpak &> /dev/null; then
        flatpak remote-info --show-commit flathub "$1" &>/dev/null
        return $?
    fi
    return 1
}

# Install a pacman package only if it exists and isn't already installed
install_pacman_if_available() {
    local pkg="$1"
    local reason="${2:-Installing ${pkg}}"
    if ! pacman_package_available "$pkg"; then
        print_warning "Package $pkg not found in repositories, skipping"
        return 0
    fi
    if pacman -Qi "$pkg" &>/dev/null; then
        print_info "$pkg is already installed"
        return 0
    fi
    print_info "$reason..."
    if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $pkg"; then
        print_success "Installed $pkg"
        return 0
    fi
    print_warning "Failed to install $pkg"
    # Non-fatal: we warn but don't propagate error to avoid tripping ERR trap
    return 0
}

# Arch: apply safe gaming optimizations (reversible via drop-in files)
optimize_arch_gaming() {
    print_header "Gaming Optimization (Arch)"

    print_user_friendly "These tweaks are applied via drop-in config files so you can undo them easily."
    print_user_friendly "Files used:"
    print_user_friendly "- /etc/sysctl.d/99-linux-integrity-repair.conf"
    print_user_friendly "- /etc/security/limits.d/99-linux-integrity-repair.conf"

    if ! prompt_yes_no "Apply gaming optimizations now?" true; then
        print_info "Skipped gaming optimizations."
        return 0
    fi

    # Helpful packages for gaming diagnostics/overlay (optional)
    install_pacman_if_available "gamemode" "Installing GameMode"
    install_pacman_if_available "mangohud" "Installing MangoHud"
    install_pacman_if_available "lib32-mangohud" "Installing lib32 MangoHud"
    install_pacman_if_available "goverlay" "Installing GOverlay"
    install_pacman_if_available "vulkan-tools" "Installing Vulkan tools"

    # Sysctl tweaks (safe defaults)
    ensure_sysctl_setting "vm.swappiness" "10"
    ensure_sysctl_setting "fs.inotify.max_user_watches" "524288"
    ensure_sysctl_setting "fs.inotify.max_user_instances" "1024"

    # Limits (helps launchers/games that open many files)
    ensure_limits_line "*" "soft" "nofile" "1048576"
    ensure_limits_line "*" "hard" "nofile" "1048576"

    print_success "Gaming optimizations applied."
    print_info "Some changes may require re-login or reboot to fully take effect."
}

# Arch: apply development optimizations (reversible via drop-in files)
optimize_arch_development() {
    print_header "Development Optimization (Arch)"

    print_user_friendly "These tweaks help with large repos, file watchers, and IDEs."
    print_user_friendly "Files used:"
    print_user_friendly "- /etc/sysctl.d/99-linux-integrity-repair.conf"
    print_user_friendly "- /etc/security/limits.d/99-linux-integrity-repair.conf"

    if ! prompt_yes_no "Apply development optimizations now?" true; then
        print_info "Skipped development optimizations."
        return 0
    fi

    # Useful debugging/dev tools (optional)
    install_pacman_if_available "lsof" "Installing lsof"
    install_pacman_if_available "strace" "Installing strace"
    install_pacman_if_available "ripgrep" "Installing ripgrep"

    # Sysctl tweaks for file watchers / tooling
    ensure_sysctl_setting "fs.inotify.max_user_watches" "524288"
    ensure_sysctl_setting "fs.inotify.max_user_instances" "1024"
    ensure_sysctl_setting "vm.max_map_count" "1048576"

    # Limits for editors/compilers (many open files)
    ensure_limits_line "*" "soft" "nofile" "1048576"
    ensure_limits_line "*" "hard" "nofile" "1048576"

    print_success "Development optimizations applied."
    print_info "Some changes may require re-login or reboot to fully take effect."
}

# Install essential tools
install_arch_essentials() {
    print_header "Installing Essential Tools"
    
    local packages=(
        "vim" "git" "grep" "curl" "wget" "unrar" "p7zip" "zip" "unzip"
        "base-devel" "reflector" "pacman-contrib"
    )
    
    for package in "${packages[@]}"; do
        if ! pacman -Qi "$package" &> /dev/null; then
            print_info "Installing $package..."
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $package" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Installed $package"
            else
                print_warning "Failed to install $package (may already be installed or unavailable)"
            fi
        else
            print_info "$package is already installed"
        fi
    done
}

# Install gaming tools
install_arch_gaming_tools() {
    print_header "Installing Gaming Tools"
    
    local packages=(
        "wine" "wine-gecko" "wine-mono" "lutris" "steam"
        "gamemode" "lib32-gamemode" "lib32-mesa" "vulkan-radeon" "lib32-vulkan-radeon"
    )
    
    for package in "${packages[@]}"; do
        install_pacman_if_available "$package" "Installing $package"
    done
}

# Install controller / gamepad support
install_arch_controller_support() {
    print_header "Installing Controller / Gamepad Support"

    print_user_friendly "Adding packages and udev rules to improve game controller support."

    # Core controller / game-device packages (if available)
    install_pacman_if_available "game-devices-udev" "Installing generic game device udev rules"
    install_pacman_if_available "steam-devices" "Installing Steam controller udev rules"
    install_pacman_if_available "xboxdrv" "Installing Xbox controller driver (xboxdrv)"

    # Attempt to reload udev rules (non-fatal)
    if command -v udevadm &> /dev/null; then
        print_info "Reloading udev rules for controllers..."
        udevadm control --reload-rules &>/dev/null || true
        udevadm trigger &>/dev/null || true
    fi

    print_success "Controller support packages processed (see log for any skipped/unavailable packages)."
}

# Install and configure Flatpak
install_arch_flatpak() {
    print_header "Installing and Configuring Flatpak"
    
    # Install Flatpak
    if ! command -v flatpak &> /dev/null; then
        print_info "Installing Flatpak..."
        if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm flatpak" 2>&1 | tee -a "$LOG_FILE"; then
            print_success "Flatpak installed"
        else
            print_error "Failed to install Flatpak"
            return 1
        fi
    else
        print_info "Flatpak is already installed"
    fi
    
    # Add Flathub repository
    print_info "Adding Flathub repository..."
    if run_with_timeout $COMMAND_TIMEOUT "flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo" 2>&1 | tee -a "$LOG_FILE"; then
        print_success "Flathub repository added"
    else
        print_warning "Flathub repository may already exist"
    fi
    
    # Install Flatseal for Flatpak management
    if check_flatpak_app_installed "com.github.tchx84.Flatseal"; then
        print_info "Flatseal is already installed"
    else
        print_info "Installing Flatseal..."
        if run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.github.tchx84.Flatseal" 2>&1 | tee -a "$LOG_FILE"; then
            print_success "Flatseal installed"
        else
            print_warning "Failed to install Flatseal (may be unavailable)"
        fi
    fi
}

# Install Flatpak applications
install_arch_flatpak_apps() {
    print_header "Installing Flatpak Applications"
    
    local apps=(
        "io.github.twintails.Twintails"
        "io.github.vikdevelop.ProtonPlus"
        "com.sobere.subtitle-edit"
    )
    
    for app in "${apps[@]}"; do
        if check_flatpak_app_installed "$app"; then
            print_info "$app is already installed"
        elif ! check_flatpak_app_available "$app"; then
            print_warning "$app not found in flathub, skipping"
        else
            print_info "Installing $app..."
            if run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub $app" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Installed $app"
            else
                print_warning "Failed to install $app (may be unavailable)"
            fi
        fi
    done
}

# Install documentation tools
install_arch_documentation() {
    print_header "Installing Documentation Tools"
    
    local packages=(
        "libreoffice-fresh" "obsidian"
    )
    
    for package in "${packages[@]}"; do
        if ! pacman -Qi "$package" &> /dev/null 2>&1; then
            print_info "Installing $package..."
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $package" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Installed $package"
            else
                print_warning "Failed to install $package (may be unavailable, trying AUR or Flatpak)"
                # Try Flatpak for Obsidian if pacman fails
                if [ "$package" = "obsidian" ]; then
                    run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub md.obsidian.Obsidian" 2>&1 | tee -a "$LOG_FILE" || true
                fi
            fi
        else
            print_info "$package is already installed"
        fi
    done
}

# Install development tools
install_arch_development() {
    print_header "Installing Development Tools"
    
    local packages=(
        "code" "neovim" "python" "nodejs" "npm" "rust" "go"
    )
    
    for package in "${packages[@]}"; do
        if ! pacman -Qi "$package" &> /dev/null 2>&1; then
            print_info "Installing $package..."
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $package" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Installed $package"
            else
                print_warning "Failed to install $package via pacman (may be unavailable)"
                # Try Flatpak for VS Code if pacman fails
                if [ "$package" = "code" ]; then
                    run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.visualstudio.code" 2>&1 | tee -a "$LOG_FILE" || true
                fi
            fi
        else
            print_info "$package is already installed"
        fi
    done
}

# Install multimedia tools
install_arch_multimedia() {
    print_header "Installing Multimedia Tools"
    
    local packages=(
        "vlc" "spotify-launcher"
    )
    
    for package in "${packages[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1; then
            print_info "$package is already installed"
        elif [ "$package" = "spotify-launcher" ] && check_flatpak_app_installed "com.spotify.Client"; then
            print_info "Spotify is already installed (via Flatpak)"
        elif [ "$package" = "vlc" ] && check_flatpak_app_installed "org.videolan.VLC"; then
            print_info "VLC is already installed (via Flatpak)"
        else
            print_info "Installing $package..."
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $package" 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Installed $package"
            else
                print_warning "Failed to install $package via pacman (trying Flatpak)"
                # Try Flatpak alternatives
                if [ "$package" = "spotify-launcher" ]; then
                    if ! check_flatpak_app_installed "com.spotify.Client"; then
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.spotify.Client" 2>&1 | tee -a "$LOG_FILE" || true
                    fi
                elif [ "$package" = "vlc" ]; then
                    if ! check_flatpak_app_installed "org.videolan.VLC"; then
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub org.videolan.VLC" 2>&1 | tee -a "$LOG_FILE" || true
                    fi
                fi
            fi
        fi
    done
}

# Install font packs for international language + emoji support
install_arch_fonts() {
    print_header "Installing Fonts (Multi-language, Web, Emoji)"

    print_user_friendly "Installing font families for many languages, web content, and emoji support."

    # Core font families
    install_pacman_if_available "ttf-dejavu" "Installing DejaVu fonts"
    install_pacman_if_available "ttf-liberation" "Installing Liberation web-compatible fonts"

    # Noto fonts cover huge language ranges
    install_pacman_if_available "noto-fonts" "Installing Noto basic fonts"
    install_pacman_if_available "noto-fonts-cjk" "Installing Noto CJK (Chinese/Japanese/Korean) fonts"
    install_pacman_if_available "noto-fonts-emoji" "Installing Noto Emoji fonts"
    install_pacman_if_available "noto-fonts-extra" "Installing Noto extra language fonts"

    print_success "Font installation step completed (see log for any skipped/unavailable fonts)."
}

# Install browser with user selection
install_arch_browser() {
    print_header "Browser Installation"
    
    echo ""
    echo -e "${CYAN}Please select a browser to install:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Firefox (Recommended, Open Source)"
    echo -e "  ${GREEN}2)${NC} Chromium (Open Source)"
    echo -e "  ${GREEN}3)${NC} Google Chrome (Proprietary)"
    echo -e "  ${GREEN}4)${NC} Brave Browser (Privacy-focused)"
    echo -e "  ${GREEN}5)${NC} Opera Browser"
    echo -e "  ${GREEN}6)${NC} Microsoft Edge"
    echo -e "  ${GREEN}7)${NC} Vivaldi Browser"
    echo -e "  ${GREEN}8)${NC} Skip browser installation"
    echo ""
    echo -ne "${YELLOW}Enter your choice [1-8]: ${NC}"
    read -r browser_choice
    
    case "$browser_choice" in
        1)
            print_info "Installing Firefox..."
            if ! pacman -Qi firefox &> /dev/null 2>&1; then
                if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm firefox" 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Firefox installed successfully"
                else
                    print_error "Failed to install Firefox"
                fi
            else
                print_info "Firefox is already installed"
            fi
            ;;
        2)
            print_info "Installing Chromium..."
            if ! pacman -Qi chromium &> /dev/null 2>&1; then
                if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm chromium" 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Chromium installed successfully"
                else
                    print_error "Failed to install Chromium"
                fi
            else
                print_info "Chromium is already installed"
            fi
            ;;
        3)
            print_info "Installing Google Chrome..."
            # Check if yay or paru is available for AUR packages
            if command -v yay &> /dev/null || command -v paru &> /dev/null; then
                local aur_helper="yay"
                if ! command -v yay &> /dev/null; then
                    aur_helper="paru"
                fi
                
                if ! pacman -Qi google-chrome &> /dev/null 2>&1; then
                    print_info "Installing Google Chrome from AUR (this may take a while)..."
                    if run_with_timeout $COMMAND_TIMEOUT "$aur_helper -S --noconfirm google-chrome" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Google Chrome installed successfully"
                    else
                        print_warning "Failed to install Google Chrome from AUR, trying Flatpak..."
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.google.Chrome" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Google Chrome"
                    fi
                else
                    print_info "Google Chrome is already installed"
                fi
            else
                print_warning "AUR helper (yay/paru) not found. Installing Google Chrome via Flatpak..."
                run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.google.Chrome" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Google Chrome"
            fi
            ;;
        4)
            print_info "Installing Brave Browser..."
            if command -v yay &> /dev/null || command -v paru &> /dev/null; then
                local aur_helper="yay"
                if ! command -v yay &> /dev/null; then
                    aur_helper="paru"
                fi
                
                if ! pacman -Qi brave-bin &> /dev/null 2>&1 && ! pacman -Qi brave &> /dev/null 2>&1; then
                    print_info "Installing Brave Browser from AUR..."
                    if run_with_timeout $COMMAND_TIMEOUT "$aur_helper -S --noconfirm brave-bin" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Brave Browser installed successfully"
                    else
                        print_warning "Failed to install Brave from AUR, trying Flatpak..."
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.brave.Browser" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Brave Browser"
                    fi
                else
                    print_info "Brave Browser is already installed"
                fi
            else
                print_warning "AUR helper not found. Installing Brave Browser via Flatpak..."
                run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.brave.Browser" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Brave Browser"
            fi
            ;;
        5)
            print_info "Installing Opera Browser..."
            if command -v yay &> /dev/null || command -v paru &> /dev/null; then
                local aur_helper="yay"
                if ! command -v yay &> /dev/null; then
                    aur_helper="paru"
                fi
                
                if ! pacman -Qi opera &> /dev/null 2>&1; then
                    print_info "Installing Opera Browser from AUR..."
                    if run_with_timeout $COMMAND_TIMEOUT "$aur_helper -S --noconfirm opera" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Opera Browser installed successfully"
                    else
                        print_warning "Failed to install Opera from AUR, trying Flatpak..."
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.opera.Opera" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Opera Browser"
                    fi
                else
                    print_info "Opera Browser is already installed"
                fi
            else
                print_warning "AUR helper not found. Installing Opera Browser via Flatpak..."
                run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.opera.Opera" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Opera Browser"
            fi
            ;;
        6)
            print_info "Installing Microsoft Edge..."
            if command -v yay &> /dev/null || command -v paru &> /dev/null; then
                local aur_helper="yay"
                if ! command -v yay &> /dev/null; then
                    aur_helper="paru"
                fi
                
                if ! pacman -Qi microsoft-edge-stable-bin &> /dev/null 2>&1; then
                    print_info "Installing Microsoft Edge from AUR..."
                    if run_with_timeout $COMMAND_TIMEOUT "$aur_helper -S --noconfirm microsoft-edge-stable-bin" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Microsoft Edge installed successfully"
                    else
                        print_error "Failed to install Microsoft Edge"
                    fi
                else
                    print_info "Microsoft Edge is already installed"
                fi
            else
                print_warning "AUR helper (yay/paru) not found. Microsoft Edge requires AUR. Skipping..."
            fi
            ;;
        7)
            print_info "Installing Vivaldi Browser..."
            if command -v yay &> /dev/null || command -v paru &> /dev/null; then
                local aur_helper="yay"
                if ! command -v yay &> /dev/null; then
                    aur_helper="paru"
                fi
                
                if ! pacman -Qi vivaldi &> /dev/null 2>&1; then
                    print_info "Installing Vivaldi Browser from AUR..."
                    if run_with_timeout $COMMAND_TIMEOUT "$aur_helper -S --noconfirm vivaldi" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Vivaldi Browser installed successfully"
                    else
                        print_warning "Failed to install Vivaldi from AUR, trying Flatpak..."
                        run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.vivaldi.Vivaldi" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Vivaldi Browser"
                    fi
                else
                    print_info "Vivaldi Browser is already installed"
                fi
            else
                print_warning "AUR helper not found. Installing Vivaldi Browser via Flatpak..."
                run_with_timeout $COMMAND_TIMEOUT "flatpak install -y flathub com.vivaldi.Vivaldi" 2>&1 | tee -a "$LOG_FILE" || print_error "Failed to install Vivaldi Browser"
            fi
            ;;
        8)
            print_info "Skipping browser installation"
            ;;
        *)
            print_warning "Invalid choice. Skipping browser installation."
            ;;
    esac
}

# Pre-check function to show what's already installed
check_arch_installed_packages() {
    print_header "Checking Already Installed Packages"
    
    local installed_count=0
    local to_install_count=0
    local installed_packages=()
    local to_install_packages=()
    
    # Essential tools
    local essentials=("vim" "git" "grep" "curl" "wget" "unrar" "p7zip" "zip" "unzip" "base-devel" "reflector" "pacman-contrib")
    # Gaming tools
    local gaming=("wine" "wine-gecko" "wine-mono" "lutris" "steam" "gamemode" "lib32-gamemode" "lib32-mesa" "vulkan-radeon" "lib32-vulkan-radeon")
    # Documentation tools
    local documentation=("libreoffice-fresh" "obsidian")
    # Development tools
    local development=("code" "neovim" "python" "nodejs" "npm" "rust" "go")
    # Multimedia tools
    local multimedia=("vlc" "spotify-launcher")
    # Flatpak apps
    local flatpak_apps=("io.github.twintails.Twintails" "io.github.vikdevelop.ProtonPlus" "com.sobere.subtitle-edit" "com.github.tchx84.Flatseal")
    
    print_info "Checking essential tools..."
    for package in "${essentials[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1 || command -v "$package" &> /dev/null 2>&1; then
            installed_packages+=("$package")
            installed_count=$((installed_count + 1))
        else
            to_install_packages+=("$package")
            to_install_count=$((to_install_count + 1))
        fi
    done
    
    print_info "Checking gaming tools..."
    for package in "${gaming[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1; then
            installed_packages+=("$package")
            installed_count=$((installed_count + 1))
        else
            to_install_packages+=("$package")
            to_install_count=$((to_install_count + 1))
        fi
    done
    
    print_info "Checking documentation tools..."
    for package in "${documentation[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1; then
            installed_packages+=("$package")
            installed_count=$((installed_count + 1))
        else
            # Check Flatpak for obsidian
            if [ "$package" = "obsidian" ] && check_flatpak_app_installed "md.obsidian.Obsidian"; then
                installed_packages+=("$package (flatpak)")
                installed_count=$((installed_count + 1))
            else
                to_install_packages+=("$package")
                to_install_count=$((to_install_count + 1))
            fi
        fi
    done
    
    print_info "Checking development tools..."
    for package in "${development[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1 || command -v "$package" &> /dev/null 2>&1; then
            installed_packages+=("$package")
            installed_count=$((installed_count + 1))
        else
            # Check Flatpak for code
            if [ "$package" = "code" ] && check_flatpak_app_installed "com.visualstudio.code"; then
                installed_packages+=("$package (flatpak)")
                installed_count=$((installed_count + 1))
            else
                to_install_packages+=("$package")
                to_install_count=$((to_install_count + 1))
            fi
        fi
    done
    
    print_info "Checking multimedia tools..."
    for package in "${multimedia[@]}"; do
        if pacman -Qi "$package" &> /dev/null 2>&1; then
            installed_packages+=("$package")
            installed_count=$((installed_count + 1))
        else
            # Check Flatpak alternatives
            if [ "$package" = "spotify-launcher" ] && check_flatpak_app_installed "com.spotify.Client"; then
                installed_packages+=("spotify (flatpak)")
                installed_count=$((installed_count + 1))
            elif [ "$package" = "vlc" ] && check_flatpak_app_installed "org.videolan.VLC"; then
                installed_packages+=("vlc (flatpak)")
                installed_count=$((installed_count + 1))
            else
                to_install_packages+=("$package")
                to_install_count=$((to_install_count + 1))
            fi
        fi
    done
    
    print_info "Checking Flatpak applications..."
    for app in "${flatpak_apps[@]}"; do
        if check_flatpak_app_installed "$app"; then
            installed_packages+=("$app (flatpak)")
            installed_count=$((installed_count + 1))
        else
            to_install_packages+=("$app (flatpak)")
            to_install_count=$((to_install_count + 1))
        fi
    done
    
    # Check Flatpak itself
    if command -v flatpak &> /dev/null; then
        installed_packages+=("flatpak")
        installed_count=$((installed_count + 1))
    else
        to_install_packages+=("flatpak")
        to_install_count=$((to_install_count + 1))
    fi
    
    # Display summary
    echo ""
    print_header "Installation Pre-Check Summary"
    
    if [ ${#installed_packages[@]} -gt 0 ]; then
        echo ""
        echo -e "${GREEN}Already Installed (${installed_count}):${NC}"
        for pkg in "${installed_packages[@]}"; do
            echo -e "  ${GREEN}✓${NC} $pkg"
        done
    fi
    
    if [ ${#to_install_packages[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Will Be Installed (${to_install_count}):${NC}"
        for pkg in "${to_install_packages[@]}"; do
            echo -e "  ${YELLOW}→${NC} $pkg"
        done
    fi
    
    echo ""
    print_info "Total packages checked: $((installed_count + to_install_count))"
    print_info "Already installed: $installed_count"
    print_info "Will be installed: $to_install_count"
    echo ""
    
    if [ $to_install_count -eq 0 ]; then
        print_success "All packages are already installed!"
    else
        print_info "Proceeding with installation..."
    fi
    return 0
}

# Full Arch Linux setup
perform_arch_setup() {
    print_header "Arch Linux Complete Setup"
    
    local desktop_env=$(detect_desktop_environment)
    print_info "Detected desktop environment/window manager: $desktop_env"
    
    # Pre-check installed packages
    check_arch_installed_packages
    
    # Update system first
    print_info "Updating system..."
    run_with_timeout $UPDATE_TIMEOUT "pacman -Syu --noconfirm" 2>&1 | tee -a "$LOG_FILE" || print_warning "System update had issues"
    
    # Install essentials
    install_arch_essentials
    
    # Install gaming tools
    install_arch_gaming_tools
    install_arch_controller_support
    
    # Install Flatpak and configure
    install_arch_flatpak
    
    # Install Flatpak applications
    install_arch_flatpak_apps
    
    # Install documentation tools
    install_arch_documentation
    
    # Install development tools
    install_arch_development
    
    # Install multimedia tools
    install_arch_multimedia
    
    # Install fonts (multi-language + emoji)
    install_arch_fonts
    
    # Install browser (ask user for selection)
    install_arch_browser
    
    # Check and install wireless drivers (Bluetooth & WiFi)
    print_header "Checking Wireless Drivers"
    print_info "Ensuring Bluetooth and WiFi drivers are properly installed..."
    install_arch_wireless_drivers
    
    print_success "Arch Linux setup completed!"
    print_info "Some applications may need to be installed manually if they're not in the repositories"
}

#############################################################################
# Wireless Driver Troubleshooting and Repair (Arch)
#############################################################################

# Install wireless drivers during setup
install_arch_wireless_drivers() {
    print_header "Installing Wireless Drivers (Bluetooth & WiFi)"
    
    # Always install base packages (they're needed even if hardware isn't detected yet)
    print_info "Installing base wireless driver packages..."
    
    # Bluetooth packages
    local bt_packages=("bluez" "bluez-utils" "bluez-firmware")
    for pkg in "${bt_packages[@]}"; do
        install_pacman_if_available "$pkg" "Installing $pkg"
    done
    
    # WiFi packages
    local wifi_packages=("networkmanager" "wpa_supplicant" "linux-firmware")
    for pkg in "${wifi_packages[@]}"; do
        install_pacman_if_available "$pkg" "Installing $pkg"
    done
    
    # Enable services
    if systemctl is-enabled --quiet bluetooth 2>/dev/null; then
        print_info "Bluetooth service already enabled"
    else
        systemctl enable bluetooth 2>&1 | tee -a "$LOG_FILE" || true
    fi
    
    if systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
        print_info "NetworkManager service already enabled"
    else
        systemctl enable NetworkManager 2>&1 | tee -a "$LOG_FILE" || true
    fi
    
    print_success "Wireless driver packages installed"
}

# Troubleshoot and repair Bluetooth drivers
troubleshoot_bluetooth() {
    print_header "Troubleshooting Bluetooth Drivers"
    
    local bluetooth_issues=0
    local bluetooth_fixed=0
    
    # Check if Bluetooth hardware exists - improved detection
    print_info "Checking for Bluetooth hardware..."
    local bt_devices=$(lsusb | grep -iE "bluetooth|bt|blue" || true)
    local bt_pci=$(lspci | grep -iE "bluetooth|bt|blue" || true)
    local bt_hci=$(hciconfig 2>/dev/null | grep -i "hci" || true)
    
    # Also check dmesg for Bluetooth devices (exclude false positives like Btrfs, systemd)
    # Only look for actual Bluetooth-related messages, not filesystem or systemd messages
    local bt_dmesg=$(dmesg | grep -iE "bluetooth|btusb|btbcm|btintel|btrtl|btmtk|bluez" | \
        grep -viE "btrfs|systemd.*btf|systemd.*\+BTF" | tail -5 || true)
    
    if [ -z "$bt_devices" ] && [ -z "$bt_pci" ] && [ -z "$bt_hci" ]; then
        print_warning "No Bluetooth hardware detected via standard methods."
        if [ -n "$bt_dmesg" ]; then
            print_info "Found Bluetooth-related messages in system log:"
            echo "$bt_dmesg" | head -3
            print_info "Bluetooth hardware may be present but driver not loaded"
        else
            # Try to force detection by checking all USB devices
            print_info "Performing deep scan for Bluetooth hardware..."
            local all_usb=$(lsusb || true)
            if echo "$all_usb" | grep -qiE "realtek|broadcom|intel|qualcomm|mediatek|marvell"; then
                print_info "Found USB devices that may include Bluetooth (combo chips):"
                echo "$all_usb" | grep -iE "realtek|broadcom|intel|qualcomm|mediatek|marvell" | head -5
                print_info "Attempting to load Bluetooth drivers anyway..."
            else
                print_warning "Skipping Bluetooth troubleshooting (no hardware detected)."
                print_info "If you know Bluetooth hardware exists, try: modprobe btusb"
                return 0
            fi
        fi
    fi
    
    if [ -n "$bt_devices" ]; then
        print_info "Found USB Bluetooth device(s):"
        echo "$bt_devices"
    fi
    if [ -n "$bt_pci" ]; then
        print_info "Found PCI Bluetooth device(s):"
        echo "$bt_pci"
    fi
    
    # Check if Bluetooth service is running
    print_info "Checking Bluetooth service status..."
    if systemctl is-active --quiet bluetooth 2>/dev/null; then
        print_success "Bluetooth service is running"
    else
        print_warning "Bluetooth service is not running"
        bluetooth_issues=$((bluetooth_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        print_info "Starting Bluetooth service..."
        if systemctl start bluetooth 2>&1 | tee -a "$LOG_FILE"; then
            print_success "Bluetooth service started"
            bluetooth_fixed=$((bluetooth_fixed + 1))
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        else
            print_warning "Failed to start Bluetooth service"
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    fi
    
    # Check if Bluetooth service is enabled
    if ! systemctl is-enabled --quiet bluetooth 2>/dev/null; then
        print_warning "Bluetooth service is not enabled at boot"
        print_info "Enabling Bluetooth service..."
        if systemctl enable bluetooth 2>&1 | tee -a "$LOG_FILE"; then
            print_success "Bluetooth service enabled"
            bluetooth_fixed=$((bluetooth_fixed + 1))
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        fi
    fi
    
    # Check for Bluetooth kernel modules
    print_info "Checking Bluetooth kernel modules..."
    local bt_modules=("bluetooth" "btusb" "btbcm" "btintel" "btrtl" "btmtk")
    local missing_modules=()
    
    for module in "${bt_modules[@]}"; do
        if ! lsmod | grep -q "^${module} "; then
            missing_modules+=("$module")
        fi
    done
    
    if [ ${#missing_modules[@]} -gt 0 ]; then
        print_warning "Missing Bluetooth kernel modules: ${missing_modules[*]}"
        bluetooth_issues=$((bluetooth_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        print_info "Loading Bluetooth kernel modules..."
        # Try to load btusb first (most common)
        if [[ " ${missing_modules[@]} " =~ " btusb " ]]; then
            if modprobe btusb 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Loaded module: btusb"
                bluetooth_fixed=$((bluetooth_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
                sleep 2  # Give hardware time to initialize
            fi
        fi
        
        # Load other modules
        for module in "${missing_modules[@]}"; do
            if [ "$module" != "btusb" ]; then
                if modprobe "$module" 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Loaded module: $module"
                    bluetooth_fixed=$((bluetooth_fixed + 1))
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                else
                    print_warning "Failed to load module: $module (may not be needed for your hardware)"
                fi
            fi
        done
        
        # Re-check for hardware after loading modules
        sleep 2
        if hciconfig 2>/dev/null | grep -q "hci"; then
            print_success "Bluetooth hardware detected after loading modules!"
        fi
    else
        print_success "All Bluetooth kernel modules are loaded"
    fi
    
    # Install/update Bluetooth packages if needed
    print_info "Checking Bluetooth packages..."
    local bt_packages=("bluez" "bluez-utils" "bluez-firmware")
    
    for pkg in "${bt_packages[@]}"; do
        if ! pacman -Qi "$pkg" &>/dev/null 2>&1; then
            print_warning "Bluetooth package $pkg is not installed"
            bluetooth_issues=$((bluetooth_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            if install_pacman_if_available "$pkg" "Installing $pkg"; then
                bluetooth_fixed=$((bluetooth_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            else
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        fi
    done
    
    # Check for rfkill blocking
    print_info "Checking if Bluetooth is blocked by rfkill..."
    if command -v rfkill &>/dev/null; then
        local blocked=$(rfkill list bluetooth 2>/dev/null | grep -i "yes" || true)
        if [ -n "$blocked" ]; then
            print_warning "Bluetooth is blocked by rfkill"
            bluetooth_issues=$((bluetooth_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            print_info "Unblocking Bluetooth..."
            if rfkill unblock bluetooth 2>&1 | tee -a "$LOG_FILE"; then
                print_success "Bluetooth unblocked"
                bluetooth_fixed=$((bluetooth_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            else
                print_warning "Failed to unblock Bluetooth"
            fi
        else
            print_success "Bluetooth is not blocked"
        fi
    fi
    
    # Final check - try to detect Bluetooth again
    print_info "Final Bluetooth hardware check..."
    if hciconfig 2>/dev/null | grep -q "hci"; then
        print_success "Bluetooth adapter is now detected!"
        local hci_devices=$(hciconfig 2>/dev/null | grep -i "hci" || true)
        echo "$hci_devices"
    elif [ -n "$bt_devices" ] || [ -n "$bt_pci" ] || [ -n "$bt_dmesg" ]; then
        print_warning "Bluetooth hardware detected but adapter not showing up"
        print_info "Try: systemctl restart bluetooth && hciconfig hci0 up"
        print_info "Or check: dmesg | grep -i bluetooth"
    fi
    
    if [ $bluetooth_issues -eq 0 ]; then
        print_success "Bluetooth drivers are working correctly"
    else
        print_info "Bluetooth troubleshooting completed: $bluetooth_fixed issue(s) fixed"
    fi
}

# Troubleshoot and repair WiFi drivers
troubleshoot_wifi() {
    print_header "Troubleshooting WiFi Drivers"
    
    local wifi_issues=0
    local wifi_fixed=0
    
    # Check if WiFi hardware exists
    print_info "Checking for WiFi hardware..."
    local wifi_devices=$(lsusb | grep -iE "network|wireless|wlan|802.11|wifi" || true)
    local wifi_pci=$(lspci | grep -iE "network|wireless|wlan|802.11|wifi" || true)
    
    if [ -z "$wifi_devices" ] && [ -z "$wifi_pci" ]; then
        print_warning "No WiFi hardware detected. Skipping WiFi troubleshooting."
        return 0
    fi
    
    if [ -n "$wifi_devices" ]; then
        print_info "Found USB WiFi device(s):"
        echo "$wifi_devices"
    fi
    if [ -n "$wifi_pci" ]; then
        print_info "Found PCI WiFi device(s):"
        echo "$wifi_pci"
    fi
    
    # Check for WiFi interface
    print_info "Checking for WiFi network interface..."
    local wifi_interface=$(ip link show | grep -iE "wlan|wifi|wlx" | head -1 | awk -F: '{print $2}' | xargs || true)
    
    # Also check using iw/iwconfig
    if [ -z "$wifi_interface" ]; then
        if command -v iw &>/dev/null; then
            wifi_interface=$(iw dev 2>/dev/null | grep -i "Interface" | awk '{print $2}' | head -1 || true)
        fi
    fi
    
    if [ -z "$wifi_interface" ]; then
        print_warning "No WiFi interface found"
        wifi_issues=$((wifi_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        # Check if Realtek USB WiFi is in CDROM mode and needs switching
        if echo "$wifi_devices" | grep -qi "rtl.*cdrom\|driver.*cdrom"; then
            print_warning "WiFi adapter detected but may be in CDROM mode (needs driver switch)"
            print_info "Attempting to switch Realtek USB WiFi from CDROM to WiFi mode..."
            
            # Try to find the device and switch it
            local rtl_device=$(echo "$wifi_devices" | grep -i "rtl" | head -1 | awk '{print $6}' | tr -d ':' || true)
            if [ -n "$rtl_device" ]; then
                print_info "Found Realtek device: $rtl_device"
                # Try using usb_modeswitch or rtl88x2bu driver
                if install_pacman_if_available "usb_modeswitch" "Installing usb_modeswitch"; then
                    wifi_fixed=$((wifi_fixed + 1))
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                fi
                
                # Try loading rtl8xxxu driver (common for Realtek USB WiFi)
                if modprobe rtl8xxxu 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Loaded rtl8xxxu driver"
                    wifi_fixed=$((wifi_fixed + 1))
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                    sleep 3  # Wait for interface to appear
                    
                    # Re-check for interface
                    wifi_interface=$(ip link show | grep -iE "wlan|wifi|wlx" | head -1 | awk -F: '{print $2}' | xargs || true)
                fi
            fi
        fi
    else
        print_success "Found WiFi interface: $wifi_interface"
        
        # Check interface status
        local iface_status=$(ip link show "$wifi_interface" 2>/dev/null | grep -oP "state \K\w+" || echo "unknown")
        if [ "$iface_status" != "UP" ]; then
            print_warning "WiFi interface $wifi_interface is DOWN"
            wifi_issues=$((wifi_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            print_info "Bringing up WiFi interface..."
            if ip link set "$wifi_interface" up 2>&1 | tee -a "$LOG_FILE"; then
                print_success "WiFi interface brought up"
                wifi_fixed=$((wifi_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            else
                print_warning "Failed to bring up WiFi interface"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        fi
    fi
    
    # Check for WiFi kernel modules
    print_info "Checking WiFi kernel modules..."
    local wifi_modules=$(lsmod | grep -iE "wifi|wireless|80211|ath|rtl|iwl|brcm|mt76|rtw88" | awk '{print $1}' || true)
    
    # Check if rtl8xxxu is loaded but wrong driver (for rtw88 devices)
    if echo "$wifi_modules" | grep -q "^rtl8xxxu "; then
        if echo "$wifi_devices" | grep -qE "0bda:(c820|b820|a820)"; then
            print_warning "Wrong driver loaded (rtl8xxxu) for RTL8821CU/8822CU - needs rtw88"
            wifi_issues=$((wifi_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        fi
    fi
    
    if [ -z "$wifi_modules" ] || ! echo "$wifi_modules" | grep -qiE "rtl|ath|iwl|brcm|mt76|rtw88"; then
        print_warning "No WiFi kernel modules loaded (or only generic modules)"
        wifi_issues=$((wifi_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        # Try to identify and load common WiFi drivers
        print_info "Attempting to identify WiFi chipset..."
        
        # Check USB WiFi devices - prioritize Realtek
        local usb_wifi=$(lsusb | grep -iE "network|wireless|wlan|802.11|rtl" | head -1 || true)
        if [ -n "$usb_wifi" ]; then
            print_info "USB WiFi device: $usb_wifi"
            
            # Check for Realtek devices specifically
            if echo "$usb_wifi" | grep -qi "rtl\|realtek"; then
                print_info "Detected Realtek USB WiFi adapter"
                
                # Extract device ID to determine correct driver
                local device_id=$(echo "$usb_wifi" | grep -oP "ID \K[0-9a-f]+:[0-9a-f]+" | head -1 || true)
                print_info "Device ID: $device_id"
                
                # Determine driver based on device ID
                local rtl_drivers=()
                case "$device_id" in
                    *:c820|*:b820|*:a820)  # RTL8821CU/8822CU - needs rtw88 driver
                        print_info "Detected RTL8821CU/8822CU chipset - using rtw88 driver"
                        rtl_drivers=("rtw88_8821cu" "rtw88_8822cu" "rtw88")
                        ;;
                    *:8812|*:8814)  # RTL8812AU/8814AU
                        rtl_drivers=("rtl8812au" "rtl8xxxu")
                        ;;
                    *:8811|*:8821)  # RTL8811AU/8821AU
                        rtl_drivers=("rtl8821au" "rtl8xxxu")
                        ;;
                    *:8192|*:8176)  # RTL8192CU/8176
                        rtl_drivers=("rtl8192cu" "rtl8xxxu")
                        ;;
                    *:8188)  # RTL8188 series
                        rtl_drivers=("rtl8188eu" "rtl8xxxu")
                        ;;
                    *)  # Generic Realtek - try common drivers
                        print_info "Unknown Realtek chipset, trying common drivers"
                        rtl_drivers=("rtw88_8821cu" "rtw88_8822cu" "rtw88" "rtl8xxxu" "rtl88x2bu" "rtl8192cu" "rtl8188eu")
                        ;;
                esac
                
                # Try loading drivers
                for driver in "${rtl_drivers[@]}"; do
                    # Unload conflicting drivers first
                    if lsmod | grep -q "^rtl8xxxu "; then
                        print_info "Unloading conflicting rtl8xxxu driver..."
                        modprobe -r rtl8xxxu 2>&1 | tee -a "$LOG_FILE" || true
                        sleep 1
                    fi
                    if lsmod | grep -q "^rtw88_"; then
                        print_info "Unloading existing rtw88 driver..."
                        modprobe -r rtw88_8821cu rtw88_8822cu rtw88 2>&1 | tee -a "$LOG_FILE" || true
                        sleep 1
                    fi
                    
                    if modprobe "$driver" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Loaded Realtek USB WiFi driver: $driver"
                        wifi_fixed=$((wifi_fixed + 1))
                        TOTAL_FIXED=$((TOTAL_FIXED + 1))
                        sleep 3  # Wait for interface to appear
                        
                        # Re-check for interface
                        wifi_interface=$(ip link show | grep -iE "wlan|wifi|wlx" | head -1 | awk -F: '{print $2}' | xargs || true)
                        if [ -n "$wifi_interface" ]; then
                            print_success "WiFi interface appeared: $wifi_interface"
                            break
                        fi
                    else
                        print_warning "Failed to load $driver, trying next..."
                    fi
                done
            else
                # Common USB WiFi drivers for other brands
                local usb_drivers=("ath9k_htc" "zd1211rw" "rtl8xxxu")
                for driver in "${usb_drivers[@]}"; do
                    if modprobe "$driver" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "Loaded USB WiFi driver: $driver"
                        wifi_fixed=$((wifi_fixed + 1))
                        TOTAL_FIXED=$((TOTAL_FIXED + 1))
                        sleep 3
                        break
                    fi
                done
            fi
        fi
        
        # Check PCI WiFi devices
        local pci_wifi=$(lspci | grep -iE "network|wireless|wlan|802.11" | head -1 || true)
        if [ -n "$pci_wifi" ]; then
            print_info "PCI WiFi device: $pci_wifi"
            # Common PCI WiFi drivers
            local pci_drivers=("iwlwifi" "ath9k" "ath10k_pci" "rtl8180" "rtl8192ce" "b43" "brcmfmac")
            for driver in "${pci_drivers[@]}"; do
                if modprobe "$driver" 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Loaded PCI WiFi driver: $driver"
                    wifi_fixed=$((wifi_fixed + 1))
                    TOTAL_FIXED=$((TOTAL_FIXED + 1))
                    sleep 3
                    break
                fi
            done
        fi
        
        # Re-check for interface after loading drivers
        if [ -z "$wifi_interface" ]; then
            sleep 2
            wifi_interface=$(ip link show | grep -iE "wlan|wifi|wlx" | head -1 | awk -F: '{print $2}' | xargs || true)
            if [ -n "$wifi_interface" ]; then
                print_success "WiFi interface appeared after loading driver: $wifi_interface"
                wifi_fixed=$((wifi_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            fi
        fi
    else
        print_success "WiFi kernel modules are loaded:"
        echo "$wifi_modules" | grep -iE "rtl|ath|iwl|brcm|mt76|rtw88" | head -5
        
        # Check if driver is loaded but interface still missing
        if [ -z "$wifi_interface" ] && echo "$wifi_modules" | grep -qE "rtw88|rtl8xxxu"; then
            print_warning "WiFi driver loaded but no interface found"
            wifi_issues=$((wifi_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            # Check for driver errors in dmesg
            local driver_errors=$(dmesg | grep -iE "rtw88|rtl8xxxu" | grep -iE "error|fail|timeout" | tail -5 || true)
            if [ -n "$driver_errors" ]; then
                print_warning "Found driver errors:"
                echo "$driver_errors" | head -3
                print_info "Attempting to reload driver..."
                
                # Try reloading the driver
                if echo "$wifi_modules" | grep -q "^rtw88_"; then
                    local loaded_rtw=$(lsmod | grep "^rtw88_" | awk '{print $1}' | head -1)
                    if [ -n "$loaded_rtw" ]; then
                        print_info "Reloading $loaded_rtw driver..."
                        modprobe -r "$loaded_rtw" 2>&1 | tee -a "$LOG_FILE" || true
                        sleep 2
                        modprobe "$loaded_rtw" 2>&1 | tee -a "$LOG_FILE" || true
                        sleep 3
                        
                        # Re-check interface
                        wifi_interface=$(ip link show | grep -iE "wlan|wifi|wlx" | head -1 | awk -F: '{print $2}' | xargs || true)
                        if [ -n "$wifi_interface" ]; then
                            print_success "WiFi interface appeared after reload: $wifi_interface"
                            wifi_fixed=$((wifi_fixed + 1))
                            TOTAL_FIXED=$((TOTAL_FIXED + 1))
                        fi
                    fi
                fi
            fi
        fi
    fi
    
    # Check for NetworkManager or wpa_supplicant
    print_info "Checking WiFi management tools..."
    if ! command -v nmcli &>/dev/null && ! command -v wpa_supplicant &>/dev/null; then
        print_warning "No WiFi management tool found (NetworkManager or wpa_supplicant)"
        wifi_issues=$((wifi_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        
        if install_pacman_if_available "networkmanager" "Installing NetworkManager"; then
            wifi_fixed=$((wifi_fixed + 1))
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
            
            # Enable NetworkManager service
            if systemctl enable NetworkManager 2>&1 | tee -a "$LOG_FILE"; then
                systemctl start NetworkManager 2>&1 | tee -a "$LOG_FILE" || true
            fi
        elif install_pacman_if_available "wpa_supplicant" "Installing wpa_supplicant"; then
            wifi_fixed=$((wifi_fixed + 1))
            TOTAL_FIXED=$((TOTAL_FIXED + 1))
        else
            TOTAL_FAILED=$((TOTAL_FAILED + 1))
        fi
    fi
    
    # Check for rfkill blocking
    print_info "Checking if WiFi is blocked by rfkill..."
    if command -v rfkill &>/dev/null; then
        local blocked=$(rfkill list wifi 2>/dev/null | grep -i "yes" || true)
        if [ -n "$blocked" ]; then
            print_warning "WiFi is blocked by rfkill"
            wifi_issues=$((wifi_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            
            print_info "Unblocking WiFi..."
            if rfkill unblock wifi 2>&1 | tee -a "$LOG_FILE"; then
                print_success "WiFi unblocked"
                wifi_fixed=$((wifi_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            else
                print_warning "Failed to unblock WiFi"
            fi
        else
            print_success "WiFi is not blocked"
        fi
    fi
    
    # Install common WiFi firmware if available
    print_info "Checking WiFi firmware packages..."
    local wifi_firmware=("linux-firmware" "linux-firmware-whence")
    
    for fw in "${wifi_firmware[@]}"; do
        if ! pacman -Qi "$fw" &>/dev/null 2>&1; then
            if install_pacman_if_available "$fw" "Installing $fw"; then
                wifi_fixed=$((wifi_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            fi
        fi
    done
    
    if [ $wifi_issues -eq 0 ]; then
        print_success "WiFi drivers are working correctly"
    else
        print_info "WiFi troubleshooting completed: $wifi_fixed issue(s) fixed"
    fi
}

# Troubleshoot both Bluetooth and WiFi
troubleshoot_wireless_drivers() {
    print_header "Troubleshooting Wireless Drivers (Bluetooth & WiFi)"
    
    troubleshoot_bluetooth
    echo ""
    troubleshoot_wifi
    
    print_success "Wireless driver troubleshooting completed"
}

#############################################################################
# Comprehensive System Scan and Vulnerability Check
#############################################################################

# Full system scan for vulnerabilities and corruption
full_system_scan() {
    print_header "Full System Scan - Checking for Vulnerabilities and Corruption"
    
    local scan_issues=0
    local scan_fixed=0
    
    # 1. Check for security vulnerabilities in installed packages
    print_info "Scanning for known security vulnerabilities..."
    if command -v arch-audit &>/dev/null || pacman_package_available "arch-audit"; then
        if ! command -v arch-audit &>/dev/null; then
            install_pacman_if_available "arch-audit" "Installing arch-audit for vulnerability scanning"
        fi
        
        print_info "Running arch-audit to check for vulnerable packages..."
        local vulns=$(arch-audit 2>/dev/null | grep -v "^$" || true)
        if [ -n "$vulns" ]; then
            print_warning "Found potentially vulnerable packages:"
            echo "$vulns" | head -20
            scan_issues=$((scan_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
            print_info "Consider updating these packages: pacman -Syu"
        else
            print_success "No known vulnerabilities found"
        fi
    else
        print_info "arch-audit not available, checking for outdated packages instead..."
        if pacman -Qu 2>/dev/null | grep -q .; then
            local outdated_count=$(pacman -Qu 2>/dev/null | wc -l)
            print_warning "Found $outdated_count outdated packages (may contain security fixes)"
            print_info "Run 'pacman -Syu' to update all packages"
            scan_issues=$((scan_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        else
            print_success "All packages are up to date"
        fi
    fi
    
    # 2. Check for orphaned packages
    print_info "Checking for orphaned packages..."
    local orphaned=$(pacman -Qtdq 2>/dev/null || true)
    if [ -n "$orphaned" ]; then
        local orphaned_count=$(echo "$orphaned" | wc -l)
        print_warning "Found $orphaned_count orphaned package(s):"
        echo "$orphaned" | head -10
        scan_issues=$((scan_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        print_info "You can remove them with: pacman -Rns \$(pacman -Qtdq)"
    else
        print_success "No orphaned packages found"
    fi
    
    # 3. Check for broken symlinks
    print_info "Scanning for broken symlinks in system directories..."
    local broken_links=$(find /usr /etc /bin /sbin /lib /lib64 -type l ! -exec test -e {} \; -print 2>/dev/null | head -20 || true)
    if [ -n "$broken_links" ]; then
        local broken_count=$(echo "$broken_links" | wc -l)
        print_warning "Found $broken_count broken symlink(s):"
        echo "$broken_links" | head -10
        scan_issues=$((scan_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    else
        print_success "No broken symlinks found"
    fi
    
    # 4. Check for missing shared libraries
    print_info "Checking for missing shared library dependencies..."
    if command -v ldd &>/dev/null; then
        local missing_libs=$(find /usr/bin /usr/sbin -type f -executable 2>/dev/null | head -50 | while read -r bin; do
            ldd "$bin" 2>/dev/null | grep "not found" || true
        done | sort -u || true)
        
        if [ -n "$missing_libs" ]; then
            print_warning "Found binaries with missing library dependencies:"
            echo "$missing_libs" | head -10
            scan_issues=$((scan_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        else
            print_success "No missing library dependencies found"
        fi
    fi
    
    # 5. Check filesystem permissions issues
    print_info "Checking for critical filesystem permission issues..."
    local perm_issues=0
    
    # Check for world-writable system directories
    local world_writable=$(find /etc /usr/bin /usr/sbin -type d -perm -0002 2>/dev/null | head -10 || true)
    if [ -n "$world_writable" ]; then
        print_warning "Found world-writable system directories (security risk):"
        echo "$world_writable" | head -5
        perm_issues=$((perm_issues + 1))
    fi
    
    # Check for setuid/setgid issues
    local suspicious_suid=$(find /usr/bin /usr/sbin -type f -perm -4000 ! -user root 2>/dev/null | head -10 || true)
    if [ -n "$suspicious_suid" ]; then
        print_warning "Found setuid files not owned by root:"
        echo "$suspicious_suid" | head -5
        perm_issues=$((perm_issues + 1))
    fi
    
    if [ $perm_issues -eq 0 ]; then
        print_success "No critical permission issues found"
    else
        scan_issues=$((scan_issues + perm_issues))
        TOTAL_ISSUES=$((TOTAL_ISSUES + perm_issues))
    fi
    
    # 6. Check for corrupted package files
    print_info "Performing deep package integrity check..."
    # Filter out common false positives (optional files, moved files, cache files)
    local corrupted=$(pacman -Qk 2>&1 | grep -E "warning|error" | \
        grep -vE "\.pyc$|\.pyo$|\.cache|\.log$|LICENSE|dictionaries|hyphenation|rust-objcopy|libonnxruntime|\.tmp" | \
        sed 's/:.*//' | sort -u | head -20 || true)
    if [ -n "$corrupted" ]; then
        local corrupted_count=$(echo "$corrupted" | wc -l)
        print_warning "Found $corrupted_count package(s) with potential file issues:"
        echo "$corrupted" | head -10
        scan_issues=$((scan_issues + corrupted_count))
        TOTAL_ISSUES=$((TOTAL_ISSUES + corrupted_count))
        
        print_info "Attempting to repair potentially corrupted packages..."
        local fixed_count=0
        while IFS= read -r pkg; do
            [ -z "$pkg" ] && continue
            if run_with_timeout $COMMAND_TIMEOUT "pacman -S --noconfirm $pkg" 2>&1 | tee -a "$LOG_FILE"; then
                fixed_count=$((fixed_count + 1))
                scan_fixed=$((scan_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
                
                # Verify if issue persists
                sleep 1
                if pacman -Qk "$pkg" 2>&1 | grep -qE "warning|error"; then
                    print_warning "Package $pkg still shows issues (may be false positive - missing optional files)"
                fi
            fi
        done <<< "$corrupted"
        
        if [ $fixed_count -gt 0 ]; then
            print_success "Repaired $fixed_count package(s)"
        fi
    else
        print_success "No package file corruption detected"
    fi
    
    # 7. Check kernel module issues
    print_info "Checking for kernel module loading errors..."
    local module_errors=$(dmesg | grep -iE "failed to load|module.*error|firmware.*missing" | tail -20 || true)
    if [ -n "$module_errors" ]; then
        print_warning "Found kernel module errors:"
        echo "$module_errors" | head -10
        scan_issues=$((scan_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    else
        print_success "No kernel module errors found"
    fi
    
    # 8. Check for disk space issues
    print_info "Checking disk space..."
    local low_space=$(df -h / | awk 'NR==2 {if ($5+0 > 90) print $5}' || true)
    if [ -n "$low_space" ]; then
        print_warning "Root filesystem is ${low_space}% full (consider cleaning up)"
        scan_issues=$((scan_issues + 1))
        TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
    else
        print_success "Disk space is adequate"
    fi
    
    # 9. Check systemd service failures
    print_info "Checking for failed systemd services..."
    local failed_services=$(systemctl --failed --no-legend 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$failed_services" ]; then
        local failed_count=$(echo "$failed_services" | wc -l)
        print_warning "Found $failed_count failed service(s):"
        echo "$failed_services" | head -10
        scan_issues=$((scan_issues + failed_count))
        TOTAL_ISSUES=$((TOTAL_ISSUES + failed_count))
        
        print_info "Attempting to restart failed services..."
        local restarted=0
        while IFS= read -r svc; do
            [ -z "$svc" ] && continue
            if systemctl reset-failed "$svc" 2>&1 | tee -a "$LOG_FILE" && systemctl start "$svc" 2>&1 | tee -a "$LOG_FILE"; then
                restarted=$((restarted + 1))
                scan_fixed=$((scan_fixed + 1))
                TOTAL_FIXED=$((TOTAL_FIXED + 1))
            fi
        done <<< "$failed_services"
        
        if [ $restarted -gt 0 ]; then
            print_success "Restarted $restarted failed service(s)"
        fi
    else
        print_success "No failed services found"
    fi
    
    # 10. Check journal for critical errors
    print_info "Checking system journal for critical errors..."
    # Filter out empty lines, whitespace-only lines, and known harmless messages
    local journal_errors=$(journalctl -p err -n 50 --no-pager 2>/dev/null | \
        grep -vE "^[[:space:]]*$|^$" | \
        grep -vE "cosmic-comp\[.*\]:[[:space:]]*$" | \
        grep -vE "^[[:space:]]*Jan.*cosmic-comp\[.*\]:[[:space:]]*$" | \
        grep -vE "^[[:space:]]*[A-Z][a-z]{2} [0-9]+.*cosmic-comp\[.*\]:[[:space:]]*$" | \
        head -20 || true)
    if [ -n "$journal_errors" ]; then
        # Count actual error lines (non-empty, non-cosmic-comp empty lines)
        local error_count=$(echo "$journal_errors" | grep -vE "^[[:space:]]*$|cosmic-comp.*^$" | wc -l)
        if [ "$error_count" -gt 0 ]; then
            print_warning "Found recent critical errors in system journal:"
            echo "$journal_errors" | grep -vE "^[[:space:]]*$|cosmic-comp.*^$" | head -10
            scan_issues=$((scan_issues + 1))
            TOTAL_ISSUES=$((TOTAL_ISSUES + 1))
        else
            print_success "No critical errors in recent journal entries (filtered out empty/harmless messages)"
        fi
    else
        print_success "No critical errors in recent journal entries"
    fi
    
    print_info "Full system scan completed: $scan_issues issue(s) found, $scan_fixed issue(s) fixed"
}

# Arch Linux system repair
perform_arch_repair() {
    print_header "Arch Linux System Repair"
    
    # Run comprehensive system scan first
    full_system_scan
    
    # Run package integrity check
    check_arch_packages
    
    # Check and repair other components
    check_flatpak_packages
    check_kernel_modules
    check_system_libraries
    check_filesystem
    
    # Troubleshoot and repair wireless drivers
    troubleshoot_wireless_drivers
    
    # Final drive health check
    check_drive_health
    
    print_success "Arch Linux system repair completed!"
}

#############################################################################
# Arch Linux Menu System
#############################################################################

show_arch_menu() {
    echo ""
    print_header "Arch Linux Menu"
    echo ""
    echo -e "${CYAN}Please select an option:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Integrity Repair - Check and repair system integrity"
    echo -e "  ${GREEN}2)${NC} System Repair - Comprehensive system repair"
    echo -e "  ${GREEN}3)${NC} Arch Linux Setup - Complete Arch Linux setup with tools and applications"
    echo -e "  ${GREEN}4)${NC} Gaming Optimization - Apply gaming performance tweaks (safe)"
    echo -e "  ${GREEN}5)${NC} Development Optimization - Apply dev/IDE tweaks (safe)"
    echo ""
    echo -ne "${YELLOW}Enter your choice [1-5]: ${NC}"
    read -r choice
    
    case "$choice" in
        1)
            print_header "Starting Integrity Repair"
            check_arch_packages
            check_flatpak_packages
            troubleshoot_wireless_drivers
            ;;
        2)
            perform_arch_repair
            ;;
        3)
            perform_arch_setup
            ;;
        4)
            optimize_arch_gaming
            ;;
        5)
            optimize_arch_development
            ;;
        *)
            print_error "Invalid choice. Exiting."
            exit 1
            ;;
    esac
}

#############################################################################
# Main Execution
#############################################################################

main() {
    check_root
    
    # Detect distribution
    DISTRO=$(detect_distro)
    DISTRO_FAMILY=$(detect_distro_family)
    
    print_header "Linux System Integrity Checker & Auto-Repair"
    print_info "Detected distribution: $DISTRO"
    print_info "Distribution family: $DISTRO_FAMILY"

    # Basic sanity checks (helps catch missing deps / common bugs early)
    preflight_checks
    
    # Arch Linux special menu
    if [ "$DISTRO_FAMILY" = "arch" ]; then
        show_arch_menu
    else
        # For other distributions, run standard integrity checks
        print_header "Starting System Integrity Checks"
        
        case "$DISTRO_FAMILY" in
            debian)
                check_debian_packages
                check_snap_packages
                check_flatpak_packages
                check_kernel_modules
                check_system_libraries
                check_filesystem
                check_drive_health
                ;;
            fedora)
                check_fedora_packages
                check_flatpak_packages
                check_kernel_modules
                check_system_libraries
                check_filesystem
                check_drive_health
                ;;
            *)
                print_warning "Unknown distribution family. Running generic checks..."
                check_flatpak_packages
                check_kernel_modules
                check_system_libraries
                check_filesystem
                ;;
        esac
    fi
    
    # Summary
    echo ""
    print_header "Summary"
    echo "Total issues found: $TOTAL_ISSUES"
    echo "Total issues fixed: $TOTAL_FIXED"
    echo "Total failed operations: $TOTAL_FAILED"
    echo "Drive issues found: $DRIVE_ISSUES"
    echo "Drive issues fixed: $DRIVE_FIXED"
    echo "Log file: $LOG_FILE"
    
    if [ $TOTAL_ISSUES -eq 0 ] && [ $DRIVE_ISSUES -eq 0 ]; then
        print_success "System check completed successfully!"
        notify_user "System Check Complete" "All checks passed successfully!"
        exit 0
    elif [ $TOTAL_FAILED -gt 0 ]; then
        print_error "Some operations failed. Please check the log file."
        notify_user "System Check Complete" "Some operations failed. Check log: $LOG_FILE"
        exit 1
    else
        print_warning "Some issues were found and addressed."
        notify_user "System Check Complete" "Check completed. Some issues were fixed."
        exit 0
    fi
}

# Run main function
main "$@"