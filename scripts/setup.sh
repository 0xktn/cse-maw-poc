#!/bin/bash
#
# Confidential Multi-Agent Workflow - Main Setup Script
#
# Usage:
#   ./setup.sh [OPTIONS]
#
# Options:
#   -h, --help          Show help
#   -r, --region REGION AWS region (default: ap-southeast-1)
#   -t, --type TYPE     EC2 instance type (default: m5.xlarge)
#   --status            Show current setup status
#   --reset             Reset all state and start fresh
#   --dry-run           Preview without executing
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Source state management
source "$SCRIPT_DIR/lib/state.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BLUE}▶ $1${NC}"; echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"; }

# Default configuration
DEFAULT_REGION="ap-southeast-1"
DEFAULT_INSTANCE_TYPE="m5.xlarge"
DEFAULT_KEY_NAME="nitro-enclave-key"
DEFAULT_VOLUME_SIZE="30"

DRY_RUN=false
SHOW_STATUS=false
RESET_STATE=false

# Parse arguments
show_help() {
    cat << EOF
Confidential Multi-Agent Workflow - Setup Script

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help
    -r, --region REGION     AWS region (default: $DEFAULT_REGION)
    -t, --type TYPE         EC2 instance type (default: $DEFAULT_INSTANCE_TYPE)
    --status                Show current setup status
    --reset                 Reset all state and start fresh
    --dry-run               Preview without executing

Examples:
    $0                      # Run setup (auto-resumes from last step)
    $0 --status             # Check what's done
    $0 --reset              # Start fresh
    $0 --region us-west-2   # Use different region
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) show_help; exit 0 ;;
        -r|--region) state_set "aws_region" "$2"; shift 2 ;;
        -t|--type) state_set "instance_type" "$2"; shift 2 ;;
        --status) SHOW_STATUS=true; shift ;;
        --reset) RESET_STATE=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Initialize state
state_init

# Handle --reset
if [[ "$RESET_STATE" == "true" ]]; then
    log_warn "Resetting all state..."
    state_reset
    log_info "State reset complete"
    exit 0
fi

# Handle --status
if [[ "$SHOW_STATUS" == "true" ]]; then
    state_status
    exit 0
fi

# Load or set defaults
AWS_REGION=$(state_get "aws_region" 2>/dev/null || echo "$DEFAULT_REGION")
INSTANCE_TYPE=$(state_get "instance_type" 2>/dev/null || echo "$DEFAULT_INSTANCE_TYPE")
KEY_NAME=$(state_get "key_name" 2>/dev/null || echo "$DEFAULT_KEY_NAME")
VOLUME_SIZE=$(state_get "volume_size" 2>/dev/null || echo "$DEFAULT_VOLUME_SIZE")

# Save config to state
state_set "aws_region" "$AWS_REGION"
state_set "instance_type" "$INSTANCE_TYPE"
state_set "key_name" "$KEY_NAME"
state_set "volume_size" "$VOLUME_SIZE"

# Export for child scripts
export AWS_REGION INSTANCE_TYPE KEY_NAME VOLUME_SIZE
export STATE_DIR STATE_DB

# Display status
echo ""
echo "┌─────────────────────────────────────────────┐"
echo "│  Confidential Multi-Agent Workflow Setup   │"
echo "└─────────────────────────────────────────────┘"
echo ""
echo "Configuration:"
echo "  Region:        $AWS_REGION"
echo "  Instance Type: $INSTANCE_TYPE"
echo "  Key Name:      $KEY_NAME"
echo ""
echo "Step Status:"
state_check "infra" && echo "  ✓ Infrastructure (completed)" || echo "  ○ Infrastructure (pending)"
state_check "kms" && echo "  ✓ KMS Configuration (completed)" || echo "  ○ KMS Configuration (pending)"
state_check "temporal" && echo "  ✓ Temporal Server (completed)" || echo "  ○ Temporal Server (pending)"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "Dry run mode - no changes will be made"
    exit 0
fi

# Check if all done
if state_check "infra" && state_check "kms" && state_check "temporal"; then
    log_info "All steps already completed! Use --reset to start over."
    exit 0
fi

read -p "Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Check prerequisites
log_step "Checking prerequisites"

if ! command -v aws &> /dev/null; then
    log_error "AWS CLI not found. Please install it first."
    exit 1
fi
log_info "AWS CLI: $(aws --version | head -1)"

if ! command -v sqlite3 &> /dev/null; then
    log_error "sqlite3 not found. Please install it first."
    exit 1
fi

if ! command -v docker &> /dev/null; then
    log_error "Docker not found. Please install Docker first."
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon not running. Please start Docker first."
    log_error "  macOS: Open Docker Desktop"
    log_error "  Linux: sudo systemctl start docker"
    exit 1
fi
log_info "Docker: $(docker --version)"

if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured. Run 'aws configure' first."
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
state_set "aws_account_id" "$AWS_ACCOUNT_ID" --encrypt
log_info "AWS Account: $AWS_ACCOUNT_ID"

# Step 1: Infrastructure
if ! state_check "infra"; then
    log_step "Step 1: Setting up EC2 Infrastructure"
    state_start "infra"
    
    if "$SCRIPT_DIR/setup-infrastructure.sh"; then
        state_complete "infra"
    else
        state_fail "infra"
        log_error "Infrastructure setup failed"
        exit 1
    fi
else
    log_step "Step 1: Infrastructure (Already Complete)"
fi

# Step 2: KMS
if ! state_check "kms"; then
    log_step "Step 2: Setting up AWS KMS"
    state_start "kms"
    
    if "$SCRIPT_DIR/setup-kms.sh"; then
        state_complete "kms"
    else
        state_fail "kms"
        log_error "KMS setup failed"
        exit 1
    fi
else
    log_step "Step 2: KMS (Already Complete)"
fi

# Step 3: Temporal
if ! state_check "temporal"; then
    log_step "Step 3: Setting up Temporal Server"
    state_start "temporal"
    
    if "$SCRIPT_DIR/setup-temporal.sh"; then
        state_complete "temporal"
    else
        state_fail "temporal"
        log_error "Temporal setup failed"
        exit 1
    fi
else
    log_step "Step 3: Temporal (Already Complete)"
fi

# Summary
log_step "Setup Complete!"

INSTANCE_IP=$(state_get "instance_ip" 2>/dev/null || echo "N/A")

echo ""
echo "┌─────────────────────────────────────────────┐"
echo "│              Next Steps                     │"
echo "└─────────────────────────────────────────────┘"
echo ""
echo "1. SSH into your instance:"
echo "   ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@${INSTANCE_IP}"
echo ""
echo "2. Clone the repo on the EC2:"
echo "   git clone https://github.com/0xktn/confidential-multi-agent-workflow.git"
echo "   cd confidential-multi-agent-workflow"
echo ""
echo "3. Run instance setup:"
echo "   ./scripts/setup-instance.sh"
echo ""
echo "4. Build the enclave:"
echo "   ./scripts/build-enclave.sh"
echo ""
echo "5. Apply KMS policy with PCR0:"
echo "   ./scripts/setup-kms-policy.sh <PCR0_VALUE>"
echo ""
echo "6. View current state anytime:"
echo "   ./scripts/setup.sh --status"
echo ""
