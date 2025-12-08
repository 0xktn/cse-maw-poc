#!/bin/bash
# Run Enclave via SSM
# Starts the enclave as a background process

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/state.sh"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

INSTANCE_ID=$(state_get "instance_id" 2>/dev/null || echo "")
AWS_REGION=$(state_get "aws_region" 2>/dev/null || echo "ap-southeast-1")

if [[ -z "$INSTANCE_ID" ]]; then
    log_error "No instance ID found"
    exit 1
fi

log_info "Starting enclave on EC2..."

# Run enclave with correct path
COMMANDS="[
    \"cd /home/ec2-user/confidential-multi-agent-workflow\",
    \"export NITRO_CLI_ARTIFACTS=/home/ec2-user/confidential-multi-agent-workflow/build\",
    \"nitro-cli run-enclave --cpu-count 2 --memory 1024 --eif-path /home/ec2-user/confidential-multi-agent-workflow/build/enclave.eif --enclave-cid 16 --debug-mode 2>&1 || echo ENCLAVE_FAILED\",
    \"sleep 3\",
    \"nitro-cli describe-enclaves\"
]"

COMMAND_ID=$(aws ssm send-command \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=$COMMANDS" \
    --timeout-seconds 120 \
    --query 'Command.CommandId' \
    --output text)

log_info "Command sent: $COMMAND_ID"

# Wait for command
sleep 15

STATUS=$(aws ssm get-command-invocation \
    --region "$AWS_REGION" \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query 'Status' \
    --output text 2>/dev/null || echo "Pending")

if [[ "$STATUS" == "Success" ]]; then
    OUTPUT=$(aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' \
        --output text)
    
    if echo "$OUTPUT" | grep -q "EnclaveID"; then
        ENCLAVE_ID=$(echo "$OUTPUT" | grep -o '"EnclaveID": "[^"]*"' | cut -d'"' -f4)
        log_info "Enclave running: $ENCLAVE_ID"
        state_set "enclave_id" "$ENCLAVE_ID"
        state_complete "enclave_running"
    else
        log_error "Enclave failed to start. Output:"
        echo "$OUTPUT"
        exit 1
    fi
else
    log_error "Command status: $STATUS"
    exit 1
fi
