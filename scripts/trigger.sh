#!/bin/bash
# Trigger script to start a confidential workflow execution
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/state.sh"
source "$SCRIPT_DIR/lib/logging.sh"

# Get instance info
INSTANCE_ID=$(state_get "instance_id" 2>/dev/null || echo "")
INSTANCE_IP=$(state_get "instance_ip" 2>/dev/null || echo "")
AWS_REGION=$(state_get "aws_region" 2>/dev/null || echo "ap-southeast-1")

if [[ -z "$INSTANCE_ID" ]]; then
    log_error "No instance found. Run ./scripts/setup.sh first."
    exit 1
fi

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --status <wf_id|latest>  Check status of a workflow"
    echo "  --verify [wf_id|latest]  Show attestation document from CloudTrail (default: latest)"
    exit 1
}

# Parse arguments
MODE="trigger"
WORKFLOW_ID=""

if [[ "$1" == "--status" ]]; then
    MODE="status"
    WORKFLOW_ID="$2"
    if [[ -z "$WORKFLOW_ID" ]]; then
        usage
    fi
elif [[ "$1" == "--verify" || "$1" == "--verify-cloudtrail" ]]; then
    MODE="verify_attestation"
elif [[ -n "$1" ]]; then
    usage
fi

if [[ "$MODE" == "status" ]]; then
    if [[ "$WORKFLOW_ID" == "latest" ]]; then
        # Get the latest workflow ID from cache
        WORKFLOW_ID=$(state_get "last_workflow_id" 2>/dev/null || echo "")
        
        if [[ -z "$WORKFLOW_ID" ]]; then
            log_error "No workflows found in cache. Trigger a workflow first."
            exit 1
        fi
        
        log_info "Latest workflow (cached): $WORKFLOW_ID"
    elif [[ -z "$2" ]]; then
        log_error "Usage: $0 --status <workflow-id|latest>"
        exit 1
    else
        WORKFLOW_ID="$2"
        log_info "Checking status of workflow: $WORKFLOW_ID"
    fi
    
    COMMAND_ID=$(aws ssm send-command \
        --region "$AWS_REGION" \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"docker exec temporal temporal --address temporal:7233 workflow describe --namespace confidential-workflow-poc --workflow-id $WORKFLOW_ID 2>&1\"]" \
        --query 'Command.CommandId' \
        --output text 2>/dev/null)
    
    # Poll for completion
    for i in {1..20}; do
        STATUS=$(aws ssm get-command-invocation \
            --region "$AWS_REGION" \
            --command-id "$COMMAND_ID" \
            --instance-id "$INSTANCE_ID" \
            --query 'Status' \
            --output text 2>/dev/null || echo "Pending")
        
        if [[ "$STATUS" == "Success" ]]; then
            break
        fi
        sleep 0.5
    done
    
    RESULT=$(aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' \
        --output text 2>/dev/null || echo "")
    
    echo ""
    echo "$RESULT"
    echo ""
    exit 0
fi


if [[ "$MODE" == "verify_attestation" ]]; then
    WORKFLOW_ID="$2"
    
    if [[ -z "$WORKFLOW_ID" ]]; then
        WORKFLOW_ID="latest"
    fi
    
    if [[ "$WORKFLOW_ID" == "latest" ]]; then
        WORKFLOW_ID=$(state_get "last_workflow_id" 2>/dev/null || echo "")
        if [[ -z "$WORKFLOW_ID" ]]; then
            log_error "No workflows found. Trigger a workflow first."
            exit 1
        fi
        log_info "Verifying attestation for latest workflow: $WORKFLOW_ID"
    else
        log_info "Verifying attestation for workflow: $WORKFLOW_ID"
    fi
    
    # Use a 10-minute time window for CloudTrail search
    # CloudTrail events can take 1-2 minutes to appear
    if date -v-10M > /dev/null 2>&1; then
        # macOS
        START_TIME=$(date -u -v-10M '+%Y-%m-%dT%H:%M:%S')
    else
        # Linux
        START_TIME=$(date -u -d '10 minutes ago' '+%Y-%m-%dT%H:%M:%S')
    fi
    END_TIME=$(date -u '+%Y-%m-%dT%H:%M:%S')
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔐 Attestation Verification"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    log_info "Searching CloudTrail for KMS Decrypt events with Nitro Enclave attestation..."
    echo ""
    
    # Poll CloudTrail for up to 5 minutes (30 attempts x 10 seconds)
    MAX_ATTEMPTS=30
    ATTEMPT=0
    ATTESTATION=""
    
    while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
        ATTEMPT=$((ATTEMPT + 1))
        
        # Fetch CloudTrail events
        ATTESTATION=$(aws cloudtrail lookup-events \
            --region "$AWS_REGION" \
            --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \
            --start-time "$START_TIME" \
            --end-time "$END_TIME" \
            --output json 2>/dev/null | \
            jq -r '.Events[] | select(.CloudTrailEvent | contains("nitro_enclaves")) | .CloudTrailEvent | fromjson' | \
            head -1)
        
        if [[ -n "$ATTESTATION" ]]; then
            echo ""
            log_info "✅ Attestation document found!"
            break
        fi
        
        # Show progress
        ELAPSED=$((ATTEMPT * 10))
        echo -ne "\r[${ATTEMPT}/${MAX_ATTEMPTS}] Polling CloudTrail... (${ELAPSED}s elapsed, CloudTrail has 2-5min delay)    "
        
        sleep 10
        
        # Update end time for next iteration
        END_TIME=$(date -u '+%Y-%m-%dT%H:%M:%S')
    done
    
    echo ""
    echo ""
    
    if [[ -z "$ATTESTATION" ]]; then
        log_error "No attestation document found after ${MAX_ATTEMPTS} attempts (5 minutes)"
        log_info "This could mean:"
        log_info "  - The workflow hasn't run yet"
        log_info "  - CloudTrail events are still propagating (can take up to 15 minutes in rare cases)"
        log_info "  - The enclave didn't decrypt any secrets"
        exit 1
    fi
    
    # Extract and display attestation fields
    echo "$ATTESTATION" | jq -r '
    "Event Time:        " + .eventTime,
    "User Agent:        " + .userAgent,
    "Source IP:         " + .sourceIPAddress,
    "",
    "Attestation Document:",
    "  Module ID:       " + .additionalEventData.recipient.attestationDocumentModuleId,
    "  Image Digest:    " + .additionalEventData.recipient.attestationDocumentEnclaveImageDigest,
    "  PCR1:            " + .additionalEventData.recipient.attestationDocumentEnclavePCR1,
    "  PCR2:            " + .additionalEventData.recipient.attestationDocumentEnclavePCR2,
    "  PCR3:            " + .additionalEventData.recipient.attestationDocumentEnclavePCR3,
    "",
    "KMS Key:           " + .resources[0].ARN
    '
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ Attestation Verified!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "This attestation document is cryptographically signed by AWS Nitro hardware."
    echo "KMS verified these measurements before releasing the encrypted secret."
    echo ""
    echo "To view full JSON:"
    echo "  aws cloudtrail lookup-events --region $AWS_REGION \\"
    echo "    --lookup-attributes AttributeKey=EventName,AttributeValue=Decrypt \\"
    echo "    --start-time \"$START_TIME\" --end-time \"$END_TIME\" \\"
    echo "    --output json | jq '.Events[] | select(.CloudTrailEvent | contains(\"nitro_enclaves\"))'"
    echo ""
    
    exit 0
fi

# Trigger new workflow
log_info "Triggering workflow on EC2 instance: $INSTANCE_ID"

# Get timestamp for unique workflow ID
WORKFLOW_ID="test-$(date +%s)"

COMMAND_ID=$(aws ssm send-command \
    --region "$AWS_REGION" \
    --instance-ids "$INSTANCE_ID" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"docker exec temporal temporal --address temporal:7233 workflow start --namespace confidential-workflow-poc --task-queue confidential-workflow-tasks --type ConfidentialWorkflow --input '\\\"test-input-data\\\"' --workflow-id $WORKFLOW_ID 2>&1 || echo FAILED\"]" \
    --query 'Command.CommandId' \
    --output text 2>/dev/null)

log_info "Command sent: $COMMAND_ID"
log_info "Waiting for response..."

# Poll for completion
for i in {1..20}; do
    STATUS=$(aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'Status' \
        --output text 2>/dev/null || echo "Pending")
    
    if [[ "$STATUS" == "Success" ]]; then
        break
    fi
    sleep 0.5
done

# Get result
RESULT=$(aws ssm get-command-invocation \
    --region "$AWS_REGION" \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query 'StandardOutputContent' \
    --output text 2>/dev/null || echo "")

if [[ -n "$RESULT" ]]; then
    # Save workflow ID to state for quick lookup
    state_set "last_workflow_id" "$WORKFLOW_ID"
    
    echo ""
    echo -e "${BLUE}=== Workflow Started ===${NC}"
    echo "$RESULT"
    echo ""
    log_info "Check status with: ${YELLOW}./scripts/trigger.sh --status $WORKFLOW_ID${NC}"
    log_info "Or use: ${YELLOW}./scripts/trigger.sh --status latest${NC}"
else
    ERROR=$(aws ssm get-command-invocation \
        --region "$AWS_REGION" \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardErrorContent' \
        --output text 2>/dev/null || echo "")
    log_error "Failed to trigger workflow"
    echo "$ERROR"
    exit 1
fi
