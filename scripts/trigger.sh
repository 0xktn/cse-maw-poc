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

# Parse arguments
if [[ "$1" == "--status" ]]; then
    if [[ -z "$2" ]]; then
        log_error "Usage: $0 --status <workflow-id>"
        exit 1
    fi
    
    WORKFLOW_ID="$2"
    log_info "Checking status of workflow: $WORKFLOW_ID"
    
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
    echo ""
    echo -e "${BLUE}=== Workflow Started ===${NC}"
    echo "$RESULT"
    echo ""
    log_info "Check status with: ${YELLOW}./scripts/trigger.sh --status $WORKFLOW_ID${NC}"
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
