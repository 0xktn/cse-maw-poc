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
    echo "  --status <wf_id|latest> Check status of a workflow"
    echo "  --verify                Run System Attestation Verification (CloudTrail + Logs)"
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
    log_info "Running System Attestation Verification on remote instance..."
    
    KMS_KEY_ID=$(state_get "kms_key_id" 2>/dev/null || echo "")
    
    COMMANDS='[
        "cd /home/ec2-user/confidential-multi-agent-workflow",
        "export KMS_KEY_ID='${KMS_KEY_ID}'",
        "PYTHONWARNINGS=ignore python3 tests/verify_attestation.py > /tmp/verify_output.txt 2>&1",
        "cat /tmp/verify_output.txt"
    ]'

    COMMAND_ID=$(aws ssm send-command \
        --region "$AWS_REGION" \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=$COMMANDS" \
        --output text \
        --query "Command.CommandId")

    log_info "Command sent: $COMMAND_ID"
    log_info "Waiting for verification results..."
    
    sleep 5
    
    while true; do
        STATUS=$(aws ssm get-command-invocation \
            --region "$AWS_REGION" \
            --command-id "$COMMAND_ID" \
            --instance-id "$INSTANCE_ID" \
            --query "Status" \
            --output text 2>/dev/null || echo "Pending")
            
        if [[ "$STATUS" == "Success" ]]; then
            AWS_PAGER="" aws ssm get-command-invocation \
                --region "$AWS_REGION" \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text
            exit 0
        elif [[ "$STATUS" == "Failed" ]]; then
            AWS_PAGER="" aws ssm get-command-invocation \
                --region "$AWS_REGION" \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardOutputContent" \
                --output text
            
            # Print stderr only if there's output
            ERR=$(AWS_PAGER="" aws ssm get-command-invocation \
                --region "$AWS_REGION" \
                --command-id "$COMMAND_ID" \
                --instance-id "$INSTANCE_ID" \
                --query "StandardErrorContent" \
                --output text)
            
            if [[ -n "$ERR" ]]; then
                echo ""
                echo "Detailed Errors:"
                echo "$ERR"
            fi
            exit 1
        fi
        sleep 5
    done
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
