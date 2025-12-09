#!/bin/bash
set -e

# Automation script for optional verification tasks
# This script completes CloudTrail and Temporal verification automatically

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/state.sh"

echo "=========================================="
echo "Optional Tasks Automation"
echo "=========================================="
echo

# Get instance details
INSTANCE_ID=$(state_get "instance_id")
REGION="ap-southeast-1"

if [ -z "$INSTANCE_ID" ]; then
    echo "❌ Error: No instance ID found in state"
    exit 1
fi

echo "Instance ID: $INSTANCE_ID"
echo "Region: $REGION"
echo

# Function to run SSM command and wait for completion
run_ssm_command() {
    local description="$1"
    local command="$2"
    local timeout="${3:-60}"
    
    echo "▶ $description"
    
    local cmd_id=$(aws ssm send-command \
        --region "$REGION" \
        --instance-ids "$INSTANCE_ID" \
        --document-name "AWS-RunShellScript" \
        --parameters "commands=[\"$command\"]" \
        --timeout-seconds "$timeout" \
        --query 'Command.CommandId' \
        --output text)
    
    echo "  Command ID: $cmd_id"
    
    # Wait for command to complete
    local status="InProgress"
    local wait_time=0
    local max_wait=$((timeout + 10))
    
    while [ "$status" = "InProgress" ] && [ $wait_time -lt $max_wait ]; do
        sleep 5
        wait_time=$((wait_time + 5))
        status=$(aws ssm get-command-invocation \
            --region "$REGION" \
            --command-id "$cmd_id" \
            --instance-id "$INSTANCE_ID" \
            --query 'Status' \
            --output text 2>/dev/null || echo "InProgress")
        echo -n "."
    done
    echo
    
    # Get output
    local output=$(aws ssm get-command-invocation \
        --region "$REGION" \
        --command-id "$cmd_id" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' \
        --output text 2>/dev/null || echo "")
    
    if [ "$status" = "Success" ]; then
        echo "✅ Success"
        if [ -n "$output" ]; then
            echo "$output" | tail -20
        fi
        return 0
    else
        echo "❌ Failed (Status: $status)"
        if [ -n "$output" ]; then
            echo "$output" | tail -20
        fi
        return 1
    fi
}

echo "=========================================="
echo "Step 1: Starting Infrastructure"
echo "=========================================="
echo

# Start vsock-proxy
run_ssm_command \
    "Starting vsock-proxy" \
    "pkill vsock-proxy || true && nohup vsock-proxy 8000 kms.ap-southeast-1.amazonaws.com 443 > /tmp/vsock-proxy.log 2>&1 & sleep 2 && ps aux | grep vsock-proxy | grep -v grep" \
    30

# Verify enclave is running
run_ssm_command \
    "Checking enclave status" \
    "nitro-cli describe-enclaves | head -10" \
    30

echo
echo "=========================================="
echo "Step 2: Running KMS Attestation Test"
echo "=========================================="
echo

run_ssm_command \
    "Running KMS test to generate CloudTrail event" \
    "cd /home/ec2-user/confidential-multi-agent-workflow && timeout 60 python3 scripts/test_kms_attestation.py 2>&1 | tail -15" \
    90

echo
echo "=========================================="
echo "Step 3: Waiting for CloudTrail (15 minutes)"
echo "=========================================="
echo

echo "CloudTrail events have a 5-15 minute delay."
echo "Waiting 15 minutes before checking..."
echo

for i in {15..1}; do
    echo "  $i minutes remaining..."
    sleep 60
done

echo
echo "=========================================="
echo "Step 4: Verifying CloudTrail"
echo "=========================================="
echo

run_ssm_command \
    "Checking CloudTrail for attestation documents" \
    "cd /home/ec2-user/confidential-multi-agent-workflow && python3 scripts/verify_cloudtrail.py 2>&1 | tail -40" \
    60

echo
echo "=========================================="
echo "Step 5: Starting Temporal Worker"
echo "=========================================="
echo

run_ssm_command \
    "Starting Temporal worker" \
    "cd /home/ec2-user/confidential-multi-agent-workflow && pkill -f worker.py || true && nohup python3 host/worker.py > /tmp/worker.log 2>&1 & sleep 5 && ps aux | grep worker.py | grep -v grep && tail -10 /tmp/worker.log" \
    30

echo
echo "=========================================="
echo "Step 6: Running Temporal Workflow Test"
echo "=========================================="
echo

run_ssm_command \
    "Executing Temporal workflow integration test" \
    "cd /home/ec2-user/confidential-multi-agent-workflow && timeout 60 python3 scripts/test_temporal_workflow.py 2>&1" \
    90

echo
echo "=========================================="
echo "✅ All Optional Tasks Complete!"
echo "=========================================="
echo
echo "Summary:"
echo "  ✅ CloudTrail verification completed"
echo "  ✅ Temporal workflow integration tested"
echo
echo "Check the output above for detailed results."
echo
