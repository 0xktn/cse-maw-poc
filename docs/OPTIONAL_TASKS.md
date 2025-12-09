# Optional Tasks Completion Guide

This guide provides step-by-step instructions for completing the optional verification tasks that require manual EC2 access.

## Prerequisites

SSH into the EC2 instance:
```bash
# Get instance IP from state
INSTANCE_IP=$(source scripts/lib/state.sh && state_get "instance_ip")
ssh -i ~/.ssh/nitro-enclave-key.pem ec2-user@$INSTANCE_IP
```

## Task 1: CloudTrail Attestation Verification

### Step 1: Start Infrastructure

```bash
cd /home/ec2-user/confidential-multi-agent-workflow

# Kill existing processes
pkill vsock-proxy || true
nitro-cli terminate-enclave --all || true

# Start vsock-proxy
nohup vsock-proxy 8000 kms.ap-southeast-1.amazonaws.com 443 > /tmp/vsock-proxy.log 2>&1 &

# Start enclave
nitro-cli run-enclave \
  --enclave-cid 16 \
  --cpu-count 2 \
  --memory 1024 \
  --eif-path build/enclave.eif \
  --debug-mode

# Verify
ps aux | grep vsock-proxy | grep -v grep
nitro-cli describe-enclaves
```

### Step 2: Generate KMS Event

```bash
# Run KMS attestation test to generate CloudTrail event
python3 scripts/test_kms_attestation.py
```

**Expected Output**:
```
✅ Configuration successful! TSK decrypted via kmstool with attestation!
✅ Processing successful!
🎉 END-TO-END KMS ATTESTATION TEST PASSED!
```

### Step 3: Wait for CloudTrail Propagation

CloudTrail events have a 5-15 minute delay. Wait at least 15 minutes before proceeding.

```bash
# Optional: Check current time
date
```

### Step 4: Verify CloudTrail

```bash
# Run CloudTrail verification
python3 scripts/verify_cloudtrail.py
```

**Expected Output**:
```
✅ Found X Decrypt events
✅ Attestation documents found in KMS Decrypt requests
✅ PCR0 verification successful
```

**If you see "No attestation documents found"**:
- Wait longer (CloudTrail delay)
- Verify the KMS test actually ran successfully
- Check that the decrypt event is from the enclave (not SSM or other services)

---

## Task 2: Temporal Workflow Integration

### Step 1: Start Temporal Worker

```bash
cd /home/ec2-user/confidential-multi-agent-workflow

# Ensure infrastructure is running (from Task 1)
ps aux | grep vsock-proxy | grep -v grep
nitro-cli describe-enclaves

# Kill existing worker
pkill -f worker.py || true

# Start worker
nohup python3 host/worker.py > /tmp/worker.log 2>&1 &

# Verify worker started
sleep 3
ps aux | grep worker.py | grep -v grep

# Check worker logs
tail -20 /tmp/worker.log
```

**Expected Log Output**:
```
INFO:__main__:Connecting to Temporal at localhost:7233
INFO:__main__:Connected to namespace: confidential-workflow-poc
INFO:__main__:Starting worker on queue: confidential-workflow-tasks
INFO:activities:Project root: /home/ec2-user/confidential-multi-agent-workflow
INFO:activities:Loaded encrypted TSK from /home/ec2-user/confidential-multi-agent-workflow/encrypted-tsk.b64
```

### Step 2: Run Temporal Workflow Test

```bash
# Run the workflow integration test
python3 scripts/test_temporal_workflow.py
```

**Expected Output**:
```
============================================================
TEMPORAL WORKFLOW INTEGRATION TEST
============================================================

1. Connecting to Temporal at localhost:7233...
   Namespace: confidential-workflow-poc
   Task Queue: confidential-workflow-tasks
✅ Connected to Temporal

2. Starting workflow...
   Workflow ID: test-confidential-workflow-XXXXX
   Task Queue: confidential-workflow-tasks
✅ Workflow started: test-confidential-workflow-XXXXX

3. Waiting for workflow to complete...
✅ Workflow completed successfully!

4. Analyzing result...
   Status: ok
   Message: processed
   Encrypted data (first 80 chars): ...
✅ Data appears to be encrypted!

🎉 TEMPORAL INTEGRATION TEST PASSED!
```

### Step 3: Verify in Temporal UI

1. Access Temporal UI:
   ```
   http://<INSTANCE_IP>:8080
   ```

2. Navigate to namespace: `confidential-workflow-poc`

3. Find your workflow ID (from test output)

4. Verify:
   - Workflow status: **Completed**
   - Input: Shows encrypted/base64 data (not plaintext)
   - Output: Shows encrypted blob
   - Activity `process_in_enclave`: **Succeeded**

---

## Troubleshooting

### Worker Fails to Start

**Error**: `encrypted-tsk.b64 not found`
```bash
# Verify file exists
ls -la /home/ec2-user/confidential-multi-agent-workflow/encrypted-tsk.b64

# If missing, regenerate
cd /home/ec2-user/confidential-multi-agent-workflow
python3 scripts/update_policy_local.py
```

**Error**: `Failed to fetch AWS credentials from IMDS`
```bash
# Check IMDS access
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Verify instance role
aws sts get-caller-identity
```

### Enclave Issues

**Error**: `HugePages_Total: 0`
```bash
# Restart allocator
sudo systemctl restart nitro-enclaves-allocator

# Verify
cat /proc/meminfo | grep HugePages
```

**Error**: Enclave crashes silently
```bash
# Check console logs
nitro-cli console --enclave-id <ENCLAVE_ID>

# Check debug mode is enabled
nitro-cli describe-enclaves | grep Flags
```

### Temporal Issues

**Error**: Workflow timeout
```bash
# Check worker logs
tail -50 /tmp/worker.log

# Check enclave logs
nitro-cli console --enclave-id <ENCLAVE_ID>
```

---

## Success Criteria

### CloudTrail Verification ✅
- [ ] KMS test passes
- [ ] CloudTrail shows Decrypt events
- [ ] Attestation documents present
- [ ] PCR0 matches current build

### Temporal Integration ✅
- [ ] Worker starts successfully
- [ ] Workflow executes without errors
- [ ] Temporal UI shows encrypted data
- [ ] Activity completes successfully

---

## Cleanup

After completing verification:

```bash
# Stop services
pkill vsock-proxy
pkill -f worker.py
nitro-cli terminate-enclave --all

# Exit SSH
exit
```

---

## Notes

- **CloudTrail Delay**: Always wait 15+ minutes after KMS call
- **Worker Logs**: Check `/tmp/worker.log` for detailed errors
- **Enclave Console**: Use `nitro-cli console` for real-time debugging
- **Temporal UI**: Access via port 8080 (may need SSH tunnel)

**All scripts are tested and ready. These manual steps are only needed due to SSM command timing constraints.**
