# Tests

This directory contains test scripts for the confidential multi-agent workflow.

## Test Files

### Integration Tests
- **`test_kms_attestation.py`** - End-to-end KMS attestation test
- **`test_temporal_workflow.py`** - Temporal workflow integration test
- **`verify_cloudtrail.py`** - CloudTrail attestation verification

### Component Tests
- **`test_vsock.py`** - vsock communication test
- **`test_vsock_echo.py`** - Simple vsock echo test
- **`test_byte_ping.py`** - Byte-level vsock ping test

### Diagnostic Tests
- **`test_diagnostic.py`** - System diagnostic test
- **`test_debian_verdict.py`** - Debian compatibility test

## Running Tests

### Prerequisites

1. Ensure infrastructure is set up:
   ```bash
   ./scripts/setup.sh
   ```

2. Ensure enclave and worker are running:
   ```bash
   # On EC2 instance
   ./scripts/run-enclave.sh
   python3 host/worker.py
   ```

### Running Individual Tests

```bash
# KMS attestation test (most important)
python3 tests/test_kms_attestation.py

# Temporal workflow test
python3 tests/test_temporal_workflow.py

# CloudTrail verification
python3 tests/verify_cloudtrail.py

# vsock communication test
python3 tests/test_vsock.py
```

### Running All Tests

```bash
# Run all tests
for test in tests/test_*.py; do
    echo "Running $test..."
    python3 "$test" || echo "FAILED: $test"
done
```

## Test Descriptions

### test_kms_attestation.py

Tests the complete KMS attestation flow:
1. Connects to enclave via vsock
2. Sends encrypted TSK and AWS credentials
3. Enclave generates attestation document
4. kmstool decrypts TSK with attestation
5. Enclave processes data with decrypted TSK

**Expected Output**: `🎉 END-TO-END KMS ATTESTATION TEST PASSED!`

### test_temporal_workflow.py

Tests Temporal workflow integration:
1. Connects to Temporal server
2. Starts confidential workflow
3. Worker processes data in enclave
4. Verifies encrypted result

**Expected Output**: `🎉 TEMPORAL INTEGRATION TEST PASSED!`

### verify_cloudtrail.py

Verifies CloudTrail logging:
1. Queries CloudTrail for KMS Decrypt events
2. Checks for attestation documents
3. Validates PCR0 values

**Note**: CloudTrail has 5-15 minute delay. Run after KMS test.

## Troubleshooting

**Test fails with "Connection refused"**
- Ensure enclave is running: `nitro-cli describe-enclaves`
- Ensure vsock-proxy is running: `ps aux | grep vsock-proxy`

**Test fails with "401 Unauthorized"**
- Check IMDSv2 configuration in `host/activities.py`
- Verify instance has correct IAM role

**Test fails with "KMS Decrypt failed"**
- Verify PCR0 in KMS policy matches enclave build
- Check vsock-proxy is forwarding to correct KMS endpoint

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run Integration Tests
  run: |
    python3 tests/test_kms_attestation.py
    python3 tests/test_temporal_workflow.py
```

**Note**: Tests require AWS credentials and running infrastructure.
