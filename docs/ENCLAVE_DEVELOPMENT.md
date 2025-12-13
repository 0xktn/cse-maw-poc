# Enclave Development

This guide covers the trusted application running inside the AWS Nitro Enclave, which handles secure data processing and encryption.

## Overview

The enclave application is the "Trusted" component that:
1. Listens for commands via vsock (port 5000)
2. Retrieves the Trusted Session Key (TSK) from KMS using hardware attestation
3. Encrypts/decrypts workflow data using AES-256-GCM
4. Returns encrypted results to the host

```
┌────────────────────────────────────────┐
│           Nitro Enclave                │
│  ┌──────────┐  ┌──────────┐           │
│  │  vsock   │  │   KMS    │           │
│  │ Listener │  │  Client  │           │
│  └────┬─────┘  └────┬─────┘           │
│       │             │                  │
│  ┌────▼─────────────▼─────┐           │
│  │   Encrypt/Decrypt      │           │
│  │   Workflow Logic       │           │
│  └────────────────────────┘           │
└────────────────────────────────────────┘
```

## Project Structure

```
enclave/
├── Dockerfile           # Minimal EIF build
├── requirements.txt     # Python dependencies
├── app.py              # Main enclave application
└── run.sh              # Startup script
```

## Implementation

### Dockerfile

The enclave uses a minimal Amazon Linux 2023 image:

```dockerfile
FROM amazonlinux:2023

# Install Python and dependencies
RUN dnf install -y python3.11 python3.11-pip && dnf clean all

# Copy kmstool_enclave_cli for KMS attestation
COPY kmstool_enclave_cli /usr/bin/
COPY libnsm.so /usr/lib64/

# Install Python packages
WORKDIR /app
COPY enclave/requirements.txt .
RUN pip3.11 install --no-cache-dir -r requirements.txt

# Copy application
COPY enclave/app.py enclave/run.sh ./
RUN chmod +x run.sh

CMD ["/app/run.sh"]
```

### Dependencies

```txt
# enclave/requirements.txt
cryptography>=41.0.0
```

### Main Application

The enclave application (`app.py`) implements:

1. **vsock Server**: Listens on port 5000 for host connections
2. **KMS Attestation**: Uses `kmstool_enclave_cli` to decrypt the TSK with hardware attestation
3. **Encryption/Decryption**: AES-256-GCM for workflow data

Key functions:
- `kms_decrypt(encrypted_tsk)` - Retrieves TSK from KMS with attestation
- `encrypt(plaintext, key)` - AES-256-GCM encryption
- `decrypt(ciphertext, key)` - AES-256-GCM decryption
- `handle_client(conn)` - Processes workflow requests

### KMS Attestation Flow

```python
def kms_decrypt(encrypted_tsk_b64):
    """Decrypt TSK using KMS with hardware attestation."""
    result = subprocess.run(
        [
            '/usr/bin/kmstool_enclave_cli',
            'decrypt',
            '--region', 'ap-southeast-1',
            '--proxy-port', '8000',
            '--aws-access-key-id', aws_access_key,
            '--aws-secret-access-key', aws_secret_key,
            '--aws-session-token', aws_session_token,
            '--ciphertext', encrypted_tsk_b64
        ],
        capture_output=True,
        text=True,
        env={'AWS_COMMON_RUNTIME_LOG_LEVEL': 'Debug'}
    )
    
    # Parse PLAINTEXT: <base64> from output
    if "PLAINTEXT:" in result.stdout:
        payload = result.stdout.split("PLAINTEXT:", 1)[1].strip()
        return base64.b64decode(payload)
```

**Key Points:**
- `kmstool_enclave_cli` automatically generates the attestation document
- KMS validates PCR0 (enclave code hash) before decrypting
- The TSK is only released if the enclave code matches the KMS policy

## Building the Enclave

```bash
# Build Docker image
docker build -t confidential-enclave:latest .

# Build EIF (Enclave Image File)
nitro-cli build-enclave \
  --docker-uri confidential-enclave:latest \
  --output-file build/enclave.eif

# Note the PCR0 value from output
# This must match the KMS key policy
```

## Running the Enclave

```bash
# Run the enclave
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 2048 \
  --eif-path build/enclave.eif \
  --enclave-cid 16

# Check status
nitro-cli describe-enclaves

# View console logs
nitro-cli console --enclave-id <ENCLAVE_ID>
```

## Workflow Protocol

The enclave handles two types of requests:

### 1. Configure Request
```json
{
  "type": "configure",
  "encrypted_tsk": "<base64>",
  "aws_access_key_id": "...",
  "aws_secret_access_key": "...",
  "aws_session_token": "..."
}
```

**Response:**
```json
{
  "status": "ok",
  "msg": "configured",
  "timestamp": "2025-12-13T10:00:00Z"
}
```

### 2. Process Request
```json
{
  "type": "process",
  "ciphertext": "<hex>"
}
```

**Response:**
```json
{
  "status": "ok",
  "result": "<hex>"
}
```

## Security Features

- **Hardware Attestation**: PCR0 validation ensures only approved code can decrypt
- **Memory Isolation**: All processing happens in enclave memory (invisible to host)
- **Ephemeral Keys**: TSK exists only in enclave memory, never persisted
- **Encrypted Communication**: All data transferred as ciphertext

## Troubleshooting

### Issue: `KMS Decrypt failed`

**Cause**: PCR0 mismatch between EIF and KMS policy

**Solution**:
```bash
# Rebuild enclave and note new PCR0
nitro-cli build-enclave --docker-uri confidential-enclave:latest --output-file build/enclave.eif

# Update KMS policy with new PCR0
./scripts/setup-kms.sh
```

### Issue: `vsock connection refused`

**Cause**: Enclave not running or wrong CID/port

**Solution**:
```bash
# Check enclave status
nitro-cli describe-enclaves

# Restart if needed
nitro-cli terminate-enclave --all
./scripts/run-enclave.sh
```

### Issue: `vsock-proxy not running`

**Cause**: KMS proxy not started

**Solution**:
```bash
# Start vsock-proxy for KMS access
pkill vsock-proxy || true
vsock-proxy 8000 kms.ap-southeast-1.amazonaws.com 443 &
```

## Development Tips

1. **Local Testing**: Use Docker to test enclave logic before building EIF
2. **Logging**: Use `print(..., flush=True)` for immediate console output
3. **PCR0 Management**: Save PCR0 values when rebuilding to track changes
4. **Memory Allocation**: Ensure sufficient memory (minimum 2048 MB for crypto libraries)

## Next Steps

- [HOST_WORKER_SETUP.md](./HOST_WORKER_SETUP.md) - Set up the host worker application
- [REFERENCE.md](./REFERENCE.md) - System reference and troubleshooting
