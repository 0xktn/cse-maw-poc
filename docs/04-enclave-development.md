# Enclave Development

This guide covers developing the trusted application that runs inside the AWS Nitro Enclave, handling secure data processing, encryption, and attestation.

## Overview

The enclave application is the "Trusted" component that:
1. Listens for commands via vsock
2. Retrieves the Trusted Session Key (TSK) from KMS using attestation
3. Decrypts incoming ciphertext, processes data, and encrypts results
4. Returns encrypted data to the host

```
┌────────────────────────────────────────┐
│           Nitro Enclave                │
│  ┌──────────┐  ┌──────────┐           │
│  │  vsock   │  │   KMS    │           │
│  │ Listener │  │  Client  │           │
│  └────┬─────┘  └────┬─────┘           │
│       │             │                  │
│  ┌────▼─────────────▼─────┐           │
│  │      Agent Logic       │           │
│  │  (Encrypt/Decrypt/     │           │
│  │   Process)             │           │
│  └────────────────────────┘           │
└────────────────────────────────────────┘
```

## Prerequisites

- Docker installed on EC2 instance
- aws-nitro-enclaves-cli installed
- AWS credentials configured
- Python 3.9+ (for enclave application)

## Project Structure

```
enclave/
├── Dockerfile           # Multi-stage build for minimal EIF
├── requirements.txt     # Python dependencies
├── app.py              # Main enclave application
├── attestation.py      # KMS attestation client
├── crypto.py           # Encryption/decryption utilities
└── agent.py            # Agent A and Agent B logic
```

## Step 1: Create the Dockerfile

Create a minimal Docker image for the enclave:

```dockerfile
# enclave/Dockerfile
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --target /app/deps

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy dependencies and application
COPY --from=builder /app/deps /app/deps
COPY . .

ENV PYTHONPATH=/app/deps

# Enclave entry point
CMD ["python", "app.py"]
```

## Step 2: Install Dependencies

```txt
# enclave/requirements.txt
boto3>=1.28.0
cryptography>=41.0.0
protobuf>=4.24.0
```

## Step 3: Implement vsock Listener

The enclave communicates with the host via vsock:

```python
# enclave/app.py
import socket
import json
import logging
from attestation import get_trusted_session_key
from agent import AgentA, AgentB

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# vsock configuration
VSOCK_PORT = 5000
VSOCK_CID = 3  # Any CID for listening

def create_vsock_server():
    """Create a vsock server socket."""
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    sock.listen(5)
    logger.info(f"Enclave listening on vsock port {VSOCK_PORT}")
    return sock

def handle_request(conn, tsk):
    """Handle a single request from the host."""
    try:
        # Receive data length first (4 bytes)
        length_bytes = conn.recv(4)
        if not length_bytes:
            return
        
        data_length = int.from_bytes(length_bytes, 'big')
        
        # Receive the full payload
        data = b''
        while len(data) < data_length:
            chunk = conn.recv(min(4096, data_length - len(data)))
            if not chunk:
                break
            data += chunk
        
        # Parse request
        request = json.loads(data.decode('utf-8'))
        mode = request.get('mode')
        payload = request.get('payload')
        
        # Route to appropriate agent
        if mode == 'A':
            result = AgentA(tsk).process(payload)
        elif mode == 'B':
            result = AgentB(tsk).process(payload)
        else:
            result = {'error': f'Unknown mode: {mode}'}
        
        # Send response
        response = json.dumps(result).encode('utf-8')
        conn.sendall(len(response).to_bytes(4, 'big'))
        conn.sendall(response)
        
    except Exception as e:
        logger.error(f"Error handling request: {e}")
        error_response = json.dumps({'error': str(e)}).encode('utf-8')
        conn.sendall(len(error_response).to_bytes(4, 'big'))
        conn.sendall(error_response)

def main():
    """Main enclave entry point."""
    logger.info("Enclave starting...")
    
    # Retrieve TSK from KMS with attestation
    logger.info("Retrieving Trusted Session Key from KMS...")
    tsk = get_trusted_session_key()
    logger.info("TSK retrieved successfully")
    
    # Start vsock server
    server = create_vsock_server()
    
    while True:
        conn, addr = server.accept()
        logger.info(f"Connection from CID: {addr[0]}")
        try:
            handle_request(conn, tsk)
        finally:
            conn.close()

if __name__ == "__main__":
    main()
```

## Step 4: Implement Attestation Client

```python
# enclave/attestation.py
import boto3
import base64
import json
import subprocess
from botocore.config import Config

def get_attestation_document():
    """
    Request attestation document from Nitro Hypervisor.
    This is only available inside a Nitro Enclave.
    """
    # Use the Nitro Security Module (NSM) to generate attestation
    # In a real enclave, use the NSM library
    # For development/testing, this returns a placeholder
    try:
        # NSM device path
        nsm_fd = open('/dev/nsm', 'rb')
        # Request attestation document
        # ... (NSM API calls)
        nsm_fd.close()
    except FileNotFoundError:
        raise RuntimeError("Not running inside a Nitro Enclave")

def get_trusted_session_key():
    """
    Retrieve the Trusted Session Key from KMS using attestation.
    """
    # In production, use aws-nitro-enclaves-sdk-python
    # This demonstrates the concept
    
    # 1. Get attestation document
    attestation_doc = get_attestation_document()
    
    # 2. Create KMS client
    # Note: Enclaves use a proxy for AWS API calls
    config = Config(
        proxies={'https': 'http://127.0.0.1:8000'}
    )
    kms = boto3.client('kms', config=config)
    
    # 3. Call KMS Decrypt with attestation
    # The encrypted key should be passed in or stored securely
    encrypted_key = get_encrypted_tsk()  # Implement based on your setup
    
    response = kms.decrypt(
        CiphertextBlob=encrypted_key,
        Recipient={
            'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
            'AttestationDocument': attestation_doc
        }
    )
    
    # 4. Return the plaintext key
    return response['Plaintext']

def get_encrypted_tsk():
    """
    Get the encrypted TSK blob.
    This could be passed via environment, file, or vsock.
    """
    # Placeholder - implement based on your key distribution strategy
    import os
    return base64.b64decode(os.environ.get('ENCRYPTED_TSK', ''))
```

## Step 5: Implement Agent Logic

```python
# enclave/agent.py
from crypto import encrypt, decrypt
import json

class AgentA:
    """
    Agent A: Generates initial state, encrypts and returns.
    """
    def __init__(self, tsk):
        self.tsk = tsk
    
    def process(self, input_data):
        """Generate initial state and encrypt."""
        # Generate initial state
        state = {
            'agent': 'A',
            'iteration': 1,
            'data': {
                'message': 'Initial state from Agent A',
                'input_received': input_data,
                'timestamp': self._get_timestamp()
            }
        }
        
        # Serialize and encrypt
        plaintext = json.dumps(state).encode('utf-8')
        ciphertext = encrypt(plaintext, self.tsk)
        
        return {
            'status': 'success',
            'ciphertext': ciphertext.hex()
        }
    
    def _get_timestamp(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()


class AgentB:
    """
    Agent B: Receives ciphertext, decrypts, modifies, re-encrypts.
    """
    def __init__(self, tsk):
        self.tsk = tsk
    
    def process(self, ciphertext_hex):
        """Decrypt, process, and re-encrypt."""
        # Decrypt incoming state
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = decrypt(ciphertext, self.tsk)
        state = json.loads(plaintext.decode('utf-8'))
        
        # Modify state
        state['agent'] = 'B'
        state['iteration'] += 1
        state['data']['processed_by_b'] = True
        state['data']['b_message'] = 'State modified by Agent B'
        state['data']['b_timestamp'] = self._get_timestamp()
        
        # Re-encrypt
        new_plaintext = json.dumps(state).encode('utf-8')
        new_ciphertext = encrypt(new_plaintext, self.tsk)
        
        return {
            'status': 'success',
            'ciphertext': new_ciphertext.hex()
        }
    
    def _get_timestamp(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()
```

## Step 6: Implement Crypto Utilities

```python
# enclave/crypto.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    Returns: nonce (12 bytes) + ciphertext + tag
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    Expects: nonce (12 bytes) + ciphertext + tag
    """
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    actual_ciphertext = ciphertext[12:]
    return aesgcm.decrypt(nonce, actual_ciphertext, None)
```

## Step 7: Build the Enclave Image

```bash
# Navigate to enclave directory
cd enclave

# Build Docker image
docker build -t confidential-enclave:latest .

# Build EIF (Enclave Image File)
nitro-cli build-enclave \
  --docker-uri confidential-enclave:latest \
  --output-file enclave.eif

# Note the PCR0 value from output!
# Update KMS policy with this value
```

## Step 8: Run the Enclave

```bash
# Run the enclave
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 1024 \
  --eif-path enclave.eif

# For debugging (allows console output)
nitro-cli run-enclave \
  --cpu-count 2 \
  --memory 1024 \
  --eif-path enclave.eif \
  --debug-mode
```

## Troubleshooting

### Issue: `FileNotFoundError: /dev/nsm`

**Cause**: Application not running inside an enclave

**Solution**: This is expected during development. Test with debug mode or mock the NSM.

### Issue: `socket.error: Address family not supported`

**Cause**: vsock not available (not in enclave or wrong kernel)

**Solution**: Verify running in enclave or use TCP for local testing.

### Issue: `KMS Decrypt failed`

**Cause**: Attestation document doesn't match KMS policy

**Solution**: Rebuild enclave and update KMS policy with new PCR0.

## Next Steps

- [05-host-worker-setup.md](./05-host-worker-setup.md) - Set up the host worker application
