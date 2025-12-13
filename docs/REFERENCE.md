# System Reference & Troubleshooting

## Component Breakdown

| Component | Technology | Role |
|-----------|------------|------|
| Trusted Compute | AWS Nitro Enclaves | Isolated execution environment for Agent logic, responsible for decryption, processing, and encryption. |
| Orchestrator | Temporal | Manages workflow state transitions and persists encrypted blobs (Ciphertext). |
| Key Management | AWS KMS | Stores the Trusted Session Key (TSK). Releases the key only upon validating the Enclave's attestation document. |
| Host Interface | vsock | Facilitates local socket communication between the untrusted Parent Instance and the Trusted Enclave. |
| Serialization | Protocol Buffers | Provides schema-bound binary serialization to ensure type safety and prevent deserialization attacks at the TEE boundary. |

## Data Flow: The Secure State Loop

The workflow executes a sequential transfer of state between Agent A and Agent B following this protocol:

1. **Bootstrapping (Agent A)**: The enclave initializes and requests the Trusted Session Key (TSK) from AWS KMS. KMS validates the enclave's PCR0 (software identity) before releasing the key.
2. **Encryption (Agent A)**: Agent A generates initial state, serializes it via Protobuf, and encrypts it using the TSK. The resulting ciphertext is returned to the host.
3. **Persistence (Host)**: The Temporal Worker receives the ciphertext via vsock and returns it to the Temporal Server. The server persists this blob in the Event History.
4. **Handoff (Agent B)**: Temporal triggers the next workflow step. The host passes the ciphertext from history to a new enclave instance (Agent B).
5. **Decryption (Agent B)**: Agent B performs independent attestation to retrieve the TSK, decrypts the input ciphertext, processes the data, and returns a new encrypted result.

## KMS Attestation Setup

### Understanding PCR0

PCR0 (Platform Configuration Register 0) is a cryptographic hash of the enclave image file (EIF). AWS KMS uses this measurement to verify the enclave's identity before releasing decryption keys.

**Key Concept**: Every time you rebuild the enclave image, the PCR0 value changes. You must update the KMS key policy with the new PCR0 to maintain access.

### Initial Setup

The automated setup script handles KMS configuration, but if you need to manually update the policy:

```bash
# 1. Build the enclave image
cd enclave
docker build -t confidential-enclave .
nitro-cli build-enclave --docker-uri confidential-enclave:latest --output-file ../build/enclave.eif

# 2. Extract PCR0 from build output
# Look for: "PCR0": "ff332b26..."

# 3. Update KMS policy with new PCR0
 # This script updates the policy to allow the new enclave image
 ./scripts/setup-kms-policy.sh <PCR0_VALUE>
 
 # 4. (Optional) Rotate TSK if needed
 # ./scripts/setup-kms.sh
```

### Viewing Current PCR0

PCR0 changes with every enclave build. To view the current value:

```bash
# During build (shown in output)
nitro-cli build-enclave --docker-uri confidential-enclave:latest --output-file build/enclave.eif

# From running enclave (via verification)
./scripts/trigger.sh --verify --deep

# From build artifacts
cat build/enclave.eif.json | jq -r '.Measurements.PCR0'
```

**Note**: The setup script automatically extracts PCR0 and updates the KMS policy, so manual management is typically not needed.

## Security Considerations

> [!CAUTION]
> This is a Proof of Concept implementation. Do not use in production without thorough security review and hardening.

### Key Security Features

- **Zero-Trust Architecture**: The orchestration layer never has access to plaintext data
- **Hardware-Backed Attestation**: Cryptographic proof of code identity before key release
- **Ephemeral Keys**: Session keys exist only in enclave memory and are never persisted
- **Immutable Execution**: PCR measurements ensure only approved code can decrypt data

### Known Limitations

- **Single Region**: This POC assumes all components operate within a single AWS region
- **Key Rotation**: Manual key rotation procedures are not implemented
- **KMS Network Proxy**: The enclave currently uses a direct vsock proxy or internal stub for KMS; full production proxy requires dedicated sidecar.
- **Audit Logging**: Enhanced audit trails for compliance requirements need additional implementation
- **Network Isolation**: Additional network policies may be required for production deployments

## Troubleshooting

### Common Issues

#### KMS Attestation Failures

**Issue**: `KMS Decrypt failed - Invalid attestation document`
- **Cause**: PCR0 mismatch between EIF and KMS policy
- **Solution**: 
  ```bash
  # 1. Rebuild enclave and extract new PCR0
  nitro-cli build-enclave --docker-uri confidential-enclave:latest --output-file build/enclave.eif
  
  # 2. Update KMS policy
   ./scripts/setup-kms-policy.sh <PCR0_VALUE>
  
  # 3. Restart enclave
  nitro-cli terminate-enclave --all
  nitro-cli run-enclave --eif-path build/enclave.eif --enclave-cid 16 --cpu-count 2 --memory 2048
  ```

**Issue**: `AWS_IO_SOCKET_NOT_CONNECTED` or `connection failure`
- **Cause**: `vsock-proxy` not running
- **Solution**:
  ```bash
  # Start vsock-proxy
  pkill vsock-proxy || true
  vsock-proxy 8000 kms.ap-southeast-1.amazonaws.com 443 &
  ```

**Issue**: `AWS_IO_TLS_NEGOTIATION_TIMEOUT`
- **Cause**: CA certificates not found by kmstool
- **Solution**: Verify Dockerfile has CA certificate symlink:
  ```dockerfile
  RUN mkdir -p /etc/pki/tls/certs && \
      ln -s /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt
  ```

#### Enclave Issues

**Issue**: `vsock connection refused`
- **Cause**: Enclave not running or incorrect CID/port
- **Solution**: 
  ```bash
  # Check enclave status
  nitro-cli describe-enclaves
  
  # If not running, start it
  nitro-cli run-enclave --eif-path build/enclave.eif --enclave-cid 16 --cpu-count 2 --memory 2048
  
  # Check enclave console logs
  nitro-cli console --enclave-id <ENCLAVE_ID>
  ```

**Issue**: Enclave fails to start with "insufficient memory"
- **Cause**: HugePages not allocated
- **Solution**:
  ```bash
  # Restart allocator service
  sudo systemctl restart nitro-enclaves-allocator
  
  # Verify hugepages
  cat /proc/meminfo | grep HugePages
  ```

#### Temporal Issues

**Issue**: `Temporal workflow timeout`
- **Cause**: Enclave processing taking longer than workflow timeout
- **Solution**: Increase workflow timeout or optimize enclave processing logic

**Issue**: Worker can't find `encrypted-tsk.b64`
- **Cause**: Path resolution issue when worker runs from different directory
- **Solution**: Verify `activities.py` has correct path resolution (fixed in latest version)

**Issue**: IMDS timeout in worker
- **Cause**: Network latency or IMDS throttling
- **Solution**: Increase timeout in `activities.py` (currently set to 5 seconds)

#### CloudTrail Issues

**Issue**: `AccessDeniedException` when running verification
- **Cause**: Missing IAM permission for CloudTrail
- **Solution**:
  ```bash
  # Add CloudTrail permission to instance role
  aws iam put-role-policy --role-name EnclaveInstanceRole \
    --policy-name CloudTrailReadAccess \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudtrail:LookupEvents"],"Resource":"*"}]}'
  ```

**Issue**: No attestation documents found in CloudTrail
- **Cause**: CloudTrail has 5-15 minute delay, or no recent KMS calls from enclave
- **Solution**: Run a workflow with `./scripts/trigger.sh`, wait 2-5 minutes, then verify with `./scripts/trigger.sh --verify --deep`

## Performance Considerations

- **Enclave Memory**: Allocate sufficient memory (minimum 2048 MB required for modern Python crypto libraries).
- **vCPU Count**: At least 2 vCPUs required (1 for Kernel, 1 for App).
- **Network Latency**: vsock communication adds ~1-5ms overhead per call
- **Encryption Overhead**: AES-256-GCM encryption adds minimal overhead (<1ms for typical payloads)
