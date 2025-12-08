# Temporal Setup

This guide covers setting up a Temporal server for workflow orchestration, with options for both Temporal Cloud and self-hosted deployments.

## Overview

Temporal provides durable workflow execution while only seeing encrypted ciphertext. In this architecture, Temporal:
- Manages workflow state transitions
- Persists encrypted blobs in Event History
- Never has access to plaintext data

## Option 1: Temporal Cloud (Recommended for Production)

Temporal Cloud is a fully managed service with built-in security, scalability, and support.

### Step 1: Create Temporal Cloud Account

1. Sign up at [cloud.temporal.io](https://cloud.temporal.io)
2. Create a new Namespace (e.g., `confidential-workflow-poc`)
3. Note your namespace address: `<namespace>.<account>.tmprl.cloud:7233`

### Step 2: Generate mTLS Certificates

Temporal Cloud requires mTLS for authentication:

```bash
# Generate CA and certificates using Temporal's tool or your preferred method
temporal-cloud-cert-generator \
  --namespace confidential-workflow-poc \
  --output-dir ./certs
```

This creates:
- `ca.pem` - Certificate Authority
- `client.pem` - Client certificate
- `client.key` - Client private key

### Step 3: Configure Connection

Create a configuration file for your workers:

```python
# temporal_config.py
TEMPORAL_CONFIG = {
    "host": "<namespace>.<account>.tmprl.cloud:7233",
    "namespace": "confidential-workflow-poc",
    "tls": True,
    "client_cert": "./certs/client.pem",
    "client_key": "./certs/client.key",
}
```

### Step 4: Store Certificates Securely

> [!CAUTION]
> Store certificates securely. Consider using AWS Secrets Manager or Parameter Store for production deployments.

```bash
# Example: Store in AWS Secrets Manager
aws secretsmanager create-secret \
  --name temporal-cloud-certs \
  --secret-string file://certs/client.pem

aws secretsmanager create-secret \
  --name temporal-cloud-key \
  --secret-string file://certs/client.key
```

---

## Option 2: Self-Hosted (Docker Compose)

For development or when you need full control over the infrastructure.

### Step 1: Clone Temporal Docker Compose

```bash
git clone https://github.com/temporalio/docker-compose.git temporal-docker
cd temporal-docker
```

### Step 2: Start Temporal Services

```bash
# Start with default settings (PostgreSQL)
docker-compose up -d

# Or with specific database
docker-compose -f docker-compose-postgres.yml up -d
```

This starts:
- **Temporal Server** (port 7233)
- **Temporal Web UI** (port 8080)
- **PostgreSQL** database

### Step 3: Verify Deployment

```bash
# Check running containers
docker-compose ps

# Access Web UI
open http://localhost:8080
```

### Step 4: Create Namespace

```bash
# Using Temporal CLI
temporal operator namespace create confidential-workflow-poc
```

### Step 5: Configure Connection

```python
# temporal_config.py
TEMPORAL_CONFIG = {
    "host": "localhost:7233",
    "namespace": "confidential-workflow-poc",
    "tls": False,  # Enable for production
}
```

---

## Production Considerations

### Security Hardening

For self-hosted production deployments:

1. **Enable TLS**: Configure mTLS between all components
2. **Network Isolation**: Deploy Temporal in private subnets
3. **Access Control**: Configure authorization (requires Temporal EE or custom auth)

```yaml
# docker-compose.override.yml
services:
  temporal:
    environment:
      - TEMPORAL_TLS_FRONTEND_CERT=...
      - TEMPORAL_TLS_FRONTEND_KEY=...
```

### High Availability

For production, consider:
- Multiple Frontend instances behind load balancer
- History service replication
- Matching service scaling
- Database replication (RDS Multi-AZ)

### Persistence Configuration

Default SQLite is not suitable for production. Configure external database:

```yaml
# docker-compose.override.yml
services:
  temporal:
    environment:
      - DB=postgresql
      - DB_PORT=5432
      - POSTGRES_HOST=your-rds-endpoint
      - POSTGRES_USER=temporal
      - POSTGRES_PASSWORD=${DB_PASSWORD}
```

---

## Testing the Connection

### Install Temporal CLI

```bash
# macOS
brew install temporal

# Linux
curl -sSf https://temporal.download/cli.sh | sh
```

### Test Connection

```bash
# For local
temporal workflow list --namespace confidential-workflow-poc

# For Temporal Cloud
temporal workflow list \
  --namespace confidential-workflow-poc \
  --address <namespace>.<account>.tmprl.cloud:7233 \
  --tls-cert-path ./certs/client.pem \
  --tls-key-path ./certs/client.key
```

### Run a Test Workflow

```bash
# Start a simple workflow to verify setup
temporal workflow start \
  --task-queue test-queue \
  --type TestWorkflow \
  --workflow-id test-001
```

## Troubleshooting

### Issue: Connection refused on port 7233

**Cause**: Temporal server not running or firewall blocking

**Solution**:
```bash
# Check if temporal is running
docker-compose ps
# Check port availability
nc -zv localhost 7233
```

### Issue: Namespace not found

**Cause**: Namespace not created or wrong name

**Solution**:
```bash
temporal operator namespace list
temporal operator namespace create <namespace>
```

### Issue: TLS handshake failed (Temporal Cloud)

**Cause**: Certificate mismatch or expired

**Solution**: Regenerate certificates and update configuration

## Next Steps

- [04-enclave-development.md](./04-enclave-development.md) - Develop the enclave application
