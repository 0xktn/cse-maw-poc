# Confidential Multi-Agent Workflow - Environment Configuration

## Overview

This directory contains environment configuration files for different deployment environments.

## Files

- **`production.env.example`** - Template for production configuration
- **`development.env`** - Development/testing configuration (debug mode enabled)
- **`.env`** - Your local configuration (gitignored, create from example)

## Usage

### Initial Setup

1. Copy the production example to create your local config:
   ```bash
   cp config/production.env.example .env
   ```

2. Edit `.env` with your specific values:
   ```bash
   # Update AWS region if needed
   AWS_REGION=your-region
   
   # KMS_KEY_ID will be set automatically by setup script
   # Or set manually if you have an existing key
   KMS_KEY_ID=your-key-id
   ```

3. Scripts will automatically load `.env` if it exists

### Configuration Variables

#### AWS Configuration
- `AWS_REGION` - AWS region for all resources (default: ap-southeast-1)
- `AWS_PROFILE` - AWS CLI profile to use (default: default)
- `KMS_KEY_ID` - KMS key ID (set by setup script or manually)

#### Enclave Configuration
- `ENCLAVE_CPU_COUNT` - Number of CPUs for enclave (default: 2)
- `ENCLAVE_MEMORY_MB` - Memory in MB for enclave (default: 2048 for prod, 1024 for dev)
- `ENCLAVE_CID` - Context ID for vsock communication (default: 16)
- `ENCLAVE_DEBUG_MODE` - Enable debug mode (default: false for prod, true for dev)

#### Temporal Configuration
- `TEMPORAL_HOST` - Temporal server address (default: localhost:7233)
- `TEMPORAL_NAMESPACE` - Temporal namespace (default: confidential-workflow-poc)
- `TASK_QUEUE` - Task queue name (default: confidential-workflow-tasks)

#### Security
- `PRODUCTION_MODE` - Enable production safety checks (default: true)

## Security Notes

### Debug Mode

**⚠️ CRITICAL**: Never enable `ENCLAVE_DEBUG_MODE=true` in production!

Debug mode disables Nitro Enclave security features:
- Allows console access to enclave
- Disables cryptographic attestation validation
- Reduces isolation guarantees

The `run-enclave.sh` script will warn you if debug mode is enabled in production.

### Production Checklist

Before deploying to production, verify:
- [ ] `ENCLAVE_DEBUG_MODE=false`
- [ ] `PRODUCTION_MODE=true`
- [ ] `ENCLAVE_MEMORY_MB=2048` (minimum for production workloads)
- [ ] KMS key policy has correct PCR0 value
- [ ] `.env` file is not committed to git

## Environment-Specific Configurations

### Development
Use `config/development.env` for local testing:
- Debug mode enabled
- Lower memory allocation (1024MB)
- Verbose logging

### Production
Use `config/production.env.example` as template:
- Debug mode disabled
- Higher memory allocation (2048MB)
- Structured logging
- Security validations enabled

## Troubleshooting

**Issue**: Scripts not loading configuration
- **Solution**: Ensure `.env` exists in project root or use `config/production.env.example`

**Issue**: Permission denied errors
- **Solution**: Check AWS credentials and IAM permissions

**Issue**: Enclave fails to start
- **Solution**: Verify memory and CPU settings match instance capabilities
