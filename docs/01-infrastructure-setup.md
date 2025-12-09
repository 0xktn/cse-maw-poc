# Infrastructure Setup (Reference)

This doc explains what the automated scripts do. You don't need to run these manually.

## What `./scripts/setup.sh` Does

1. **Gets latest Amazon Linux 2023 AMI** via SSM parameter
2. **Creates key pair** (`~/.ssh/nitro-enclave-key.pem`)
3. **Creates security group** with SSH access from your IP
4. **Launches EC2** with Nitro Enclave enabled

## Instance Types

| Type | vCPUs | Memory | Use Case |
|------|-------|--------|----------|
| `m5.xlarge` | 4 | 16 GB | Dev/Test |
| `m5.2xlarge` | 8 | 32 GB | Production |

> [!IMPORTANT]
> Nitro Enclaves require at least 2 vCPUs and **2048 MB** reserved for the enclave to support Python `cryptography` + Runtime overhead.

## What `./scripts/setup-instance.sh` Does (run on EC2)

1. Updates system packages
2. Installs Nitro Enclaves CLI
3. Configures enclave allocator (2 vCPUs, 2GB RAM)
4. Installs Docker

## Manual Commands (Reference)

### Get Latest AMI

```bash
aws ssm get-parameters \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text
```

### Launch with Enclave

```bash
aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type m5.xlarge \
  --enclave-options 'Enabled=true'
```

## Next Steps

- [02-kms-configuration.md](./02-kms-configuration.md) - KMS details
