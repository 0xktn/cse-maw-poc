# Infrastructure Setup

This guide covers AWS EC2 instance setup with Nitro Enclave support.

## Quick Start (Automated)

```bash
# Set your passphrase
echo "your-password" > INSECURE_PASSWORD_TEXT

# Run automated setup
./scripts/setup.sh --region ap-southeast-1
```

The script handles everything: AMI lookup, key pair, security group, EC2 launch.

---

## Manual Steps (Reference)

If you prefer manual setup or need to understand what the scripts do:

### Prerequisites

- AWS CLI installed and configured
- SSH key pair for EC2 access

### Instance Types

| Type | vCPUs | Memory | Use Case |
|------|-------|--------|----------|
| `m5.xlarge` | 4 | 16 GB | Dev/Test |
| `m5.2xlarge` | 8 | 32 GB | Production |

> [!IMPORTANT]
> Nitro Enclaves require at least 2 vCPUs and 512 MB reserved for the enclave.

### 1. Get Latest AMI

```bash
export AWS_REGION="ap-southeast-1"

export AMI_ID=$(aws ssm get-parameters \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' \
  --output text)
```

### 2. Launch Instance

```bash
aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type m5.xlarge \
  --key-name your-key \
  --enclave-options 'Enabled=true'
```

### 3. Install Nitro CLI (on EC2)

```bash
sudo dnf update -y
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo usermod -aG ne ec2-user
newgrp ne
```

### 4. Install Docker (on EC2)

```bash
sudo dnf install -y docker
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
newgrp docker
```

## Next Steps

- [02-kms-configuration.md](./02-kms-configuration.md) - Configure AWS KMS
