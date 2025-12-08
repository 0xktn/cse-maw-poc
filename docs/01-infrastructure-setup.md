# Infrastructure Setup

This guide covers the AWS EC2 instance setup with Nitro Enclave support for running the Confidential Multi-Agent Workflow.

## Prerequisites

- AWS Account with appropriate permissions
- AWS CLI installed and configured
- SSH key pair for EC2 access

## EC2 Instance Requirements

### Supported Instance Types

Nitro Enclaves require specific instance types. Recommended options:

| Instance Type | vCPUs | Memory | Use Case |
|---------------|-------|--------|----------|
| `m5.xlarge` | 4 | 16 GB | Development/Testing |
| `c5.xlarge` | 4 | 8 GB | Compute-intensive workloads |
| `m5.2xlarge` | 8 | 32 GB | Production workloads |

> [!IMPORTANT]
> Nitro Enclaves require at least 2 vCPUs and 512 MB of memory allocated to the enclave. Plan your instance size accordingly.

## Step 1: Launch EC2 Instance

### Using AWS Console

1. Navigate to **EC2 Dashboard** → **Launch Instance**
2. Select **Amazon Linux 2023** AMI
3. Choose an enclave-supported instance type (e.g., `m5.xlarge`)
4. Configure instance details:
   - Enable **Enclave** under Advanced Details
5. Configure storage (minimum 30 GB recommended)
6. Configure security group:
   - SSH (port 22) from your IP
   - Any ports needed for Temporal communication
7. Launch with your key pair

### Using AWS CLI

```bash
aws ec2 run-instances \
  --image-id ami-xxxxxxxxxxxxxxxxx \
  --instance-type m5.xlarge \
  --key-name your-key-pair \
  --enclave-options 'Enabled=true' \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=nitro-enclave-poc}]'
```

> [!NOTE]
> Replace `ami-xxxxxxxxxxxxxxxxx` with the latest Amazon Linux 2023 AMI ID for your region.

## Step 2: Install Nitro Enclaves CLI

SSH into your instance and run:

```bash
# Update system packages
sudo dnf update -y

# Install Nitro Enclaves CLI
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Start and enable the allocator service
sudo systemctl start nitro-enclaves-allocator.service
sudo systemctl enable nitro-enclaves-allocator.service

# Add your user to the ne group
sudo usermod -aG ne ec2-user

# Verify installation
nitro-cli --version
```

## Step 3: Configure Enclave Allocator

Edit the allocator configuration to reserve resources for enclaves:

```bash
sudo nano /etc/nitro_enclaves/allocator.yaml
```

Recommended configuration:

```yaml
# /etc/nitro_enclaves/allocator.yaml
---
# Memory in MiB to allocate for enclaves
memory_mib: 2048

# Number of CPUs to reserve for enclaves
cpu_count: 2

# CPU pool (optional, for NUMA optimization)
# cpu_pool: 1-3
```

Restart the allocator service:

```bash
sudo systemctl restart nitro-enclaves-allocator.service
```

## Step 4: Verify Setup

```bash
# Check allocator status
sudo systemctl status nitro-enclaves-allocator.service

# Verify enclave resources
nitro-cli describe-enclaves

# Run a test enclave (optional)
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path /usr/share/nitro_enclaves/examples/hello.eif --debug-mode
```

## Step 5: Install Docker (Required for Building EIFs)

```bash
# Install Docker
sudo dnf install -y docker

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker ec2-user

# Log out and back in for group changes to take effect
```

## Troubleshooting

### Issue: Enclave allocator fails to start

**Cause**: Insufficient resources or enclave not enabled on instance

**Solution**:
1. Verify instance has enclave support: `aws ec2 describe-instances --instance-ids <id> --query 'Reservations[].Instances[].EnclaveOptions'`
2. Check allocator logs: `sudo journalctl -u nitro-enclaves-allocator.service`

### Issue: Permission denied when running nitro-cli

**Cause**: User not in `ne` group

**Solution**:
```bash
sudo usermod -aG ne $USER
# Log out and back in
```

## Next Steps

- [02-kms-configuration.md](./02-kms-configuration.md) - Configure AWS KMS for attestation-based key access
