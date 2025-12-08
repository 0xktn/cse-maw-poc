# Prerequisites

Install required tools and configure AWS access before running setup.

## 1. Install Tools

### AWS CLI

```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Verify
aws --version
```

### SQLite

```bash
# macOS (pre-installed)
sqlite3 --version

# Linux
sudo apt install sqlite3
```

## 2. Configure AWS

```bash
aws configure
# AWS Access Key ID: (from IAM console)
# AWS Secret Access Key: (from IAM console)
# Default region: ap-southeast-1
# Default output: json
```

Verify:
```bash
aws sts get-caller-identity
```

> [!NOTE]
> Your IAM user needs: `AmazonEC2FullAccess`, `AWSKeyManagementServicePowerUser`, `IAMFullAccess`

## 3. Setup Passphrase

```bash
echo "your-password" > INSECURE_PASSWORD_TEXT
```

## 4. Run Setup

```bash
./scripts/setup.sh
```

That's it! The script handles:
- EC2 instance with Nitro Enclave
- KMS key with attestation policy
- Temporal server (local Docker)

Check progress anytime:
```bash
./scripts/setup.sh --status
```

## Next Steps

After EC2 is running, SSH in and run:
```bash
./scripts/setup-instance.sh
```

Then see [04-enclave-development.md](./04-enclave-development.md) for building the enclave.
