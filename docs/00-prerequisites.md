# Prerequisites

Before starting, ensure you have the required tools and AWS access configured.

## Required Tools

### AWS CLI

```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify
aws --version
```

### Docker

```bash
# macOS
brew install --cask docker

# Linux (Ubuntu/Debian)
sudo apt update
sudo apt install docker.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

### SQLite

```bash
# macOS (pre-installed)
sqlite3 --version

# Linux
sudo apt install sqlite3
```

## AWS Configuration

### 1. Create IAM User

1. Go to [IAM Console](https://console.aws.amazon.com/iam/)
2. Create user with programmatic access
3. Attach policies:
   - `AmazonEC2FullAccess`
   - `AWSKeyManagementServicePowerUser`
   - `IAMFullAccess`

### 2. Configure CLI

```bash
aws configure
# Enter:
#   AWS Access Key ID
#   AWS Secret Access Key
#   Default region: ap-southeast-1
#   Default output format: json
```

### 3. Verify Access

```bash
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDAXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-user"
}
```

## State Passphrase

The setup scripts use encrypted local state. Create a passphrase file:

```bash
echo "your-password" > INSECURE_PASSWORD_TEXT
```

> [!NOTE]
> This file is gitignored. For interactive use, you can skip this and enter the passphrase when prompted.

## Next Steps

- [01-infrastructure-setup.md](./01-infrastructure-setup.md) - Set up EC2 with Nitro Enclaves
