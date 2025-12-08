# KMS Configuration

This guide covers AWS KMS setup for cryptographic attestation with Nitro Enclaves.

## Quick Start (Automated)

```bash
./scripts/setup-kms.sh
```

After building your enclave, apply the attestation policy:

```bash
./scripts/setup-kms-policy.sh <PCR0_VALUE>
```

---

## Manual Steps (Reference)

### 1. Create KMS Key

```bash
export AWS_REGION="ap-southeast-1"

KEY_ID=$(aws kms create-key \
  --description "Trusted Session Key for Confidential Workflow" \
  --query 'KeyMetadata.KeyId' \
  --output text)

aws kms create-alias \
  --alias-name alias/confidential-workflow-tsk \
  --target-key-id $KEY_ID
```

### 2. Create IAM Role

```bash
# Create role for EC2
aws iam create-role \
  --role-name EnclaveInstanceRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach KMS decrypt permission
aws iam put-role-policy \
  --role-name EnclaveInstanceRole \
  --policy-name KMSDecryptPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
    }]
  }'
```

### 3. Apply Attestation Policy

After building your enclave (`nitro-cli build-enclave`), get the PCR0 value and apply:

```bash
aws kms put-key-policy \
  --key-id $KEY_ID \
  --policy-name default \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowRoot",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"},
        "Action": "kms:*",
        "Resource": "*"
      },
      {
        "Sid": "AllowEnclaveDecrypt",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/EnclaveInstanceRole"},
        "Action": "kms:Decrypt",
        "Resource": "*",
        "Condition": {
          "StringEqualsIgnoreCase": {
            "kms:RecipientAttestation:ImageSha384": "PCR0_VALUE"
          }
        }
      }
    ]
  }'
```

## Next Steps

- [03-temporal-setup.md](./03-temporal-setup.md) - Set up Temporal server
