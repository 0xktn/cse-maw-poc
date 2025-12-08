# KMS Configuration

This guide covers AWS KMS setup for cryptographic attestation, enabling the enclave to securely retrieve the Trusted Session Key (TSK).

## Overview

AWS KMS integrates with Nitro Enclaves through **cryptographic attestation**. The enclave generates an attestation document signed by the Nitro Hypervisor, which KMS validates before releasing the decryption key.

```
┌─────────────┐     Attestation Doc     ┌─────────────┐
│   Enclave   │ ──────────────────────► │   AWS KMS   │
│             │ ◄────────────────────── │             │
└─────────────┘     Decrypted Key       └─────────────┘
```

## Prerequisites

- AWS CLI configured with appropriate permissions
- Your Enclave Image File (EIF) built (to obtain PCR0 hash)
- IAM permissions for KMS key management

## Step 1: Create KMS Key

### Using AWS Console

1. Navigate to **KMS** → **Customer managed keys**
2. Click **Create key**
3. Settings:
   - Key type: **Symmetric**
   - Key usage: **Encrypt and decrypt**
4. Add alias: `confidential-workflow-tsk`
5. Define key administrators
6. Define key usage permissions (will modify policy later)
7. Review and create

### Using AWS CLI

```bash
# Create the key
aws kms create-key \
  --description "Trusted Session Key for Confidential Multi-Agent Workflow" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT

# Note the KeyId from the output, then create an alias
aws kms create-alias \
  --alias-name alias/confidential-workflow-tsk \
  --target-key-id <KeyId>
```

## Step 2: Obtain Enclave PCR Values

When you build your enclave image, the `nitro-cli` outputs PCR (Platform Configuration Register) values:

```bash
nitro-cli build-enclave --docker-uri your-enclave-image:latest --output-file enclave.eif
```

Example output:
```
{
  "Measurements": {
    "HashAlgorithm": "Sha384",
    "PCR0": "abc123...def456",  # Enclave image hash
    "PCR1": "...",               # Kernel hash
    "PCR2": "..."                # Application hash
  }
}
```

> [!IMPORTANT]
> Save the **PCR0** value! This is your enclave's unique software identity and is required for the KMS policy.

## Step 3: Configure KMS Key Policy

The key policy enforces that only your specific enclave can decrypt data. Modify the policy to include attestation conditions:

```json
{
  "Version": "2012-10-17",
  "Id": "confidential-workflow-key-policy",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow Enclave Decrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:role/EnclaveInstanceRole"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "PCR0_VALUE_HERE"
        }
      }
    },
    {
      "Sid": "Allow Key Administrators",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:user/admin"
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}
```

### Apply the Policy

```bash
aws kms put-key-policy \
  --key-id alias/confidential-workflow-tsk \
  --policy-name default \
  --policy file://kms-policy.json
```

## Step 4: Create IAM Role for EC2 Instance

The EC2 instance needs an IAM role to communicate with KMS:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID"
    }
  ]
}
```

Attach this policy to your EC2 instance role.

## Step 5: Generate and Encrypt the TSK

For the POC, generate a Data Encryption Key (DEK) that will serve as the TSK:

```bash
# Generate a data key
aws kms generate-data-key \
  --key-id alias/confidential-workflow-tsk \
  --key-spec AES_256 \
  --output json > data-key.json

# The output contains:
# - Plaintext: Base64-encoded key (use for initial encryption, then discard)
# - CiphertextBlob: Encrypted key (store this, enclave will decrypt it)
```

> [!CAUTION]
> Never store the plaintext key. The enclave should be the only entity that receives the plaintext key through KMS decryption with attestation.

## Verification

### Test Key Policy (without attestation)

```bash
# This should FAIL if policy is correctly configured
aws kms decrypt \
  --key-id alias/confidential-workflow-tsk \
  --ciphertext-blob fileb://encrypted-key.bin
```

Expected error: `AccessDeniedException` (attestation required)

### Verify via CloudTrail

After enclave successfully decrypts:
1. Go to **CloudTrail** → **Event history**
2. Filter by Event name: `Decrypt`
3. Verify the event contains `attestationDocument` field

## Troubleshooting

### Issue: `KMS Decrypt failed - Invalid attestation document`

**Cause**: PCR0 in policy doesn't match current enclave image

**Solution**:
1. Rebuild enclave: `nitro-cli build-enclave ...`
2. Note the new PCR0 value
3. Update KMS key policy with new PCR0
4. Restart enclave

### Issue: `AccessDeniedException` even with valid attestation

**Cause**: IAM role missing KMS permissions

**Solution**: Verify the EC2 instance role has `kms:Decrypt` permission for the key

## Next Steps

- [03-temporal-setup.md](./03-temporal-setup.md) - Set up Temporal orchestration server
