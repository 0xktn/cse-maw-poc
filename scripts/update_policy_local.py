import boto3
import json
import os
import secrets
import base64

def update_policy_and_encrypt():
    # PCR0 from Build Attempt 19 (Official Source Build + TLS Fix)
    EXPECTED_PCR0 = "ff332b261c7e90783f1782aad362dd1c9f0cd75f95687f78816933145c62a78c18b8fbe644adadd116a2d4305b888994"
    region = "ap-southeast-1"
    key_id = "901ee892-db48-4a51-903a-25d46a721c8e"
    account_id = "345594574230"
    role_name = "EnclaveInstanceRole"
    
    session = boto3.Session(profile_name='default', region_name=region)
    kms = session.client('kms')
    
    print(f"Updating Policy for Key {key_id}...")
    
    policy = {
      "Version": "2012-10-17",
      "Id": "confidential-workflow-key-policy",
      "Statement": [
        {
          "Sid": "Enable IAM User Permissions",
          "Effect": "Allow",
          "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
          "Action": "kms:*",
          "Resource": "*"
        },
        {
          "Sid": "Allow Enclave Decrypt",
          "Effect": "Allow",
          "Principal": {"AWS": f"arn:aws:iam::{account_id}:role/{role_name}"},
          "Action": "kms:Decrypt",
          "Resource": "*",
          "Condition": {
            "StringEqualsIgnoreCase": {
              "kms:RecipientAttestation:ImageSha384": EXPECTED_PCR0
            }
          }
        }
      ]
    }
    
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName='default',
        Policy=json.dumps(policy)
    )
    print("Policy Updated!")
    
    print("Generating and Encrypting TSK...")
    # Generate 32 bytes TSK
    tsk = secrets.token_bytes(32)
    
    # Encrypt
    resp = kms.encrypt(
        KeyId=key_id,
        Plaintext=tsk
    )
    
    ciphertext = resp['CiphertextBlob']
    b64_cipher = base64.b64encode(ciphertext).decode('utf-8')
    
    with open('encrypted-tsk.b64.local', 'w') as f:
        f.write(b64_cipher)
        
    print("Saved encrypted-tsk.b64.local")

if __name__ == "__main__":
    update_policy_and_encrypt()
