import socket
import sys
import time
import json
import base64
import os
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from botocore.config import Config

class KMSAttestationClient:
    def __init__(self):
        # Configure boto3 to use the vsock endpoint for KMS
        # Nitro Enclaves have a specific KMS proxy at standard vsock ports, 
        # but typical boto3 usage assumes IP networking. 
        # In a real deployed enclave, we need 'aws-nsm-interface' for attestation.
        # For this PoC, we will assume the host proxies KMS requests or we simulate.
        pass

    def decrypt(self, encrypted_data_b64):
        # Placeholder for full Attestation-based Decryption
        # In a real scenario, this involves:
        # 1. Getting Attestation Doc from NSM
        # 2. Calling kms.decrypt(CiphertextBlob=..., Recipient={AttestationDocument...})
        
        # For POC, simplified wrapper around standard boto3 if available, or simulation
        try:
             # Just a structural placeholder verifying imports work
             return b"DECRYPTED_KEY_PLACEHOLDER_32_BYTES__" 
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}", file=sys.stderr)
            raise

class EncryptionService:
    def __init__(self, key: bytes):
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> bytes:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce + ciphertext

    def decrypt(self, data: bytes) -> str:
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

def main():
    print("[ENCLAVE] App Starting...", flush=True)
    
    # 1. Initialize Services (Verify Imports fail fast)
    try:
        # Generate a dummy key for this stage to prove logic works without needing actual KMS connect yet
        # We want to isolate "App Logic" factor from "KMS Permission" factor
        traffic_key = b'0'*32 
        cipher = EncryptionService(traffic_key)
        print("[ENCLAVE] Crypto Initialized", flush=True)
    except Exception as e:
        print(f"[ENCLAVE] Crypto Init Failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Start Vsock Server
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    except AttributeError:
        s = socket.socket(40, socket.SOCK_STREAM)
        
    s.bind((cid, port))
    s.listen(1)
    print(f"[ENCLAVE] Listening on port {port}...", flush=True)
    
    while True:
        try:
            conn, addr = s.accept()
            print(f"[ENCLAVE] Connection from {addr}", flush=True)
            
            # Simple protocol: Receive data -> Encrypt it -> Send back
            data = conn.recv(4096)
            if data:
                print(f"[ENCLAVE] Received {len(data)} bytes", flush=True)
                # Parse if JSON or treating as raw string
                # For verification, we just treat as string
                try:
                    text_input = data.decode('utf-8').strip()
                    encrypted = cipher.encrypt(text_input)
                    # Return base64 encoded result
                    response = base64.b64encode(encrypted)
                    conn.sendall(response)
                    print("[ENCLAVE] Sent encrypted response", flush=True)
                except Exception as e:
                    err_msg = f"Error: {str(e)}".encode()
                    conn.sendall(err_msg)
            
            conn.close()
        except Exception as e:
            print(f"[ENCLAVE] Loop Error: {e}", flush=True)
            time.sleep(1)

if __name__ == "__main__":
    main()
