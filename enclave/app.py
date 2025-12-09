import socket
import sys
import os
import base64
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Force line buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("[ENCLAVE] Manual Handler V2 (Functional) Starting...", flush=True)

# Global State
CREDENTIALS = {
    'ak': None,
    'sk': None,
    'token': None
}
ENCRYPTION_KEY = None # 32-byte TSK

def kms_decrypt(ciphertext_b64):
    print(f"[ENCLAVE] Decrypting blob len={len(ciphertext_b64)}", flush=True)
    try:
        cmd = [
            '/usr/bin/kmstool_enclave_cli', 'decrypt',
            '--region', 'ap-southeast-1',
            '--proxy-port', '8000',
            '--ciphertext', ciphertext_b64
        ]
        if CREDENTIALS['ak']:
            cmd.extend(['--aws-access-key-id', CREDENTIALS['ak']])
        if CREDENTIALS['sk']:
            cmd.extend(['--aws-secret-access-key', CREDENTIALS['sk']])
        if CREDENTIALS['token']:
            cmd.extend(['--aws-session-token', CREDENTIALS['token']])
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        output = result.stdout.strip()
        if "PLAINTEXT:" in output:
            payload = output.split("PLAINTEXT:", 1)[1].strip()
            return base64.b64decode(payload)
        return base64.b64decode(output)
    except Exception as e:
        print(f"[ERROR] KMS Decrypt failed: {e}", flush=True)
        return None

def extract_val(msg_str, key):
    # Rudimentary JSON parser for specific keys
    if f'"{key}":' not in msg_str and f'"{key}":' not in msg_str: return None
    try:
        sub = msg_str.split(f'"{key}"')[1]
        # skip until colon
        sub = sub.split(':', 1)[1].strip()
        # skip quote
        if sub.startswith('"'):
            val = sub.split('"', 2)[1]
            return val
        return None
    except:
        return None

def run_server():
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(5)
        print(f"[ENCLAVE] Listening on CID {cid} Port {port}", flush=True)
    except Exception as e:
        print(f"[FATAL] Bind failed: {e}", flush=True)
        return

    while True:
        try:
            conn, addr = s.accept()
            print(f"[ENCLAVE] Connect from {addr}", flush=True)
            
            try:
                data = conn.recv(8192)
                if not data:
                    print("[ENCLAVE] Empty data", flush=True)
                    conn.close()
                    continue
                
                print(f"[ENCLAVE] Received {len(data)} bytes", flush=True)
                conn.sendall(data) # ECHO BACK (For Safety Check)

            except Exception as e_req:
                print(f"[ERROR] Request failed: {e_req}", flush=True)
            finally:
                conn.close()
        except Exception as e_acc:
             print(f"[FATAL] Accept failed: {e_acc}", flush=True)

if __name__ == "__main__":
    run_server()
