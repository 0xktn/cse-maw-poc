import socket
import sys
import os
import base64
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Force line buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("[ENCLAVE] Bytes-Native Handler Starting...", flush=True)

# Global State
CREDENTIALS = {
    'ak': None,
    'sk': None,
    'token': None
}
ENCRYPTION_KEY = None # 32-byte TSK

def kms_decrypt_bytes(ciphertext_b64_bytes):
    # Expects bytes input
    print(f"[ENCLAVE] Decrypt (Bytes) len={len(ciphertext_b64_bytes)}", flush=True)
    try:
        cmd = [
            '/usr/bin/kmstool_enclave_cli', 'decrypt',
            '--region', 'ap-southeast-1',
            '--proxy-port', '8000',
            '--ciphertext', ciphertext_b64_bytes.decode('ascii') # Argument must be str for Popen args usually, but let's try strict ascii
        ]
        
        # Args
        if CREDENTIALS['ak']:
            cmd.extend(['--aws-access-key-id', CREDENTIALS['ak'].decode('ascii')])
        if CREDENTIALS['sk']:
            cmd.extend(['--aws-secret-access-key', CREDENTIALS['sk'].decode('ascii')])
        if CREDENTIALS['token']:
            cmd.extend(['--aws-session-token', CREDENTIALS['token'].decode('ascii')])
        
        # capture_output=True returns bytes in stdout if text=False (default)
        result = subprocess.run(
            cmd, capture_output=True, check=True
        )
        
        output = result.stdout.strip()
        # Parse PLAINTEXT: <base64> (In verification we saw "PLAINTEXT: ...")
        # All bytes
        marker = b"PLAINTEXT:"
        if marker in output:
            payload = output.split(marker, 1)[1].strip()
            return base64.b64decode(payload)
        return base64.b64decode(output)

    except Exception as e:
        print(f"[ERROR] KMS Decrypt failed: {e}", flush=True)
        return None

def extract_val_bytes(msg_bytes, key_bytes):
    # Rudimentary JSON bytes parser
    # key_bytes should be b'key'
    # Look for b'"key":'
    search_key = b'"' + key_bytes + b'":'
    if search_key not in msg_bytes:
        # try with space
        search_key = b'"' + key_bytes + b'" :'
        if search_key not in msg_bytes:
            return None
            
    try:
        # Split by key
        sub = msg_bytes.split(b'"' + key_bytes + b'"')[1]
        # skip until colon
        sub = sub.split(b':', 1)[1].strip()
        # check if string value
        if sub.startswith(b'"'):
            # extract string content
            val = sub.split(b'"', 2)[1]
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
                    conn.close()
                    continue
                
                print(f"[ENCLAVE] Recv {len(data)} bytes", flush=True)

                if b'ping' in data:
                    print("[ENCLAVE] Ping detected", flush=True)
                    conn.sendall(b'{"status": "ok", "msg": "pong"}')
                else:
                    conn.sendall(data) # ECHO BACK

            except Exception as e_req:
                print(f"[ERROR] Request failed: {e_req}", flush=True)
            finally:
                conn.close()
        except Exception as e_acc:
             print(f"[FATAL] Accept failed: {e_acc}", flush=True)

if __name__ == "__main__":
    run_server()
