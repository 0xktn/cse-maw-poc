import socket
import sys
import os
import base64
import subprocess
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Standard IO buffering
# We use explicit flush=True in prints

print("[ENCLAVE] Starting Full Logic App (Debian)...", flush=True)

# Global State
CREDENTIALS = {
    'ak': None,
    'sk': None,
    'token': None
}
ENCRYPTION_KEY = None # 32-byte TSK

def kms_decrypt(ciphertext_b64):
    print(f"[ENCLAVE] Decrypting ciphertext len={len(ciphertext_b64)}", flush=True)
    try:
        cmd = [
            '/usr/bin/kmstool_enclave_cli', 'decrypt',
            '--region', 'ap-southeast-1',
            '--proxy-port', '8000',
            '--aws-access-key-id', CREDENTIALS['ak'],
            '--aws-secret-access-key', CREDENTIALS['sk'],
            '--aws-session-token', CREDENTIALS['token'],
            '--ciphertext', ciphertext_b64
        ]
        
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        
        output = result.stdout.strip()
        # Parse PLAINTEXT: <base64>
        marker = "PLAINTEXT:"
        if marker in output:
            payload = output.split(marker, 1)[1].strip()
            return (base64.b64decode(payload), None)
        return (base64.b64decode(output), None)

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip()
        print(f"[ERROR] KMS Tool Failed: {err_msg}", flush=True)
        return (None, err_msg)
    except Exception as e:
        err_msg = str(e)
        print(f"[ERROR] KMS Decrypt Exception: {err_msg}", flush=True)
        return (None, err_msg)

def run_server():
    global ENCRYPTION_KEY
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(5)
        print(f"[ENCLAVE] Listening on {cid}:{port}", flush=True)
    except Exception as e:
        print(f"[FATAL] Bind failed: {e}", flush=True)
        return

    while True:
        try:
            conn, addr = s.accept()
            print(f"[ENCLAVE] Connect from {addr}", flush=True)
            
            # Read data
            data = conn.recv(16384) # 16KB buffer
            if not data:
                conn.close()
                continue
            
            try:
                msg = data.decode('utf-8')
                req = json.loads(msg)
                msg_type = req.get('type')
                
                response = {"status": "error", "msg": "unknown_type"}
                
                if msg_type == 'ping':
                    response = {"status": "ok", "msg": "pong"}
                    
                elif msg_type == 'configure':
                    CREDENTIALS['ak'] = req.get('access_key_id')
                    CREDENTIALS['sk'] = req.get('secret_access_key')
                    CREDENTIALS['token'] = req.get('session_token')
                    tsk_b64 = req.get('encrypted_tsk')
                    
                    if tsk_b64:
                        print("[ENCLAVE] Decrypting TSK...", flush=True)
                        tsk_bytes, err_details = kms_decrypt(tsk_b64)
                        if tsk_bytes:
                            ENCRYPTION_KEY = tsk_bytes
                            print(f"[ENCLAVE] TSK Set! (len={len(ENCRYPTION_KEY)})", flush=True)
                            response = {"status": "ok", "msg": "configured"}
                        else:
                            response = {"status": "error", "msg": "kms_decrypt_failed", "details": err_details}
                    else:
                         response = {"status": "error", "msg": "missing_tsk"}

                elif msg_type == 'process':
                     if not ENCRYPTION_KEY:
                         response = {"status": "error", "msg": "not_configured"}
                     else:
                         print("[ENCLAVE] Processing message...", flush=True)
                         # Logic for process would go here
                         # For now just return echo
                         response = {"status": "ok", "msg": "processed", "echo": req}

                conn.sendall(json.dumps(response).encode('utf-8'))
                
            except json.JSONDecodeError:
                conn.sendall(b'{"status": "error", "msg": "invalid_json"}')
            except Exception as e:
                print(f"[ERROR] Handler failed: {e}", flush=True)
                conn.sendall(b'{"status": "error", "msg": "internal_error"}')
                
            conn.close()
            
        except Exception as e:
            print(f"[FATAL] Loop error: {e}", flush=True)

if __name__ == "__main__":
    run_server()
