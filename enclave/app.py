import socket
import sys
import os
import base64
import subprocess
import traceback

# Force line buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("[ENCLAVE] Manual Handler App Starting...", flush=True)

# Lazy import cryptography to catch import errors safely
AESGCM = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print("[ENCLAVE] Cryptography module imported successfully", flush=True)
except ImportError as e:
    print(f"[ERROR] Cryptography import failed: {e}", flush=True)
except Exception as e:
    print(f"[ERROR] Cryptography import crashed: {e}", flush=True)

class KMSAttestationClient:
    def __init__(self, region='ap-southeast-1', proxy_port=8000):
        self.region = region
        self.proxy_port = proxy_port
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.aws_session_token = None
        print(f"[ENCLAVE] KMS Client initialized", flush=True)

    def set_credentials(self, access_key, secret_key, token):
        self.aws_access_key_id = access_key
        self.aws_secret_access_key = secret_key
        self.aws_session_token = token
        print("[ENCLAVE] Credentials updated", flush=True)

    def decrypt(self, ciphertext_b64):
        print(f"[ENCLAVE] Decrypting TSK (b64 length: {len(ciphertext_b64)})", flush=True)
        try:
            cmd = [
                '/usr/bin/kmstool_enclave_cli', 'decrypt',
                '--region', self.region,
                '--proxy-port', str(self.proxy_port),
                '--ciphertext', ciphertext_b64
            ]
            if self.aws_access_key_id:
                cmd.extend(['--aws-access-key-id', self.aws_access_key_id])
            if self.aws_secret_access_key:
                cmd.extend(['--aws-secret-access-key', self.aws_secret_access_key])
            if self.aws_session_token:
                cmd.extend(['--aws-session-token', self.aws_session_token])
            
            # Using partial=True to allow text decoding if possible, but we process bytes generally
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=True
            )
            
            output = result.stdout.strip()
            # Parse PLAINTEXT: <base64>
            if "PLAINTEXT:" in output:
                payload = output.split("PLAINTEXT:", 1)[1].strip()
                return base64.b64decode(payload)
            else:
                # Fallback
                return base64.b64decode(output)

        except subprocess.CalledProcessError as e:
            print(f"[ERROR] kmstool failed: {e.stderr}", flush=True)
            raise
        except Exception as e:
            print(f"[ERROR] Decrypt failed: {e}", flush=True)
            traceback.print_exc()
            raise

class EncryptionService:
    def __init__(self, key: bytes):
        if not AESGCM:
            raise ImportError("AESGCM not available")
        print(f"[ENCLAVE] Init EncryptionService with key len={len(key)}", flush=True)
        if len(key) != 32:
            raise ValueError(f"Key length {len(key)} != 32")
        self.aesgcm = AESGCM(key)
    
    def decrypt(self, nonce, ciphertext, aad=None):
        return self.aesgcm.decrypt(nonce, ciphertext, aad)

    def encrypt(self, nonce, plaintext, aad=None):
        return self.aesgcm.encrypt(nonce, plaintext, aad)

def run_server():
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    server_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        server_sock.bind((cid, port))
        server_sock.listen(5)
        print(f"[ENCLAVE] Listening on CID {cid} Port {port}", flush=True)
    except Exception as e:
        print(f"[FATAL] Bind failed: {e}", flush=True)
        return

    kms_client = KMSAttestationClient()
    encryption_service = None # Set after configure

    while True:
        try:
            conn, addr = server_sock.accept()
            print(f"[ENCLAVE] Connect from {addr}", flush=True)
            
            try:
                data = conn.recv(8192)
                if not data:
                    print("[ENCLAVE] Empty data", flush=True)
                    conn.close()
                    continue

                # MANUAL PARSING
                # We expect simple flat JSON: {"type": "...", "key": "...", ...}
                # Since we can't use json.loads, we will do basic substring search or regex
                # For safety and memory, we stick to substring search for 'type'
                
                # We work with BYTES if possible to avoid unicode decode crashes, 
                # but for simplicity let's try strict ascii decode first.
                try:
                    msg_str = data.decode('utf-8', errors='ignore')
                except Exception:
                    msg_str = ""

                print(f"[ENCLAVE] Received {len(data)} bytes", flush=True)

                if '"type": "ping"' in msg_str or '"type":"ping"' in msg_str:
                    conn.sendall(b'{"status": "ok", "msg": "pong"}')
                
                elif '"type": "configure"' in msg_str or '"type":"configure"' in msg_str:
                    print("[ENCLAVE] Handling Configure", flush=True)
                    try:
                        # Extract Creds manually - this is hacky but necessary
                        # expecting: "access_key_id": "...", "secret_access_key": "...", "session_token": "...", "encrypted_key": "..."
                        # We will use simple string splitting logic
                        
                        def extract_val(key):
                            if f'"{key}":' not in msg_str and f'"{key}":' not in msg_str: return None
                            # Find start of value
                            s_idx = msg_str.find(f'"{key}"') + len(key) + 2 # quote+key+quote
                            # Skip colon and whitespace
                            while s_idx < len(msg_str) and msg_str[s_idx] in ': "': s_idx += 1
                            # Find end quote
                            e_idx = msg_str.find('"', s_idx)
                            return msg_str[s_idx:e_idx]

                        ak = extract_val("access_key_id")
                        sk = extract_val("secret_access_key")
                        st = extract_val("session_token")
                        enc_key_b64 = extract_val("encrypted_key") # TSK
                        
                        if not (ak and sk and st and enc_key_b64):
                            print("[ERROR] Missing config fields", flush=True)
                            conn.sendall(b'{"status": "error", "msg": "missing_fields"}')
                        else:
                            kms_client.set_credentials(ak, sk, st)
                            tsk = kms_client.decrypt(enc_key_b64)
                            encryption_service = EncryptionService(tsk)
                            conn.sendall(b'{"status": "ok", "msg": "configured"}')
                            
                    except Exception as e:
                        print(f"[ERROR] Config failed: {e}", flush=True)
                        traceback.print_exc()
                        # Construct error JSON carefully
                        err_msg = str(e).replace('"', "'")
                        conn.sendall(f'{{"status": "error", "msg": "{err_msg}"}}'.encode())

                elif '"type": "process"' in msg_str or '"type":"process"' in msg_str:
                     print("[ENCLAVE] Handling Process", flush=True)
                     if not encryption_service:
                         conn.sendall(b'{"status": "error", "msg": "not_configured"}')
                     else:
                         try:
                             # Extract encrypted_data
                             # "encrypted_data": "base64..."
                             enc_data_b64 = extract_val("encrypted_data")
                             if not enc_data_b64:
                                 conn.sendall(b'{"status": "error", "msg": "missing_data"}')
                             else:
                                 # Decrypt 
                                 # (Assuming standard packing: nonce(12) + ciphertext)
                                 blob = base64.b64decode(enc_data_b64)
                                 nonce = blob[:12]
                                 ciphertext = blob[12:]
                                 
                                 plaintext_bytes = encryption_service.decrypt(nonce, ciphertext, None)
                                 plaintext = plaintext_bytes.decode('utf-8')
                                 
                                 # RE-ENCRYPT response?
                                 # For this simple verification, let's just return success or echo
                                 # But the response logic asked for specific format.
                                 # Implementation: encrypt("Processed: " + plaintext)
                                 
                                 response_text = f"Processed: {plaintext}"
                                 nonce_resp = os.urandom(12)
                                 cipher_resp = encryption_service.encrypt(nonce_resp, response_text.encode(), None)
                                 blob_resp = nonce_resp + cipher_resp
                                 blob_b64 = base64.b64encode(blob_resp).decode()
                                 
                                 resp_json = f'{{"status": "ok", "encrypted_data": "{blob_b64}"}}'
                                 conn.sendall(resp_json.encode())

                         except Exception as e:
                             print(f"[ERROR] Process failed: {e}", flush=True)
                             traceback.print_exc()
                             err_msg = str(e).replace('"', "'")
                             conn.sendall(f'{{"status": "error", "msg": "{err_msg}"}}'.encode())
                
                else:
                    print(f"[ENCLAVE] Unknown message type: {msg_str[:50]}", flush=True)
                    conn.sendall(b'{"status": "error", "msg": "unknown_type"}')

            except Exception as e:
                print(f"[ERROR] Request handling failed: {e}", flush=True)
                traceback.print_exc()
            finally:
                conn.close()

        except Exception as e:
            print(f"[FATAL] Accept loop error: {e}", flush=True)

if __name__ == "__main__":
    run_server()
