import socket
import sys
import os
import json
import base64
import subprocess
import time

# Force line buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("[ENCLAVE] App Starting (Full Logic)...", flush=True)

# Lazy imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print("[ENCLAVE] Cryptography imported")
except ImportError as e:
    print(f"[ERROR] Cryptography missing: {e}")
    AESGCM = None

class KMSAttestationClient:
    def __init__(self, region='ap-southeast-1', proxy_port=8000):
        self.region = region
        self.proxy_port = proxy_port
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.aws_session_token = None
        print(f"[ENCLAVE] KMS Client Init (region={region})")

    def set_credentials(self, ak, sk, token):
        self.aws_access_key_id = ak
        self.aws_secret_access_key = sk
        self.aws_session_token = token
        print("[ENCLAVE] Credentials updated")

    def decrypt(self, encrypted_data_b64):
        print("[ENCLAVE] Decrypting TSK...")
        cmd = [
            '/usr/bin/kmstool_enclave_cli', 'decrypt', 
            '--region', self.region,
            '--proxy-port', str(self.proxy_port),
            '--ciphertext', encrypted_data_b64
        ]
        if self.aws_access_key_id:
             cmd.extend(['--aws-access-key-id', self.aws_access_key_id])
        if self.aws_secret_access_key:
             cmd.extend(['--aws-secret-access-key', self.aws_secret_access_key])
        if self.aws_session_token:
             cmd.extend(['--aws-session-token', self.aws_session_token])
        
        print(f"[ENCLAVE] Executing kmstool...")
        try:
            # Check if binary exists
            if not os.path.exists('/usr/bin/kmstool_enclave_cli'):
                 raise FileNotFoundError("kmstool_enclave_cli not found at /usr/bin/kmstool_enclave_cli")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"[ERROR] kmstool failed: {result.stderr}")
                raise RuntimeError(f"kmstool failed: {result.stderr}")
                
            out = result.stdout.strip()
            print(f"[ENCLAVE] kmstool output length: {len(out)}")
            
            if out.startswith("PLAINTEXT:"):
                b64 = out.split(":", 1)[1].strip()
                return base64.b64decode(b64)
            return base64.b64decode(out)
        except Exception as e:
            print(f"[ERROR] Decrypt exception: {e}")
            raise

class EncryptionService:
    def __init__(self, key):
        print(f"[ENCLAVE] Init EncryptionService with key len={len(key)}")
        if len(key) != 32:
             raise ValueError(f"Invalid key length: {len(key)}")
        self.aesgcm = AESGCM(key)
    
    def encrypt(self, plaintext):
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, b64_data):
        raw = base64.b64decode(b64_data)
        nonce = raw[:12]
        ct = raw[12:]
        return self.aesgcm.decrypt(nonce, ct, None).decode()

class EnclaveApp:
    def __init__(self):
        self.kms = KMSAttestationClient()
        self.cipher = None
        print("[ENCLAVE] App Ready")

    def run_server(self):
        cid = socket.VMADDR_CID_ANY
        port = 5000
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(5)
        print(f"[ENCLAVE] Listening on {cid}:{port}")
        
        while True:
            try:
                conn, addr = s.accept()
                print(f"[ENCLAVE] Connection from {addr}")
                self.handle(conn)
            except Exception as e:
                print(f"[ERROR] Accept Loop: {e}")

    def handle(self, conn):
        try:
            data = conn.recv(8192)
            if not data: return
            
            try:
                msg = json.loads(data.decode())
            except Exception as e:
                print(f"[ERROR] JSON Decode: {e}")
                conn.sendall(json.dumps({'status': 'error', 'msg': f"JSON Error: {e}"}).encode())
                return

            mtype = msg.get('type')
            
            if mtype == 'ping':
                conn.sendall(json.dumps({'status': 'ok', 'msg': 'pong'}).encode())
                
            elif mtype == 'configure':
                print("[ENCLAVE] Configuring...")
                self.kms.set_credentials(
                    msg.get('aws_access_key_id'), 
                    msg.get('aws_secret_access_key'), 
                    msg.get('aws_session_token')
                )
                tsk = self.kms.decrypt(msg.get('encrypted_tsk'))
                self.cipher = EncryptionService(tsk)
                conn.sendall(json.dumps({'status': 'ok'}).encode())
                
            elif mtype == 'process':
                print("[ENCLAVE] Processing...")
                if self.cipher is None:
                    raise RuntimeError("Not Configured")
                payload = msg.get('payload')
                plain = self.cipher.decrypt(payload)
                processed = f"Processed: {plain}"
                enc_out = self.cipher.encrypt(processed)
                conn.sendall(json.dumps({'status': 'ok', 'result': enc_out}).encode())
                
            elif mtype == 'get_logs':
                # Return tail of log file
                try:
                    with open('/tmp/enclave.log', 'r') as f:
                        logs = f.read()[-4096:]
                except: logs = "No logs"
                conn.sendall(json.dumps({'status': 'ok', 'logs': logs}).encode())
                
            else:
                print(f"[ERROR] Unknown type: {mtype}")
                conn.sendall(json.dumps({'status': 'error', 'msg': f"Unknown type: {mtype}"}).encode())

        except Exception as e:
            print(f"[ERROR] Handle Exception: {e}")
            import traceback
            traceback.print_exc()
            conn.sendall(json.dumps({'status': 'error', 'msg': str(e)}).encode())
        finally:
            conn.close()

if __name__ == "__main__":
    EnclaveApp().run_server()
