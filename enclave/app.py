import socket
import sys
import time
import json
import base64
import os

# Critical: Print immediately to verify process start
print("[ENCLAVE] Python Process Started (PID {})".format(os.getpid()), flush=True)

# Lazy/Safe imports
IMPORT_ERROR_TRACE = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print("[ENCLAVE] Cryptography imported", flush=True)
except Exception as e:
    import traceback
    IMPORT_ERROR_TRACE = f"{e}\n{traceback.format_exc()}"
    print(f"[ERROR] Cryptography import failed: {IMPORT_ERROR_TRACE}", flush=True)
    AESGCM = None

try:
    import boto3
    print("[ENCLAVE] Boto3 imported", flush=True)
except ImportError as e:
    print(f"[ERROR] Boto3 import failed: {e}", flush=True)
    boto3 = None

try:
    import aws_nsm_interface
    print("[ENCLAVE] AWS NSM Interface imported", flush=True)
except ImportError as e:
    print(f"[ERROR] AWS NSM Interface import failed: {e}", flush=True)
    aws_nsm_interface = None

class KMSAttestationClient:
    """
    Uses official AWS kmstool_enclave_cli for KMS operations with attestation.
    The binary is built from aws-nitro-enclaves-sdk-c and handles:
    - NSM device access for attestation document generation
    - KMS API calls with attestation
    """
    def __init__(self, region: str = 'ap-southeast-1', proxy_port: int = 8000):
        self.region = region
        self.proxy_port = proxy_port
        print(f"[ENCLAVE] KMS Client initialized (region={region}, proxy_port={proxy_port})", flush=True)

    def decrypt(self, encrypted_data_b64: str) -> bytes:
        """
        Use official AWS kmstool_enclave_cli for KMS decrypt with attestation.
        """
        import subprocess
        
        cmd = [
            '/usr/bin/kmstool_enclave_cli', 'decrypt',
            '--region', self.region,
            '--proxy-port', str(self.proxy_port),
            '--ciphertext', encrypted_data_b64
        ]
        
        print(f"[ENCLAVE] Running: {' '.join(cmd)}", flush=True)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[ERROR] kmstool stderr: {result.stderr}", flush=True)
            raise RuntimeError(f"kmstool decrypt failed: {result.stderr}")
        
        print("[ENCLAVE] KMS Decrypt successful (via kmstool)!", flush=True)
        return base64.b64decode(result.stdout.strip())

class EncryptionService:
    def __init__(self, key: bytes):
        if not AESGCM:
            raise ImportError(f"Cryptography module missing. Trace: {IMPORT_ERROR_TRACE}")
            
        if len(key) != 32:
            # Pad or truncate for stub stability if fallback key is wrong size
            key = (key * 32)[:32]
            
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt(self, data_b64: str) -> str:
        data = base64.b64decode(data_b64)
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

class EnclaveApp:
    def __init__(self):
        self.kms_client = KMSAttestationClient()
        self.cipher = None
        self.configured = False

    def handle_connection(self, conn, addr):
        print(f"[ENCLAVE] Conn from {addr}", flush=True)
        try:
            data = conn.recv(8192)
            if not data: return
            
            try:
                msg = json.loads(data.decode('utf-8'))
            except:
                print(f"[ERROR] Bad JSON", flush=True)
                return

            msg_type = msg.get('type')
            if msg_type == 'configure':
                print("[ENCLAVE] Handling Configure", flush=True)
                # Try real decrypt, fallback to dummy is handled in client
                tsk = self.kms_client.decrypt(msg.get('encrypted_tsk', ''))
                self.cipher = EncryptionService(tsk)
                self.configured = True
                conn.sendall(json.dumps({'status': 'ok'}).encode())
                
            elif msg_type == 'process':
                print("[ENCLAVE] Handling Process", flush=True)
                if not self.configured:
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'not configured'}).encode())
                    return
                
                plain = self.cipher.decrypt(msg.get('payload'))
                # Prove we did something
                result = plain + " [ENCLAVE SIGNED]"
                cipher_out = self.cipher.encrypt(result)
                conn.sendall(json.dumps({'status': 'ok', 'result': cipher_out}).encode())
                
        except Exception as e:
            print(f"[ERROR] Handler: {e}", flush=True)
            conn.sendall(json.dumps({'status': 'error', 'exception': str(e)}).encode())
        finally:
            conn.close()

    def run(self):
        cid = socket.VMADDR_CID_ANY
        port = 5000
        try:
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        except:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
        s.bind((cid, port))
        s.listen(1)
        print(f"[ENCLAVE] Listening on {port}", flush=True)
        
        while True:
            try:
                conn, addr = s.accept()
                self.handle_connection(conn, addr)
            except Exception as e:
                print(f"[ERROR] Loop: {e}", flush=True)
                time.sleep(1)

if __name__ == "__main__":
    main_app = EnclaveApp()
    main_app.run()
