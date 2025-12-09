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
    KMS client using official AWS kmstool_enclave_cli for attestation.
    This calls the kmstool binary which handles NSM attestation internally.
    """
    def __init__(self, region='ap-southeast-1', proxy_port=8000):
        self.region = region
        self.proxy_port = proxy_port
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.aws_session_token = None
        print(f"[ENCLAVE] KMS Client initialized (region={region}, proxy_port={proxy_port})", flush=True)
    
    def set_credentials(self, access_key_id, secret_access_key, session_token):
        """Set AWS credentials for kmstool calls."""
        self.aws_access_key_id = access_key_id
        self.aws_secret_access_key = secret_access_key
        self.aws_session_token = session_token
        print("[ENCLAVE] AWS credentials configured", flush=True)

    def decrypt(self, encrypted_data_b64):
        """
        Decrypt KMS ciphertext using kmstool_enclave_cli with attestation.
        
        Args:
            encrypted_data_b64: Base64-encoded KMS ciphertext blob
            
        Returns:
            bytes: Decrypted plaintext (32 bytes for TSK)
        """
        try:
            print("[ENCLAVE] Calling kmstool_enclave_cli for KMS decrypt...", flush=True)
            
            # Build command with AWS credentials
            cmd = [
                '/usr/bin/kmstool_enclave_cli',
                'decrypt',
                '--region', self.region,
                '--proxy-port', str(self.proxy_port),
                '--ciphertext', encrypted_data_b64
            ]
            
            # Add AWS credentials if available
            if self.aws_access_key_id:
                cmd.extend(['--aws-access-key-id', self.aws_access_key_id])
            if self.aws_secret_access_key:
                cmd.extend(['--aws-secret-access-key', self.aws_secret_access_key])
            if self.aws_session_token:
                cmd.extend(['--aws-session-token', self.aws_session_token])
            
            print(f"[ENCLAVE] Running kmstool with credentials: {bool(self.aws_access_key_id)}", flush=True)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                print(f"[ENCLAVE] kmstool stderr: {error_msg}", flush=True)
                raise RuntimeError(f"kmstool_enclave_cli failed (exit {result.returncode}): {error_msg}")
            
            # kmstool outputs "PLAINTEXT: <base64>" format
            output = result.stdout.strip()
            print(f"[ENCLAVE] kmstool output: {output[:100]}...", flush=True)
            
            if output.startswith("PLAINTEXT:"):
                plaintext_b64 = output.split(":", 1)[1].strip()
            else:
                plaintext_b64 = output
            
            plaintext = base64.b64decode(plaintext_b64)
            
            print(f"[ENCLAVE] KMS Decrypt successful via kmstool! Plaintext length: {len(plaintext)} bytes", flush=True)
            return plaintext
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("kmstool_enclave_cli timed out after 30s")
        except Exception as e:
            print(f"[ERROR] KMS Decrypt via kmstool failed: {e}", flush=True)
            import traceback
            traceback.print_exc()
            raise

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
                encrypted_tsk = msg.get('encrypted_tsk', '')
                print(f"[ENCLAVE] Encrypted TSK length: {len(encrypted_tsk)}", flush=True)
                
                # Set AWS credentials if provided
                aws_access_key_id = msg.get('aws_access_key_id')
                aws_secret_access_key = msg.get('aws_secret_access_key')
                aws_session_token = msg.get('aws_session_token')
                
                if aws_access_key_id and aws_secret_access_key:
                    self.kms_client.set_credentials(
                        aws_access_key_id,
                        aws_secret_access_key,
                        aws_session_token
                    )
                else:
                    print("[ENCLAVE] WARNING: No AWS credentials provided", flush=True)
                
                # Decrypt TSK via kmstool
                tsk = self.kms_client.decrypt(encrypted_tsk)
                print(f"[ENCLAVE] TSK decrypted! Length: {len(tsk)} bytes, Type: {type(tsk)}", flush=True)
                print(f"[ENCLAVE] TSK (hex): {tsk.hex() if isinstance(tsk, bytes) else tsk}", flush=True)
                
                # Initialize encryption service
                self.cipher = EncryptionService(tsk)
                self.configured = True
                print("[ENCLAVE] Encryption service initialized", flush=True)
                conn.sendall(json.dumps({'status': 'ok'}).encode())
                
            elif msg_type == 'process':
                print("[ENCLAVE] Handling Process", flush=True)
                if not self.configured:
                    print("[ENCLAVE] ERROR: Not configured", flush=True)
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'not configured'}).encode())
                    return
                
                if not self.cipher:
                    print("[ENCLAVE] ERROR: Cipher is None", flush=True)
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'cipher not initialized'}).encode())
                    return
                
                payload = msg.get('payload')
                if not payload:
                    print("[ENCLAVE] ERROR: No payload in message", flush=True)
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'no payload'}).encode())
                    return
                
                print(f"[ENCLAVE] Decrypting payload (length: {len(payload)})", flush=True)
                plain = self.cipher.decrypt(payload)
                print(f"[ENCLAVE] Decrypted: {plain}", flush=True)
                
                # Prove we did something
                result = plain + " [ENCLAVE SIGNED]"
                print(f"[ENCLAVE] Encrypting result: {result}", flush=True)
                cipher_out = self.cipher.encrypt(result)
                print(f"[ENCLAVE] Encrypted result length: {len(cipher_out)}", flush=True)
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
