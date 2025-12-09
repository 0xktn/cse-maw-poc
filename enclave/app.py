import socket
import sys
import time
import json
import base64
import os

# Critical: Force line buffering for stdout/stderr to ensure logs persist
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Critical: Print immediately to verify process start
print("[ENCLAVE] Python Process Started (PID {})".format(os.getpid()))

# Lazy/Safe imports
IMPORT_ERROR_TRACE = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    print(f"[ENCLAVE] Cryptography imported")
except Exception as e:
    import traceback
    IMPORT_ERROR_TRACE = f"{e}\n{traceback.format_exc()}"
    print(f"[ERROR] Cryptography import failed: {IMPORT_ERROR_TRACE}")
    AESGCM = None

try:
    import boto3
    print("[ENCLAVE] Boto3 imported")
except ImportError as e:
    print(f"[ERROR] Boto3 import failed: {e}")
    boto3 = None

try:
    import aws_nsm_interface
    print("[ENCLAVE] AWS NSM Interface imported")
except ImportError as e:
    print(f"[ERROR] AWS NSM Interface import failed: {e}")
    aws_nsm_interface = None

import io

class EnclaveLogger:
    def __init__(self):
        self.log_file = "/tmp/enclave.log"
    
    def log(self, message):
        # We rely on print() being redirected to the file by run.sh
        # But we can also explicitly write if needed.
        # Since run.sh does redirection, print is enough.
        print(f"[ENCLAVE] {message}")
        
    def get_logs(self):
        try:
            with open(self.log_file, "r") as f:
                return f.read()
        except Exception as e:
            return f"Error reading logs: {e}"

logger = EnclaveLogger()

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
        print(f"[ENCLAVE] KMS Client initialized (region={region}, proxy_port={proxy_port})")
    
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
            print(f"[ERROR] Cryptography module missing. Trace: {IMPORT_ERROR_TRACE}", flush=True)
            raise ImportError(f"Cryptography module missing. Trace: {IMPORT_ERROR_TRACE}")
            
        print(f"[ENCLAVE] EncryptionService init with key length: {len(key)} bytes, type: {type(key)}", flush=True)
        
        if len(key) != 32:
            print(f"[ERROR] Invalid key length: {len(key)}. Expected 32 bytes.", flush=True)
            if isinstance(key, bytes):
                print(f"[ERROR] Key dump (hex): {key.hex()}", flush=True)
            # Throw explicit error instead of silent truncation for debugging real flow
            raise ValueError(f"Invalid TSK length: {len(key)}. Expected 32 bytes.")
            
        self.aesgcm = AESGCM(key)
        print("[ENCLAVE] EncryptionService initialized successfully with AESGCM", flush=True)

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

# ... (KMSAttestationClient and EncryptionService use logger.log instead of print) ...

class EnclaveApp:
    def __init__(self):
        self.kms_client = KMSAttestationClient()
        self.cipher = None
        self.configured = False

    def handle_connection(self, conn, addr):
        logger.log(f"Conn from {addr}")
        try:
            data = conn.recv(8192)
            if not data: return
            
            try:
                msg = json.loads(data.decode('utf-8'))
            except:
                logger.log("ERROR: Bad JSON")
                return

            msg_type = msg.get('type')
            
            if msg_type == 'get_logs':
                conn.sendall(json.dumps({'status': 'ok', 'logs': logger.get_logs()}).encode())
                return
                
            if msg_type == 'configure':
                logger.log("Handling Configure")
                encrypted_tsk = msg.get('encrypted_tsk', '')
                logger.log(f"Encrypted TSK length: {len(encrypted_tsk)}")
                
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
                    logger.log("WARNING: No AWS credentials provided")
                
                # Decrypt TSK via kmstool
                tsk = self.kms_client.decrypt(encrypted_tsk)
                logger.log(f"TSK decrypted! Length: {len(tsk)} bytes, Type: {type(tsk)}")
                logger.log(f"TSK (hex): {tsk.hex() if isinstance(tsk, bytes) else tsk}")
                
                # Initialize encryption service
                self.cipher = EncryptionService(tsk)
                self.configured = True
                logger.log("Encryption service initialized")
                conn.sendall(json.dumps({'status': 'ok'}).encode())
                
            elif msg_type == 'process':
                logger.log("Handling Process")
                if not self.configured:
                    logger.log("ERROR: Not configured")
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'not configured'}).encode())
                    return
                
                if not self.cipher:
                    logger.log("ERROR: Cipher is None")
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'cipher not initialized'}).encode())
                    return
                
                payload = msg.get('payload')
                if not payload:
                    logger.log("ERROR: No payload in message")
                    conn.sendall(json.dumps({'status': 'error', 'msg': 'no payload'}).encode())
                    return
                
                logger.log(f"Decrypting payload (length: {len(payload)})")
                plain = self.cipher.decrypt(payload)
                logger.log(f"Decrypted: {plain}")
                
                # Prove we did something
                result = plain + " [ENCLAVE SIGNED]"
                logger.log(f"Encrypting result: {result}")
                cipher_out = self.cipher.encrypt(result)
                logger.log(f"Encrypted result length: {len(cipher_out)}")
                conn.sendall(json.dumps({'status': 'ok', 'result': cipher_out}).encode())
                
        except Exception as e:
            logger.log(f"ERROR Handler: {e}")
            import traceback
            traceback.print_exc()
            tb = traceback.format_exc()
            logger.log(f"Traceback: {tb}")
            conn.sendall(json.dumps({'status': 'error', 'exception': str(e), 'traceback': tb}).encode())
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
