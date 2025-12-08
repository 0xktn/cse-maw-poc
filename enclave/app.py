"""
Enclave Application Entry Point

Implements confidential processing with KMS attestation and AES-256-GCM encryption.
KMS configuration is received from host via vsock on first connection.
"""

import os
import sys
import json
import socket
import base64
import logging
from typing import Dict, Any, Optional

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KMSAttestationClient:
    """Handles KMS attestation and TSK decryption"""
    
    def __init__(self, kms_key_id: str, encrypted_tsk_b64: str, region: str = 'ap-southeast-1'):
        self.kms_key_id = kms_key_id
        self.encrypted_tsk = base64.b64decode(encrypted_tsk_b64)
        self.region = region
        self.tsk = None
        
    def get_attestation_document(self) -> bytes:
        """Generate attestation document from NSM device"""
        try:
            from nsm_util import nsm_get_attestation_doc
            doc = nsm_get_attestation_doc()
            return doc
        except Exception as e:
            logger.warning(f"NSM not available, using fallback: {e}")
            return b''
        
    def decrypt_tsk(self) -> bytes:
        """Request TSK from KMS with attestation"""
        logger.info("Requesting TSK from KMS...")
        
        try:
            client = boto3.client('kms', region_name=self.region)
            
            attestation_doc = self.get_attestation_document()
            
            if attestation_doc:
                # Production: decrypt with attestation
                response = client.decrypt(
                    CiphertextBlob=self.encrypted_tsk,
                    Recipient={
                        'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_256',
                        'AttestationDocument': attestation_doc
                    }
                )
                self.tsk = response['Plaintext']
                logger.info("TSK decrypted with attestation")
            else:
                # Fallback: decrypt without attestation
                logger.warning("Decrypting without attestation (testing mode)")
                response = client.decrypt(CiphertextBlob=self.encrypted_tsk)
                self.tsk = response['Plaintext']
                
            return self.tsk
            
        except Exception as e:
            logger.error(f"Failed to decrypt TSK: {e}")
            raise


class EncryptionService:
    """Handles AES-256-GCM encryption/decryption"""
    
    def __init__(self, tsk: bytes):
        self.aesgcm = AESGCM(tsk)
        logger.info("Encryption service initialized")
        
    def encrypt(self, plaintext: bytes) -> Dict[str, str]:
        """Encrypt with AES-256-GCM"""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode()
        }
        
    def decrypt(self, encrypted_data: Dict[str, str]) -> bytes:
        """Decrypt with AES-256-GCM"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        return self.aesgcm.decrypt(nonce, ciphertext, None)


class VsockServer:
    """vsock server for host communication"""
    
    def __init__(self, port: int = 5000):
        self.port = port
        self.encryption_service: Optional[EncryptionService] = None
        self.kms_client: Optional[KMSAttestationClient] = None
        self.configured = False
        
    def start(self):
        """Listen on vsock"""
        logger.info(f"Starting vsock server on port {self.port}...")
        
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.bind((socket.VMADDR_CID_ANY, self.port))
        sock.listen()
        
        logger.info("vsock server listening")
        
        while True:
            try:
                conn, addr = sock.accept()
                logger.info(f"Connection from {addr}")
                self.handle_request(conn)
            except Exception as e:
                logger.error(f"Error handling connection: {e}")
                
    def handle_request(self, conn: socket.socket):
        """Process request from host"""
        try:
            # Receive request
            data = conn.recv(8192)
            if not data:
                logger.warning("Empty request")
                conn.close()
                return
                
            request = json.loads(data.decode())
            request_type = request.get('type', 'process')
            
            # Handle configuration request
            if request_type == 'configure':
                logger.info("Received configuration from host")
                self.configure(request)
                response = json.dumps({'status': 'configured'})
                conn.sendall(response.encode())
                conn.close()
                return
            
            # Handle processing request
            if not self.configured:
                error = {'error': 'Enclave not configured'}
                conn.sendall(json.dumps(error).encode())
                conn.close()
                return
            
            # Process data
            input_data = request.get('data', '')
            result = f"Processed: {input_data}"
            
            # Encrypt result
            encrypted = self.encryption_service.encrypt(result.encode())
            logger.info("Result encrypted")
            
            # Send response
            response = json.dumps(encrypted)
            conn.sendall(response.encode())
            
        except Exception as e:
            logger.error(f"Error processing request: {e}", exc_info=True)
            error_response = json.dumps({'error': str(e)})
            try:
                conn.sendall(error_response.encode())
            except:
                pass
        finally:
            conn.close()
            
    def configure(self, config: Dict[str, Any]):
        """Configure enclave with KMS settings from host"""
        kms_key_id = config.get('kms_key_id')
        encrypted_tsk = config.get('encrypted_tsk')
        region = config.get('region', 'ap-southeast-1')
        
        if not kms_key_id or not encrypted_tsk:
            raise ValueError("Missing KMS configuration")
        
        logger.info(f"Configuring with KMS key: {kms_key_id[:20]}...")
        
        # Initialize KMS client and decrypt TSK
        self.kms_client = KMSAttestationClient(kms_key_id, encrypted_tsk, region)
        tsk = self.kms_client.decrypt_tsk()
        
        # Initialize encryption service
        self.encryption_service = EncryptionService(tsk)
        self.configured = True
        
        logger.info("Enclave configured successfully")


def main():
    """Main entry point"""
    logger.info("Starting enclave application...")
    logger.info("Waiting for configuration from host...")
    
    try:
        # Start vsock server (will receive config on first connection)
        server = VsockServer()
        server.start()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
