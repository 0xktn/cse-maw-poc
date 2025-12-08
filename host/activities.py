"""
Temporal Activities

Activities that communicate with the enclave via vsock.
"""

import socket
import json
import logging
import os
from temporalio import activity

logger = logging.getLogger(__name__)


def get_kms_config():
    """Get KMS configuration from local files"""
    # Read from project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Get KMS key ID from state or environment
    kms_key_id = os.environ.get('KMS_KEY_ID', '')
    
    # Read encrypted TSK
    tsk_path = os.path.join(project_root, 'encrypted-tsk.b64')
    try:
        with open(tsk_path, 'r') as f:
            encrypted_tsk = f.read().strip()
    except FileNotFoundError:
        logger.error(f"encrypted-tsk.b64 not found at {tsk_path}")
        encrypted_tsk = ''
    
    return {
        'kms_key_id': kms_key_id,
        'encrypted_tsk': encrypted_tsk,
        'region': os.environ.get('AWS_REGION', 'ap-southeast-1')
    }


# Global flag to track if enclave is configured
_enclave_configured = False


def configure_enclave():
    """Send configuration to enclave on first use"""
    global _enclave_configured
    
    if _enclave_configured:
        return
    
    logger.info("Configuring enclave with KMS settings...")
    
    config = get_kms_config()
    
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((16, 5000))
        
        # Send configuration
        config_request = {
            'type': 'configure',
            **config
        }
        sock.sendall(json.dumps(config_request).encode())
        
        # Wait for confirmation
        response = sock.recv(4096)
        result = json.loads(response.decode())
        
        sock.close()
        
        if result.get('status') == 'configured':
            logger.info("Enclave configured successfully")
            _enclave_configured = True
        else:
            raise Exception(f"Configuration failed: {result}")
            
    except Exception as e:
        logger.error(f"Failed to configure enclave: {e}")
        raise


@activity.defn
async def process_in_enclave(request_data: str) -> str:
    """
    Send data to enclave for confidential processing via vsock.
    
    Returns encrypted blob as JSON string.
    """
    # Configure enclave on first use
    if not _enclave_configured:
        configure_enclave()
    
    logger.info(f"Sending to enclave: {request_data[:50]}...")
    
    try:
        # Connect to enclave
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((16, 5000))
        
        # Send processing request
        request = {
            'type': 'process',
            'data': request_data
        }
        sock.sendall(json.dumps(request).encode())
        
        # Receive encrypted response
        response_data = sock.recv(8192)
        encrypted_result = json.loads(response_data.decode())
        
        sock.close()
        
        if 'error' in encrypted_result:
            raise Exception(encrypted_result['error'])
        
        logger.info("Received encrypted result from enclave")
        
        # Return encrypted blob as JSON string
        return json.dumps(encrypted_result)
        
    except Exception as e:
        logger.error(f"Failed to communicate with enclave: {e}")
        raise
