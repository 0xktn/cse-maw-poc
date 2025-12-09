"""
Temporal Activities

Activities that communicate with the enclave via vsock.
"""

import socket
import os
import json
import time
from datetime import datetime
from temporalio import activity
import logging
from functools import wraps

logger = logging.getLogger(__name__)


def get_kms_config():
    """Get KMS configuration from local files and AWS credentials from IMDS"""
    # Read from project root - handle both running from host/ and project root
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(current_dir) == 'host':
        project_root = os.path.dirname(current_dir)
    else:
        project_root = current_dir
    
    logger.info(f"Project root: {project_root}")
    
    # Get KMS key ID from state or environment
    kms_key_id = os.environ.get('KMS_KEY_ID', '')
    
    # Read encrypted TSK
    tsk_path = os.path.join(project_root, 'encrypted-tsk.b64')
    try:
        with open(tsk_path, 'r') as f:
            encrypted_tsk = f.read().strip()
        logger.info(f"Loaded encrypted TSK from {tsk_path}")
    except FileNotFoundError:
        logger.error(f"encrypted-tsk.b64 not found at {tsk_path}")
        encrypted_tsk = ''
    
    # Fetch AWS credentials from IMDS (v2)
    import requests
    try:
        # Get IMDSv2 session token
        token_response = requests.put(
            'http://169.254.169.254/latest/api/token',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'},
            timeout=5
        )
        token_response.raise_for_status()
        token = token_response.text
        
        # Get IAM role name (with token)
        role_response = requests.get(
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            headers={'X-aws-ec2-metadata-token': token},
            timeout=5
        )
        role_response.raise_for_status()
        role_name = role_response.text.strip()
        
        # Get credentials (with token)
        creds_response = requests.get(
            f'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}',
            headers={'X-aws-ec2-metadata-token': token},
            timeout=5
        )
        creds_response.raise_for_status()
        creds = creds_response.json()
        
        aws_access_key_id = creds['AccessKeyId']
        aws_secret_access_key = creds['SecretAccessKey']
        aws_session_token = creds['Token']
        logger.info("AWS credentials fetched from IMDS")
    except Exception as e:
        logger.error(f"Failed to fetch AWS credentials from IMDS: {e}")
        aws_access_key_id = None
        aws_secret_access_key = None
        aws_session_token = None
    
    return {
        'kms_key_id': kms_key_id,
        'encrypted_tsk': encrypted_tsk,
        'region': os.environ.get('AWS_REGION', 'ap-southeast-1'),
        'aws_access_key_id': aws_access_key_id,
        'aws_secret_access_key': aws_secret_access_key,
        'aws_session_token': aws_session_token
    }


# Global flag to track if enclave is configured
_enclave_configured = False


def retry_on_failure(max_retries=3, delay=1, backoff=2):
    """Decorator to retry function on failure with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = delay
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        logger.error(f"{func.__name__} failed after {max_retries} retries: {e}")
                        raise
                    
                    logger.warning(f"{func.__name__} failed (attempt {retries}/{max_retries}): {e}. Retrying in {current_delay}s...")
                    time.sleep(current_delay)
                    current_delay *= backoff
            
        return wrapper
    return decorator


@retry_on_failure(max_retries=3, delay=2)
def configure_enclave():
    """Send configuration to enclave on first use with retry logic"""
    global _enclave_configured
    
    if _enclave_configured:
        return
    
    logger.info("Configuring enclave with KMS settings...")
    
    config = get_kms_config()
    
    sock = None
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        logger.debug("Connecting to enclave at CID 16, port 5000...")
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
        
        if result.get('status') == 'ok':
            logger.info("Enclave configured successfully")
            _enclave_configured = True
        else:
            error_msg = result.get('msg', 'unknown error')
            error_details = result.get('details', '')
            raise Exception(f"Configuration failed: {error_msg}. Details: {error_details}")
    except socket.timeout:
        raise Exception("Timeout connecting to enclave. Is the enclave running? Check with 'nitro-cli describe-enclaves'")
    except ConnectionRefusedError:
        raise Exception("Connection refused by enclave. Ensure enclave is running and listening on port 5000")
    except Exception as e:
        # The retry decorator will log and re-raise, so we just re-raise here.
        # If this is the last retry, the decorator will log the final error.
        raise
    finally:
        if sock:
            sock.close()


@activity.defn
async def health_check() -> dict:
    """Health check activity to verify worker and enclave status"""
    return {
        "status": "healthy",
        "enclave_configured": _enclave_configured,
        "timestamp": datetime.utcnow().isoformat(),
        "worker": "running"
    }


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
            'payload': request_data
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
