#!/usr/bin/env python3
"""
Test script to verify KMS attestation flow with kmstool_enclave_cli.
This script sends a configure message with encrypted TSK to trigger KMS decrypt.
"""
import socket
import json
import base64
import os

def test_kms_attestation():
    """Test that enclave can decrypt TSK using kmstool with attestation."""
    
    # Read encrypted TSK
    tsk_path = '/home/ec2-user/confidential-multi-agent-workflow/encrypted-tsk.b64'
    with open(tsk_path, 'r') as f:
        encrypted_tsk = f.read().strip()
    
    print(f"Encrypted TSK (first 80 chars): {encrypted_tsk[:80]}...")
    
    # Connect to enclave
    print("Connecting to Enclave CID 16 Port 5000...")
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(60)  # Longer timeout for KMS call
    sock.connect((16, 5000))
    print("Connected!")
    
    # Send configuration with encrypted TSK
    print("Sending Configuration with Encrypted TSK...")
    config_msg = {
        'type': 'configure',
        'kms_key_id': os.environ.get('KMS_KEY_ID', '901ee892-db48-4a51-903a-25d46a721c8e'),
        'encrypted_tsk': encrypted_tsk,
        'region': 'ap-southeast-1'
    }
    sock.sendall(json.dumps(config_msg).encode())
    
    # Wait for response
    response = sock.recv(4096)
    print(f"Config Response: {response}")
    
    result = json.loads(response.decode())
    if result.get('status') != 'ok':
        print(f"❌ Configuration failed: {result}")
        return False
    
    print("✅ Configuration successful! TSK decrypted via kmstool with attestation!")
    sock.close()
    
    # Now test processing
    print("\nTesting data processing with decrypted TSK...")
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((16, 5000))
    
    process_msg = {
        'type': 'process',
        'payload': base64.b64encode(b'Test data for encryption').decode()
    }
    sock.sendall(json.dumps(process_msg).encode())
    
    response = sock.recv(4096)
    result = json.loads(response.decode())
    
    if result.get('status') == 'ok':
        print(f"✅ Processing successful! Encrypted result: {result['result'][:80]}...")
        print("\n🎉 END-TO-END KMS ATTESTATION TEST PASSED!")
        return True
    else:
        print(f"❌ Processing failed: {result}")
        print(f"   Status: {result.get('status')}")
        print(f"   Exception: {result.get('exception')}")
        print(f"   Message: {result.get('msg')}")
        return False

if __name__ == '__main__':
    try:
        success = test_kms_attestation()
        exit(0 if success else 1)
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
