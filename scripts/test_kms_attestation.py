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
    
    # 1. Ping Test
    print("Sending Ping...")
    sock.sendall(json.dumps({"type": "ping"}).encode())
    resp = sock.recv(1024)
    print(f"Ping Response: {resp}")
    try:
        if json.loads(resp).get('status') != 'ok':
            print("Ping Failed!")
            return False
    except:
        print("Ping Response Invalid!")
        return False
        
    sock.close()
    
    # Reconnect for Configure
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.settimeout(60) # Apply timeout to the new socket as well
    sock.connect((16, 5000))

    # Fetch credentials from IMDS
    print("Fetching credentials from IMDS...")
    import urllib.request
    try:
        # Get Role Name
        req = urllib.request.Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        role_name = urllib.request.urlopen(req).read().decode()
        
        # Get Creds
        req = urllib.request.Request(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}")
        creds = json.loads(urllib.request.urlopen(req).read().decode())
        
        print(f"Got credentials for role: {role_name}")
        
    except Exception as e:
        print(f"Failed to fetch credentials from IMDS: {e}")
        # Fallback to env vars if available (e.g. for local debug)
        creds = {
            "AccessKeyId": os.environ.get("AWS_ACCESS_KEY_ID"),
            "SecretAccessKey": os.environ.get("AWS_SECRET_ACCESS_KEY"),
            "Token": os.environ.get("AWS_SESSION_TOKEN")
        }

    # Send configuration with encrypted TSK
    print("Sending Configuration with Encrypted TSK...")
    config_msg = {
        'type': 'configure',
        'kms_key_id': os.environ.get('KMS_KEY_ID', '901ee892-db48-4a51-903a-25d46a721c8e'),
        'encrypted_tsk': encrypted_tsk,
        'region': 'ap-southeast-1',
        'access_key_id': creds.get('AccessKeyId'),
        'secret_access_key': creds.get('SecretAccessKey'),
        'session_token': creds.get('Token')
    }
    sock.sendall(json.dumps(config_msg).encode())
    
    # Wait for response
    response = sock.recv(4096)
    print(f"Config Response: {response}")
    
    result = json.loads(response.decode())
    
    # FETCH LOGS NOW to see TSK details before potential crash
    print("\n📥 Fetching enclave logs (intermediate)...")
    try:
        log_sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        log_sock.settimeout(5)
        log_sock.connect((16, 5000))
        log_sock.sendall(json.dumps({'type': 'get_logs'}).encode())
        log_response = json.loads(log_sock.recv(16384).decode())
        print("=== ENCLAVE LOGS (Config Phase) ===")
        print(log_response.get('logs', 'No logs returned'))
        print("===================================\n")
        log_sock.close()
    except Exception as e:
        print(f"Failed to fetch intermediate logs: {e}")

    if result.get('status') == 'ok':
        print("✅ Configuration successful! TSK decrypted via kmstool with attestation!")
    else:
        print(f"❌ Configuration failed: {result}")
        sock.close() # Close the config socket on failure
        return False

    sock.close() # Close the config socket after successful configuration
    
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
        
        # Fetch enclave logs
        print("\n📥 Fetching enclave logs...")
        try:
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((16, 5000))
            sock.sendall(json.dumps({'type': 'get_logs'}).encode())
            log_response = json.loads(sock.recv(16384).decode())
            print("\n=== ENCLAVE LOGS ===")
            print(log_response.get('logs', 'No logs returned'))
            print("====================")
        except Exception as e:
            print(f"Failed to fetch logs: {e}")
            
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
