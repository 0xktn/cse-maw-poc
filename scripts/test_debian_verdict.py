import socket
import json
import sys

def test_debian_verdict():
    cid = 16
    port = 5000
    
    print(f"Connecting to Enclave CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        
        # 1. Send Invalid JSON
        print("Test 1: Sending Invalid JSON ('Hello')")
        s.sendall(b"Hello")
        resp1 = s.recv(4096)
        print(f"Response 1: {resp1}")
        
        if b"invalid_json" in resp1:
            print("PASS: Handled Invalid JSON safely.")
        else:
            print("FAIL: Did not handle invalid JSON as expected.")

        s.close()
        
        # 2. Send Valid JSON
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        
        print("\nTest 2: Sending Valid JSON ({'type': 'test'})")
        s.sendall(b'{"type": "test"}')
        resp2 = s.recv(4096)
        print(f"Response 2: {resp2}")
        
        if b"Debian Rocks" in resp2:
            print("PASS: Handled Valid JSON logic.")
        else:
            print("FAIL: Logic verification failed.")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_debian_verdict()
