import socket
import json
import sys

def test_iso_json():
    cid = 16
    port = 5000
    
    print(f"Connecting to Enclave CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        
        payload = json.dumps({"test": "hello_from_host"})
        print(f"Sending: {payload}")
        s.sendall(payload.encode('utf-8'))
        
        response = s.recv(4096)
        print(f"Response: {response}")
        
        if b"hello_from_host" in response:
            print("SUCCESS: JSON Roundtrip worked!")
            sys.exit(0)
        else:
            print("FAILURE: Invalid response.")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_iso_json()
