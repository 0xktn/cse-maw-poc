import socket
import sys

def test_diagnostic():
    cid = 16
    port = 5000
    
    print(f"Connecting to Enclave CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        
        # Send anything to trigger report
        s.sendall(b"status")
        
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
            
        print("\n--- Enclave Report ---")
        print(resp.decode('utf-8', errors='replace'))
        print("----------------------")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_diagnostic()
