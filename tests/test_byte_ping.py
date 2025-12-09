import socket
import sys

def test_ping():
    cid = 16
    port = 5000
    
    print(f"Connecting to Enclave CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        print("Connected!")
        
        msg = b'ping'
        print(f"Sending: {msg}")
        s.sendall(msg)
        
        response = s.recv(1024)
        print(f"Response: {response}")
        
        if response == b'pong':
            print("SUCCESS: Exact Match Ping worked.")
            sys.exit(0)
        elif response == msg:
            print("FAILURE: Echoed back (Match failed).")
            sys.exit(1)
        else:
            print(f"FAILURE: Unexpected response: {response}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(2)
        
if __name__ == "__main__":
    test_ping()
