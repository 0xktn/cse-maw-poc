import socket
import sys

def test_echo():
    cid = 16 # Default enclave CID
    port = 5000
    
    print(f"Connecting to Enclave CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((cid, port))
        print("Connected!")
        
        msg = b"Hello Enclave"
        print(f"Sending: {msg}")
        s.sendall(msg)
        
        response = s.recv(1024)
        print(f"Received: {response}")
        
        if response == msg:
            print("Echo Verified! SUCCESS")
            return True
        else:
            print(f"Echo Mismatch: {response}")
            return False
            
    except Exception as e:
        print(f"Connection Failed: {e}")
        return False
    finally:
        s.close()

if __name__ == "__main__":
    if test_echo():
        sys.exit(0)
    else:
        sys.exit(1)
