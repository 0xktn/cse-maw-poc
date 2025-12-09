import socket
import sys

def listen_for_death_rattle():
    port = 8000
    cid = socket.VMADDR_CID_ANY
    
    print(f"HOST: Listening for Death Rattle on CID {cid} Port {port}...")
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(1)
        
        conn, addr = s.accept()
        print(f"HOST: Connection from {addr}")
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
            
        print("\nHOST: End of Stream")
        conn.close()
        s.close()
            
    except Exception as e:
        print(f"HOST Error: {e}")

if __name__ == "__main__":
    listen_for_death_rattle()
