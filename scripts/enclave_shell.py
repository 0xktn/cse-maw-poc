import socket
import sys

def run_shell_cmd():
    cid = 16
    port = 5000
    
    if len(sys.argv) < 2:
        print("Usage: python3 enclave_shell.py <command>")
        sys.exit(1)
        
    cmd = " ".join(sys.argv[1:])
    print(f"Sending Command: {cmd}")
    
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((cid, port))
        
        s.sendall(cmd.encode('utf-8'))
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
            
        print("--- Output ---")
        print(response.decode('utf-8', errors='replace'))
        print("--------------")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_shell_cmd()
