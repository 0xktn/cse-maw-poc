import socket
import sys
import os
import json
import subprocess

# Force line buffering
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

print("[ENCLAVE] Echo Server (Large Buffer) Starting...", flush=True)

def run_server():
    # Bind to CID_ANY port 5000
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(5) # Backlog
        
        print(f"[ENCLAVE] Listening on CID {cid} Port {port}", flush=True)
        
        while True:
            try:
                conn, addr = s.accept()
                print(f"[ENCLAVE] Connection from {addr}", flush=True)
                try:
                    data = conn.recv(8192)
                    if data:
                        print(f"[ENCLAVE] Received: {data}", flush=True)
                        conn.sendall(data) # Echo back
                        print(f"[ENCLAVE] Sent echo", flush=True)
                    else:
                        print(f"[ENCLAVE] Empty payload", flush=True)
                except Exception as e:
                    print(f"[ENCLAVE] Error handling: {e}", flush=True)
                finally:
                    conn.close()
                    print(f"[ENCLAVE] Connection closed", flush=True)
            except Exception as e:
                print(f"[ENCLAVE] Accept error: {e}", flush=True)
    except Exception as e:
         print(f"[ENCLAVE] Server bind error: {e}", flush=True)

if __name__ == "__main__":
    run_server()
