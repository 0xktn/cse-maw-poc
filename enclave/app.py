import socket
import sys

def run_server():
    cid = socket.VMADDR_CID_ANY
    port = 5000
    
    # Minimal Bind
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.bind((cid, port))
        s.listen(5)
    except Exception as e:
        # Can't report this unless we have a way out, but this is basic
        return

    while True:
        try:
            conn, addr = s.accept()
            
            try:
                conn.sendall(b"STEP1_START\n")
                
                import json
                conn.sendall(b"STEP2_JSON_OK\n")
                
                import cryptography
                conn.sendall(b"STEP3_CRYPTO_OK\n")
                
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                conn.sendall(b"STEP4_AESGCM_OK\n")
                
                with open("/usr/bin/kmstool_enclave_cli", "rb") as f:
                    pass
                conn.sendall(b"STEP5_KMSTOOL_FOUND\n")
                
            except Exception as e:
                conn.sendall(f"ERROR: {e}\n".encode())
            
            conn.close()
            
        except Exception:
            pass

if __name__ == "__main__":
    run_server()
