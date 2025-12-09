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
            
            # Diagnostic Report
            report = ["Enclave Alive"]
            
            # Check Imports
            try:
                import json
                report.append("Import json: OK")
            except ImportError as e:
                report.append(f"Import json: FAIL ({e})")

            try:
                import cryptography
                report.append("Import cryptography: OK")
            except ImportError as e:
                report.append(f"Import cryptography: FAIL ({e})")
                
            try:
                import requests 
                # We expect fail or not installed, but checking standard lib behavior
            except ImportError:
                 pass
            
            # Check File System
            try:
                with open("/usr/bin/kmstool_enclave_cli", "rb") as f:
                    report.append("kmstool binary: FOUND")
            except Exception as e:
                report.append(f"kmstool binary: FAIL ({e})")
                
            # Send Report
            resp = "\n".join(report)
            conn.sendall(resp.encode('utf-8'))
            conn.close()
            
        except Exception:
            pass

if __name__ == "__main__":
    run_server()
