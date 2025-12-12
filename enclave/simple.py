import socket
import json
import sys

print("Starting Simple Server...", flush=True)

try:
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = 5000
    s.bind((cid, port))
    s.listen(5)
    print(f"Listening on {cid}:{port}", flush=True)
except Exception as e:
    print(f"Bind failed: {e}", flush=True)
    sys.exit(1)

while True:
    try:
        conn, addr = s.accept()
        print(f"Connect from {addr}", flush=True)
        data = conn.recv(1024)
        print(f"Received: {data}", flush=True)
        response = {"status": "ok", "msg": "simple_server"}
        conn.sendall(json.dumps(response).encode())
        conn.close()
    except Exception as e:
        print(f"Error: {e}", flush=True)
