
import socket
import json

def fetch_logs():
    print("Connecting to Enclave CID 16 Port 5000...")
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((16, 5000))
        
        print("Sending get_logs command...")
        sock.sendall(json.dumps({'type': 'get_logs'}).encode())
        
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            
        response = json.loads(data.decode())
        print("\n=== ENCLAVE LOGS ===")
        print(response.get('logs', 'No logs field in response'))
        print("====================")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    fetch_logs()
