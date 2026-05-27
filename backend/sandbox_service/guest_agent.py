"""
Guest Agent running inside the Firecracker MicroVM.

It listens on a vsock port for commands from the host VMManager,
executes them safely, and returns structured stdout/stderr/exit_code via vsock.
"""
import json
import socket
import subprocess
import sys
import traceback
from pathlib import Path


def main():
    # Firecracker vsock uses AF_VSOCK (family 40)
    # The guest listens on a specific port, e.g., 5000, for the host to connect.
    # Alternatively, the host listens and the guest connects.
    # For a guest agent, listening on a port is typical.
    
    VSOCK_PORT = 5000
    
    try:
        # Standard AF_VSOCK constant is 40 in Python (Linux)
        server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        # CID_ANY is -1
        server.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
        server.listen(1)
        print(f"Guest Agent listening on vsock port {VSOCK_PORT}...")
        
        while True:
            conn, addr = server.accept()
            handle_connection(conn)
    except Exception as e:
        print(f"Guest Agent failed to start: {e}")
        sys.exit(1)


def handle_connection(conn):
    try:
        # Read the command payload (JSON)
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk: # Protocol uses newline as delimiter
                break
                
        if not data:
            return
            
        payload = json.loads(data.decode("utf-8").strip())
        command = payload.get("command", [])
        working_dir = payload.get("working_dir", "/workspace")
        timeout = payload.get("timeout", 120)
        
        # Execute the command
        result = run_command(command, working_dir, timeout)
        
        # Send back the result
        response = json.dumps(result) + "\n"
        conn.sendall(response.encode("utf-8"))
    except Exception as e:
        error_resp = json.dumps({
            "exit_code": -1,
            "stdout": "",
            "stderr": traceback.format_exc()
        }) + "\n"
        conn.sendall(error_resp.encode("utf-8"))
    finally:
        conn.close()


def run_command(command: list[str], working_dir: str, timeout: int) -> dict:
    try:
        Path(working_dir).mkdir(parents=True, exist_ok=True)
        process = subprocess.run(
            command,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "exit_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 124,
            "stdout": "",
            "stderr": "Command timed out."
        }
    except Exception as e:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": str(e)
        }

if __name__ == "__main__":
    main()
