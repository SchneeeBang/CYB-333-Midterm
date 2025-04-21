# CYB-333-Midterm
# server.py
import socket

HOST = '127.0.0.1'  # Localhost
PORT = 65432        # Non-privileged port

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, PORT))  # Bind socket to address
            s.listen()
            print(f"Server is listening on {HOST}:{PORT}...")

            conn, addr = s.accept()  # Wait for a client to connect
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)  # Receive data from client
                    if not data:
                        print("Client disconnected.")
                        break
                    message = data.decode()
                    print(f"Received from client: {message}")

                    response = f"Server received: {message}"
                    conn.sendall(response.encode())  # Send response to client

        except Exception as e:
            print(f"Server error: {e}")

if __name__ == "__main__":
    start_server()

# client.py
import socket

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))  # Attempt to connect to server
            print(f"Connected to server at {HOST}:{PORT}")

            while True:
                message = input("Enter message to send (type 'exit' to quit): ")
                if message.lower() == 'exit':
                    print("Disconnecting from server...")
                    break

                s.sendall(message.encode())  # Send message to server

                data = s.recv(1024)  # Receive response
                print(f"Received from server: {data.decode()}")

        except ConnectionRefusedError:
            print("Failed to connect: Server is not running.")
        except Exception as e:
            print(f"Client error: {e}")

if __name__ == "__main__":
    start_client()

# port_scanner.py

import socket
from datetime import datetime

def is_valid_port_range(start_port, end_port):
    return 0 <= start_port <= 65535 and 0 <= end_port <= 65535 and start_port <= end_port

def scan_ports(target_host, start_port, end_port):
    print(f"\nStarting scan on host: {target_host}")
    print(f"Scanning ports from {start_port} to {end_port}")
    print("-" * 50)

    if not is_valid_port_range(start_port, end_port):
        print("Error: Invalid port range. Ports must be between 0 and 65535, and start <= end.")
        return

    open_ports = []

    try:
        # Resolve the hostname
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{target_host}'.")
        return

    start_time = datetime.now()

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    print(f"[+] Port {port} is OPEN")
                    open_ports.append(port)
                else:
                    print(f"[-] Port {port} is closed")
            except socket.error as e:
                print(f"[!] Error on port {port}: {e}")
            except KeyboardInterrupt:
                print("\nScan cancelled by user.")
                return

    end_time = datetime.now()
    duration = end_time - start_time

    print("-" * 50)
    print(f"Scan complete in {duration}")
    print(f"Open ports: {open_ports if open_ports else 'None found'}\n")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("host", help="Target host to scan")
    parser.add_argument("start_port", type=int, help="Start of port range")
    parser.add_argument("end_port", type=int, help="End of port range")

    args = parser.parse_args()

    scan_ports(args.host, args.start_port, args.end_port)
