from socket import *
import threading
import sys

SERVER_PORT = 8000
SERVER_NAME = 'keyserver'

public_keys = {}
LOCK = threading.Lock()

def handle_client(connectionSocket, addr):
    source = f"{addr[0]}:{addr[1]}"

    try:
        received_data = connectionSocket.recv(4096)
        if not received_data:
            return

        message_parts = received_data.split(b'|', 2)
        command = message_parts[0].decode().upper()

        if command == 'REGISTER':
            if len(message_parts) < 3:
                connectionSocket.sendall(b"Missing ID or Key")
                return

            client_id = message_parts[1].decode()
            pubkey_pem_bytes = message_parts[2]

            with LOCK:
                public_keys[client_id] = pubkey_pem_bytes

            print(f"[SERVER] Successful registration. ID: {client_id}.")

            connectionSocket.sendall(b"Registration successful")
        elif command == 'GETKEY':
            if len(message_parts) < 2:
                connectionSocket.sendall(b"Missing ID")
                return

            client_id = message_parts[1].decode()

            with LOCK:
                public_key = public_keys.get(client_id)

            if public_key:
                print(f"[SERVER] ID request: {client_id}, sent key.")
                connectionSocket.sendall(public_key)
            else:
                print(f"[SERVER] ID request: {client_id}, key NOT FOUND.")
                connectionSocket.sendall(b"KEY_NOT_FOUND")
        else:
            print(f"[SERVER] Unknown command ({command}) from: {source}.")
            connectionSocket.sendall(b"Unknown command")

    except Exception as e:
        print(f"[SERVER] Error in receiver ({source}): {e}")
    finally:
        connectionSocket.close()

def receive():
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    try:
        serverSocket.bind(('', SERVER_PORT))
        serverSocket.listen(5)
        print(f"[SERVER] Server started on port: {SERVER_PORT}")
    except Exception as e:
        print(f"[SERVER] Error while connecting: {e}")
        sys.exit(1)

    while True:
        try:
            connectionSocket, addr = serverSocket.accept()
            print(f"[SERVER] New connection: {addr}")

            thread = threading.Thread(target=handle_client, args=(connectionSocket, addr))
            thread.start()

        except KeyboardInterrupt:
            print(f"[SERVER] Server stopped.")
            break
        except Exception as e:
            print(f"[SERVER] Error while receiving: {e}")

    serverSocket.close()

if __name__ == "__main__":
    receive()