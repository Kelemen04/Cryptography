from socket import *
from Crypto.PublicKey import RSA
import sys
import time

if len(sys.argv) != 2:
    print("Error, please add a parameter (PORT) when running.")
    sys.exit(1)

client_id = sys.argv[1]
client_host_name = f'client{client_id[3:]}'

KEY_SERVER_NAME = 'keyserver'
KEY_SERVER_PORT = 8000
CLIENT_LISTEN_PORT = int(client_id)

key = RSA.generate(2048)
pubkey = key.publickey()

print(f"[{client_host_name}] RSA keys generated.")

clientSocket = None

try:
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((KEY_SERVER_NAME, KEY_SERVER_PORT))
    print(
        f"[{client_host_name}] Successful connection to the server ({KEY_SERVER_NAME}:{KEY_SERVER_PORT})")

    pubkey_pem = pubkey.export_key('PEM')
    full_registration_message = b"REGISTER|" + client_id.encode() + b"|" + pubkey_pem

    clientSocket.sendall(full_registration_message)
    print(f"[{client_host_name}] Registration sent to the server.")

    response = clientSocket.recv(1024).decode()
    print(f"[{client_host_name}] Answer from the server: {response}")

except Exception as e:
    print(f"[{client_host_name}] Error during communication: {e}")
    sys.exit(1)
finally:
    if clientSocket:
        clientSocket.close()

def write():
    while True:
        try:
            time.sleep(1)
        except:
            break

def receive():
    pass

print(f"[{client_host_name}] Registration finished")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"[{client_host_name}] Client stopped by user")