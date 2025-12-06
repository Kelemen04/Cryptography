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

if client_id == '8001':
    TARGET_PARTNER_ID = '8002'
else:
    TARGET_PARTNER_ID = '8001'

key = RSA.generate(2048)
pubkey = key.publickey()
privkey = key

print(f"[{client_host_name}] RSA keys generated.")


def communicate_with_keyserver(request_message):
    keyserver_socket = None
    try:
        keyserver_socket = socket(AF_INET, SOCK_STREAM)
        keyserver_socket.connect((KEY_SERVER_NAME, KEY_SERVER_PORT))
        keyserver_socket.sendall(request_message)
        response = keyserver_socket.recv(4096)
        return response
    except Exception as e:
        print(f"[{client_host_name}] Communication error with KeyServer: {e}")
        return None
    finally:
        if keyserver_socket:
            keyserver_socket.close()

def registerPubKey():
    pubkey_pem = pubkey.export_key('PEM')
    full_registration_message = b"REGISTER|" + client_id.encode() + b"|" + pubkey_pem

    print(f"[{client_host_name}] Registering public key...")
    response = communicate_with_keyserver(full_registration_message)

    if response:
        try:
            response_decoded = response.decode()
        except:
            response_decoded = "Invalid response format"

        print(f"[{client_host_name}] KeyServer answer: {response_decoded}")

        if "FAILED" not in response_decoded and "ERROR" not in response_decoded:
            return True
        else:
            return False
    return False

def getPubKey(target_id):
    request_message = b"GETKEY|" + target_id.encode()

    print(f"[{client_host_name}] Requesting public key for ID: {target_id}...")
    response_bytes = communicate_with_keyserver(request_message)

    if response_bytes:
        try:
            partner_pubkey_obj = RSA.import_key(response_bytes)
            print(f"[{client_host_name}] Partner key for {target_id} received.")
            return partner_pubkey_obj
        except Exception as e:
            print(f"[{client_host_name}] Error importing key: {e}")

            try:
                print(f"[{client_host_name}] Server response was: {response_bytes.decode()}")
            except:
                pass

            return None
    return None

if not registerPubKey():
    print(f"[{client_host_name}] Registration FAILED. Exiting.")
    sys.exit(1)

print(f"[{client_host_name}] Registration finished.")

partner_pubkey = getPubKey(TARGET_PARTNER_ID)

if partner_pubkey:
    print(f"[{client_host_name}] Initial key exchange complete. Ready for P2P.")
else:
    print(f"[{client_host_name}] Failed to get partner key. Cannot start P2P.")

def write():
    while True:
        try:
            time.sleep(1)
        except:
            break


def receive():
    pass

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"[{client_host_name}] Client stopped by user")