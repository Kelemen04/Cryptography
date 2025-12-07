from socket import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import sys
import time
import threading
import utils
import re
import binascii

if len(sys.argv) != 3:
    print("Error: please provide a PORT and list of supported algorithms.Example: python client.py 8001 AES-CBC,VIGENERE-ECB")
    sys.exit(1)

client_id = sys.argv[1]
client_host_name = f'client{client_id[3:]}'

SUPPORTED_ALGS_INPUT = sys.argv[2]
VALID_ALGS = {"AES", "VIGENERE"}
VALID_MODES = {"ECB", "CBC", "CFB", "OFB", "CTR"}

SUPPORTED_ALGS = []
for alg_mode in SUPPORTED_ALGS_INPUT.split(','):
    alg_mode_upper = alg_mode.strip().upper()
    if '-' in alg_mode_upper:
        alg, mode = alg_mode_upper.split('-', 1)
        if alg in VALID_ALGS and mode in VALID_MODES:
            SUPPORTED_ALGS.append(alg_mode_upper)
    elif alg_mode_upper in VALID_ALGS and "ECB" in VALID_MODES:
        pass

if not SUPPORTED_ALGS:
    print(f"Error: No valid AES/VIGENERE algorithm-mode combinations found in '{SUPPORTED_ALGS_INPUT}'.")
    sys.exit(1)

KEY_SERVER_NAME = 'keyserver'
KEY_SERVER_PORT = 8000
CLIENT_LISTEN_PORT = int(client_id)

if client_id == '8001':
    TARGET_PARTNER_ID = '8002'
else:
    TARGET_PARTNER_ID = '8001'

my_half_secret = None
partner_half_secret = None
cipher_config = None
SELECTED_COMMON_ALG = None

key = RSA.generate(2048)
pubkey = key.publickey()
privkey = key

print(f"[{client_host_name}-LOG] RSA Key Pair Generated.")

def communicate_with_keyserver(request_message):
    keyserver_socket = None
    try:
        keyserver_socket = socket(AF_INET, SOCK_STREAM)
        keyserver_socket.connect((KEY_SERVER_NAME, KEY_SERVER_PORT))
        keyserver_socket.sendall(request_message)
        response = keyserver_socket.recv(4096)
        return response
    except Exception as e:
        print(f"[{client_host_name}] KeyServer Error: {e}")
        return None
    finally:
        if keyserver_socket:
            keyserver_socket.close()

def registerPubKey():
    pubkey_pem = pubkey.export_key('PEM')
    msg = b"REGISTER|" + client_id.encode() + b"|" + pubkey_pem
    print(f"[{client_host_name}-LOG] Registering Public Key on Server.")
    response = communicate_with_keyserver(msg)
    if response and b"successful" in response:
        print(f"[{client_host_name}-LOG] KeyServer Response: {response.decode()}")
        return True
    return False

def getPubKey(target_id):
    msg = b"GETKEY|" + target_id.encode()
    print(f"[{client_host_name}-LOG] Requesting Public Key for {target_id}")
    response = communicate_with_keyserver(msg)
    if response and b"BEGIN PUBLIC KEY" in response:
        try:
            k = RSA.import_key(response)
            print(f"[{client_host_name}-LOG] Received Public Key for {target_id}.")
            return k
        except:
            pass
    return None

if not registerPubKey():
    sys.exit(1)

time.sleep(1)
partner_pubkey = getPubKey(TARGET_PARTNER_ID)

def send_encrypted_message(message_str):
    if not partner_pubkey:
        print(f"[{client_host_name}-ERROR] Cannot send: Missing partner key.")
        return
    try:
        cipher_rsa = PKCS1_OAEP.new(partner_pubkey)
        encrypted_msg = cipher_rsa.encrypt(message_str.encode('utf-8'))
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(('localhost', int(TARGET_PARTNER_ID)))
        s.sendall(encrypted_msg)
        s.close()
    except Exception as e:
        print(f"[{client_host_name}] Send Error: {e}")

def send_hello():
    alg_list_str = ",".join(SUPPORTED_ALGS)
    print(f"[{client_host_name}-LOG] Sending HELLO with list: {alg_list_str}")
    send_encrypted_message(f"HELLO|{client_id}|{alg_list_str}")

def send_ack():
    alg_list_str = ",".join(SUPPORTED_ALGS)
    print(f"[{client_host_name}-LOG] Sending ACK with list: {alg_list_str}")
    send_encrypted_message(f"ACK|{client_id}|{alg_list_str}")

def send_half_secret():
    global my_half_secret
    if my_half_secret is None:
        my_half_secret = get_random_bytes(16)
        print(f"[{client_host_name}-LOG] Generated Internal Half-Secret: {my_half_secret.hex()}")
    print(f"[{client_host_name}-LOG] Sending Half-Secret")
    send_encrypted_message(f"SECRET|{my_half_secret.hex()}")

def find_common_algorithm(my_algs, partner_algs):
    partner_set = set(partner_algs)
    for alg in my_algs:
        if alg in partner_set:
            return alg
    return None

def initBlockCipher(common_key):
    global cipher_config, SELECTED_COMMON_ALG

    match = re.match(r"([A-Z0-9]+)-([A-Z]+)", SELECTED_COMMON_ALG)
    if not match:
        print(f"[{client_host_name}-ERROR] Invalid selected algorithm format: {SELECTED_COMMON_ALG}")
        sys.exit(1)

    algorithm = match.group(1)
    mode = match.group(2)

    if algorithm == "AES":
        block_size_bits = 128
        block_size_bytes = 16
        iv = b'\x00' * 16
        padding = "PKCS7"
    elif algorithm == "VIGENERE":
        block_size_bits = 64
        block_size_bytes = 8
        iv = b'\x00' * 8
        padding = "SF"
    else:
        print(f"[{client_host_name}-ERROR] Unsupported algorithm: {algorithm}")
        sys.exit(1)

    if mode == "ECB":
        iv = b''

    cipher_config = {
        "block_size_bits": block_size_bits,
        "block_size_bytes": block_size_bytes,
        "algorithm": algorithm,
        "key_bytes": common_key,
        "mode": mode,
        "padding": padding,
        "iv_bytes": iv,
        "pad_len": 0
    }

    print("-----------------------")
    print(f"[{client_host_name}-SUCCESS] BLOCK CIPHER INITIALIZED!")
    print(f"[{client_host_name}-INFO] Negotiated Config: {SELECTED_COMMON_ALG}")
    print(f"[{client_host_name}-INFO] Algorithm: {algorithm}, Mode: {mode}, Block: {block_size_bytes} bytes")
    print(f"[{client_host_name}-INFO] Final Common Key: {common_key.hex()}")
    print("-----------------------")
    print("____CHAT STARTED___")

def get_cipher_func(mode, direction):
    func_map = {
        "ECB": (utils.ecb_encrypt, utils.ecb_decrypt),
        "CBC": (utils.cbc_encrypt, utils.cbc_decrypt),
        "CFB": (utils.cfb_encrypt, utils.cfb_decrypt),
        "OFB": (utils.ofb_encrypt, utils.ofb_decrypt),
        "CTR": (utils.ctr_encrypt, utils.ctr_decrypt)
    }

    if mode in func_map:
        return func_map[mode][0] if direction == 'encrypt' else func_map[mode][1]

    raise ValueError(f"Unsupported cipher mode: {mode}")

def send_chat_message(text):
    global SELECTED_COMMON_ALG
    if cipher_config is None:
        print("Waiting for secure connection")
        return

    try:
        encrypt_func = get_cipher_func(cipher_config["mode"], 'encrypt')
        msg_bytes = text.encode('utf-8')
        padded_msg, _ = utils.padding(msg_bytes, cipher_config["padding"], cipher_config["block_size_bits"])
        blocks = utils.slicing(padded_msg, cipher_config["block_size_bytes"])
        encrypted_bytes = encrypt_func(blocks, cipher_config)

        print(f"[LOG] Sending Encrypted Data ({SELECTED_COMMON_ALG}, Hex): {encrypted_bytes.hex()}")

        s = socket(AF_INET, SOCK_STREAM)
        s.connect(('localhost', int(TARGET_PARTNER_ID)))
        s.sendall(encrypted_bytes)
        s.close()
    except Exception as e:
        print(f"Chat Send Error: {e}")

def p2p_receive():
    server = socket(AF_INET, SOCK_STREAM)
    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    global partner_pubkey, partner_half_secret, my_half_secret, cipher_config, SELECTED_COMMON_ALG

    try:
        server.bind(('', CLIENT_LISTEN_PORT))
        server.listen(1)
        print(f"[{client_host_name}-LOG] Listening on port {CLIENT_LISTEN_PORT}")

        while True:
            conn, addr = server.accept()
            data = conn.recv(4096)
            if data:
                if cipher_config is not None:
                    print(f"\n[LOG] Received Encrypted Data (Hex): {data.hex()}")
                    try:
                        decrypt_func = get_cipher_func(cipher_config["mode"], 'decrypt')
                        blocks = utils.slicing(data, cipher_config["block_size_bytes"])
                        decrypted_padded = decrypt_func(blocks, cipher_config)

                        decrypted = decrypted_padded
                        padding_type = cipher_config["padding"]

                        if padding_type == "PKCS7" or padding_type == "SF":
                            block_size = cipher_config["block_size_bytes"]

                            if not decrypted_padded:
                                decrypted = b''
                            else:
                                try:
                                    pad_len = decrypted_padded[-1]

                                    if 0 < pad_len <= block_size:
                                        decrypted = utils.unpadding(decrypted_padded, pad_len)
                                        decrypted = decrypted.rstrip(b'\x04').rstrip(b'\x00')

                                    else:
                                        print(
                                            f"[{client_host_name}-WARNING] Invalid padding length ({pad_len}).")
                                        decrypted = decrypted_padded.rstrip(b'\x04').rstrip(b'\x00')

                                except IndexError:
                                    print(
                                        f"[{client_host_name}-ERROR] Index error during unpadding.")
                                    decrypted = decrypted_padded

                        print(f"[Partner]: {decrypted.decode('utf-8')}")
                        print(">>> ", end='', flush=True)
                    except Exception as e:
                        print(f"[ERROR] Chat decryption failed: {e}")

                else:
                    try:
                        cipher = PKCS1_OAEP.new(privkey)
                        msg_str = cipher.decrypt(data).decode('utf-8')

                        print(f"[{client_host_name}-RECV-RSA] Decrypted: {msg_str}")

                        if msg_str.startswith(("HELLO", "ACK")) and "|" in msg_str:
                            parts = msg_str.split("|")

                            if len(parts) < 3:
                                print(
                                    f"[{client_host_name}-ERROR] Handshake message format error.")
                                conn.close()
                                continue

                            partner_alg_list_str = parts[2]
                            partner_algs = [alg.strip().upper() for alg in partner_alg_list_str.split(',')]

                            common_alg = find_common_algorithm(SUPPORTED_ALGS, partner_algs)

                            if common_alg:
                                SELECTED_COMMON_ALG = common_alg
                                print(f"[{client_host_name}-LOG] Common algorithm selected: {SELECTED_COMMON_ALG}")
                            else:
                                print(f"[{client_host_name}-ERROR] No common algorithm found. Exiting.")
                                sys.exit(1)

                            if client_id == '8002' and msg_str.startswith("HELLO"):
                                if partner_pubkey is None:
                                    partner_pubkey = getPubKey(TARGET_PARTNER_ID)
                                time.sleep(1)
                                send_ack()

                            elif client_id == '8001' and msg_str.startswith("ACK"):
                                time.sleep(1)
                                send_half_secret()

                        elif msg_str.startswith("SECRET"):
                            partner_half_secret = bytes.fromhex(msg_str.split("|")[1])

                            if client_id == '8002' and my_half_secret is None:
                                time.sleep(1)
                                send_half_secret()

                            if my_half_secret and partner_half_secret:
                                common = utils.generate_common_secret(my_half_secret, partner_half_secret)
                                initBlockCipher(common)

                    except Exception as e:
                        print(f"[{client_host_name}-ERROR] Handshake failed: {e}")
            conn.close()
    finally:
        server.close()

def write_loop():
    while True:
        if cipher_config is None:
            time.sleep(1)
            continue
        try:
            msg = input(">>> ")
            if msg:
                send_chat_message(msg)
        except:
            break

t = threading.Thread(target=p2p_receive, daemon=True)
t.start()

if client_id == '8001':
    time.sleep(2)
    send_hello()

write_loop()