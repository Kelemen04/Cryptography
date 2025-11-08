import json
import binascii
import re
from Crypto.Cipher import AES

HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def load_plaintext(file):

    with open(file, "rb") as f:
        plaintext = f.read()

    return plaintext

def load_data(path):

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def key_to_bytes(key_value, block_size, algorithm):

    if isinstance(key_value, str) and HEX_RE.match(key_value) and len(key_value) % 2 == 0:
        key = binascii.unhexlify(key_value)
    else:
        raise ValueError("Incorrect key!Must be a hex.")

    if algorithm.upper() == "AES":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes long")
        return key
    else:
        if len(key) % block_size != 0:
            key = (key * ((block_size // len(key)) + 1))[:block_size]
        return key


def parse_iv(iv_value, block_size_bytes):

    if isinstance(iv_value, str) and HEX_RE.match(iv_value) and len(iv_value) % 2 == 0:
        iv = binascii.unhexlify(iv_value)

        if len(iv) != block_size_bytes:
            raise ValueError(f"The IV length must be: {block_size_bytes}")

        return iv

    raise ValueError("Incorrect IV!")


def validate_and_prepare(data):
    block_bits = int(data.get("block_size_bits", 0))
    if block_bits % 8 != 0:
        raise ValueError("The length of a block must be multiple of 8")
    block_bytes = block_bits // 8

    required = ["block_size_bits", "algorithm", "key", "mode", "padding"]
    for r in required:
        if r not in data:
            raise ValueError(f"Missing configuration data: {r}")

    key = key_to_bytes(data["key"], block_bytes, data["algorithm"])

    iv = b""
    if data["mode"] != "ECB":
        if "iv" not in data or not data["iv"]:
            raise ValueError("IV is required!")
        iv = parse_iv(data["iv"], block_bytes)

    return {
        "block_size_bits": block_bits,
        "block_size_bytes": block_bytes,
        "algorithm": data["algorithm"],
        "key_bytes": key,
        "mode": data["mode"],
        "padding": data["padding"],
        "iv_bytes": iv,
    }

def padding(plaintext,type,bits):

    block_size = bits // 8

    if type == "zero-padding":
        while len(plaintext) % block_size != 0:
            plaintext += b'\x00'

    if type == "DES":
        if len(plaintext) % block_size != 0:
            plaintext += b'\x80'
            while len(plaintext) % block_size != 0:
                plaintext += b'\x00'

    if type == "SF":
        pad = block_size - (len(plaintext) % block_size)
        while len(plaintext) % block_size != 0:
            plaintext += bytes([pad])

    return plaintext

def slicing(plaintext,block_size):
    start = 0
    end = block_size
    blocks = []

    while start < len(plaintext):
        blocks.append(plaintext[start:end])
        start = end
        end += block_size

    return blocks


def encrypt_vigenere(plaintext, key):
    ciphertext = bytearray()

    for i in range(len(plaintext)):
        ciphertext.append((plaintext[i] +  key[i]) % 256)

    return bytes(ciphertext)


def decrypt_vigenere(ciphertext, key):
    plaintext = bytearray()

    for i in range(len(ciphertext)):
        plaintext.append((ciphertext[i] - key[i]) % 256)

    return bytes(plaintext)

def ecb_encrypt(blocks, prepared):
    encrypted_blocks = []

    for block in blocks:
        if prepared["algorithm"].upper() == "VIGENERE":
            encrypted = encrypt_vigenere(block, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            encrypted = cipher.encrypt(block)
        else:
            raise ValueError("Unsupported algorithm")

        encrypted_blocks.append(encrypted)

    return b''.join(encrypted_blocks)

def cbc_encrypt(blocks, prepared):
    encrypted_blocks = []

    prev = prepared["iv_bytes"]

    for block in blocks:
        xor_block = bytearray(len(block))
        for i in range(len(block)):
            xor_block[i] = block[i] ^ prev[i]

        if prepared["algorithm"].upper() == "VIGENERE":
            encrypted = encrypt_vigenere(bytes(xor_block), prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            encrypted = cipher.encrypt(bytes(xor_block))
        else:
            raise ValueError("Unsupported algorithm")

        encrypted_blocks.append(encrypted)
        prev = encrypted

    return b''.join(encrypted_blocks)


def cfb_encrypt(blocks, prepared):
    encrypted_blocks = []

    prev = prepared["iv_bytes"]

    for block in blocks:
        if prepared["algorithm"].upper() == "VIGENERE":
            cipher_block = encrypt_vigenere(prev, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            cipher_block = cipher.encrypt(prev)
        else:
            raise ValueError("Unsupported algorithm")

        xor_block = bytearray(len(block))
        for i in range(len(block)):
            xor_block[i] = block[i] ^ cipher_block[i]

        encrypted = bytes(xor_block)
        encrypted_blocks.append(encrypted)

        prev = encrypted

    return b''.join(encrypted_blocks)

def ofb_encrypt(blocks, prepared):
    encrypted_blocks = []

    prev = prepared["iv_bytes"]

    for block in blocks:
        if prepared["algorithm"].upper() == "VIGENERE":
            cipher_block = encrypt_vigenere(prev, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            cipher_block = cipher.encrypt(prev)
        else:
            raise ValueError("Unsupported algorithm")

        prev = cipher_block

        xor_block = bytearray(len(block))
        for i in range(len(block)):
            xor_block[i] = block[i] ^ cipher_block[i]

        encrypted = bytes(xor_block)
        encrypted_blocks.append(encrypted)

    return b''.join(encrypted_blocks)


if __name__ == "__main__":

    data = load_data("data.json")
    prepared = validate_and_prepare(data)

    plaintext = load_plaintext("input_file")

    plaintext_padding = padding(plaintext, prepared["padding"], prepared["block_size_bits"])

    blocks = slicing(plaintext_padding,prepared["block_size_bytes"])

    match data["mode"]:
        case "ECB":
            ecb_encrypt(blocks, prepared)
        case "CBC":
            cbc_encrypt(blocks, prepared)
        case "CFB":
            cfb_encrypt(blocks, prepared)
        case "OFB":
            ofb_encrypt(blocks, prepared)
        case "CTR":
            ctr_encrypt(blocks, prepared)