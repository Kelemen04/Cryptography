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

def padding(plaintext, type, bits):
    block_size = bits // 8
    pad_len = 0

    if type == "zero-padding":
        pad_len = (block_size - (len(plaintext) % block_size)) % block_size
        plaintext += b'\x00' * pad_len

    elif type == "DES":
        pad_len = block_size - (len(plaintext) % block_size)
        if pad_len == block_size:
            pad_len = 0
        else:
            pad_len2 = pad_len
            plaintext += b'\x80'
            pad_len2 -= 1
            if pad_len > 0:
                plaintext += b'\x00' * pad_len2

    elif type == "SF":
        pad_len = block_size - (len(plaintext) % block_size)
        plaintext += bytes([pad_len] * pad_len)

    return plaintext, pad_len

def unpadding(plaintext, pad_len):
    if pad_len == 0:
        return plaintext
    return plaintext[:-pad_len]

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

def ecb_decrypt(blocks, prepared):
    decrypted_blocks = []

    for block in blocks:
        if prepared["algorithm"].upper() == "VIGENERE":
            decrypted = decrypt_vigenere(block, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            decrypted = cipher.decrypt(block)
        else:
            raise ValueError("Unsupported algorithm")

        decrypted_blocks.append(decrypted)

    return b''.join(decrypted_blocks)

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

def cbc_decrypt(blocks, prepared):
    decrypted_blocks = []
    prev = prepared["iv_bytes"]

    for block in blocks:
        if prepared["algorithm"].upper() == "VIGENERE":
            decrypted = decrypt_vigenere(block, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            decrypted = cipher.decrypt(block)
        else:
            raise ValueError("Unsupported algorithm")

        xor_block = bytearray(len(decrypted))
        for i in range(len(decrypted)):
            xor_block[i] = decrypted[i] ^ prev[i]

        decrypted_blocks.append(bytes(xor_block))
        prev = block

    return b''.join(decrypted_blocks)

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

def cfb_decrypt(blocks, prepared):
    decrypted_blocks = []
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

        decrypted = bytes(xor_block)
        decrypted_blocks.append(decrypted)

        prev = block

    return b''.join(decrypted_blocks)


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

def ofb_decrypt(blocks, prepared):
    return ofb_encrypt(blocks, prepared)

def ctr_encrypt(blocks, prepared):
    encrypted_blocks = []
    nonce = prepared["iv_bytes"]
    block_size = prepared["block_size_bytes"]

    for i, block in enumerate(blocks):
        counter_block = int.from_bytes(nonce, byteorder='big') + i
        counter_block_bytes = counter_block.to_bytes(block_size, byteorder='big')

        if prepared["algorithm"].upper() == "VIGENERE":
            cipher_block = encrypt_vigenere(counter_block_bytes, prepared["key_bytes"])
        elif prepared["algorithm"].upper() == "AES":
            cipher = AES.new(prepared["key_bytes"], AES.MODE_ECB)
            cipher_block = cipher.encrypt(counter_block_bytes)
        else:
            raise ValueError("Unsupported algorithm")

        xor_block = bytearray(len(block))
        for j in range(len(block)):
            xor_block[j] = block[j] ^ cipher_block[j]

        encrypted_blocks.append(bytes(xor_block))

    return b''.join(encrypted_blocks)


def ctr_decrypt(blocks, prepared):
    return ctr_encrypt(blocks, prepared)

if __name__ == "__main__":

    data = load_data("data.json")
    prepared = validate_and_prepare(data)

    text = "input_file.jpg"
    plaintext = load_plaintext(text)

    plaintext_padding,pad_len = padding(plaintext, prepared["padding"], prepared["block_size_bits"])
    prepared["pad_len"] = pad_len

    blocks = slicing(plaintext_padding,prepared["block_size_bytes"])

    encrypted = None
    match data["mode"].upper():
        case "ECB":
            encrypted = ecb_encrypt(blocks, prepared)
        case "CBC":
            encrypted = cbc_encrypt(blocks, prepared)
        case "CFB":
            encrypted = cfb_encrypt(blocks, prepared)
        case "OFB":
            encrypted = ofb_encrypt(blocks, prepared)
        case "CTR":
            encrypted = ctr_encrypt(blocks, prepared)
        case _:
            raise ValueError("Unsupported mode")

    with open("encrypted_file", "wb") as f:
        f.write(encrypted)

    encrypted_blocks = slicing(encrypted, prepared["block_size_bytes"])

    decrypted = None
    match data["mode"].upper():
        case "ECB":
            decrypted = ecb_decrypt(encrypted_blocks, prepared)
        case "CBC":
            decrypted = cbc_decrypt(encrypted_blocks, prepared)
        case "CFB":
            decrypted = cfb_decrypt(encrypted_blocks, prepared)
        case "OFB":
            decrypted = ofb_decrypt(encrypted_blocks, prepared)
        case "CTR":
            decrypted = ctr_decrypt(encrypted_blocks, prepared)
        case _:
            raise ValueError("Unsupported mode")

    decrypted = unpadding(decrypted, prepared["pad_len"])

    with open("decrypted_file", "wb") as f:
        f.write(decrypted)