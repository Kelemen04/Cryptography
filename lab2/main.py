import json
import binascii
import re

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


if __name__ == "__main__":

    data = load_data("data.json")
    prepared = validate_and_prepare(data)

    plaintext = load_plaintext("input_file")

    file = padding(plaintext, prepared["padding"], prepared["block_size_bits"])

