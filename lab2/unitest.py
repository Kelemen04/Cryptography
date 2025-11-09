import pytest
from main import (
    load_plaintext, padding, unpadding, slicing,
    validate_and_prepare,
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    cfb_encrypt, cfb_decrypt,
    ofb_encrypt, ofb_decrypt,
    ctr_encrypt, ctr_decrypt
)

ALGORITHMS = ["AES", "VIGENERE"]
MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"]
PADDING_TYPE = "DES"
INPUT_FILE = "input_file.png"

def encrypt_decrypt(algorithm, mode, input_file):
    plaintext = load_plaintext(input_file)
    data = {
        "algorithm": algorithm,
        "mode": mode,
        "padding": PADDING_TYPE,
        "key": "00112233445566778899aabbccddeeff",
        "iv": "0102030405060708090a0b0c0d0e0f10",
        "block_size_bits": 128,
        "block_size_bytes": 16
    }

    prepared = validate_and_prepare(data)

    padded, pad_len = padding(plaintext, prepared["padding"], prepared["block_size_bits"])
    prepared["pad_len"] = pad_len

    blocks = slicing(padded, prepared["block_size_bytes"])

    if mode.upper() == "ECB":
        encrypted = ecb_encrypt(blocks, prepared)
    elif mode.upper() == "CBC":
        encrypted = cbc_encrypt(blocks, prepared)
    elif mode.upper() == "CFB":
        encrypted = cfb_encrypt(blocks, prepared)
    elif mode.upper() == "OFB":
        encrypted = ofb_encrypt(blocks, prepared)
    elif mode.upper() == "CTR":
        encrypted = ctr_encrypt(blocks, prepared)
    else:
        raise ValueError("Invalid mode")

    enc_blocks = slicing(encrypted, prepared["block_size_bytes"])
    if mode.upper() == "ECB":
        decrypted = ecb_decrypt(enc_blocks, prepared)
    elif mode.upper() == "CBC":
        decrypted = cbc_decrypt(enc_blocks, prepared)
    elif mode.upper() == "CFB":
        decrypted = cfb_decrypt(enc_blocks, prepared)
    elif mode.upper() == "OFB":
        decrypted = ofb_decrypt(enc_blocks, prepared)
    elif mode.upper() == "CTR":
        decrypted = ctr_decrypt(enc_blocks, prepared)
    else:
        raise ValueError("Invalid mode")

    decrypted = unpadding(decrypted, prepared["pad_len"])
    return decrypted

@pytest.mark.parametrize("algorithm", ALGORITHMS)
@pytest.mark.parametrize("mode", MODES)
def test_encrypt_decrypt(algorithm, mode):
    decrypted = encrypt_decrypt(algorithm, mode, INPUT_FILE)

    with open(INPUT_FILE, "rb") as f:
        plaintext = f.read()

    assert decrypted == plaintext, f"Mismatch in {algorithm}-{mode}"
