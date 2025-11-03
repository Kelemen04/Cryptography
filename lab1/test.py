
from crypto import (
    encrypt_caesar, decrypt_caesar,
    encrypt_vigenere, decrypt_vigenere,
    encrypt_scytale, decrypt_scytale,
    encrypt_railfence, decrypt_railfence,
    encrypt_caesar_binary, decrypt_caesar_binary
)

def run_tests():
    print("CAESAR:")
    text = "EZ EGY SZOVEG"
    enc = encrypt_caesar(text)
    dec = decrypt_caesar(enc)
    print(f"Plaintext:  {text}")
    print(f"Encrypted:  {enc}")
    print(f"Decrypted:  {dec}")

    print("\nVIGENERe:")
    text = "UBBMATEINFO"
    key = "LEMON"
    enc = encrypt_vigenere(text, key)
    dec = decrypt_vigenere(enc, key)
    print(f"Plaintext:  {text}")
    print(f"Keyword:    {key}")
    print(f"Encrypted:  {enc}")
    print(f"Decrypted:  {dec}")

    print("\nSCYTALE CIPHER")
    text = "SCYTALEFELADAT"
    circumference = 3
    enc = encrypt_scytale(text, circumference)
    dec = decrypt_scytale(enc, circumference)
    print(f"Plaintext:  {text}")
    print(f"Encrypted:  {enc}")
    print(f"Decrypted:  {dec}")

    print("\nRAILFENCE:")
    text = "RAILFENCEESFELADAT"
    num_rails = 3
    enc = encrypt_railfence(text, num_rails)
    dec = decrypt_railfence(enc, num_rails)
    print(f"Plaintext:  {text}")
    print(f"Encrypted:  {enc}")
    print(f"Decrypted:  {dec}")

    print("\nCAESAR BIN:")
    data = b"HELLO WORLD"
    enc = encrypt_caesar_binary(data)
    dec = decrypt_caesar_binary(enc)
    print(f"Plain bytes: {data}")
    print(f"Encrypted:   {enc}")
    print(f"Decrypted:   {dec}")

run_tests()
