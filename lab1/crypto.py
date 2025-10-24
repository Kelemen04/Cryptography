#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: Kelemen Szilard
SUNet: ksim2360

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    key = 3

    if not isinstance(plaintext, str):
        raise TypeError("Text must be a string")

    if len(plaintext) == 0:
        raise ValueError("Text cannot be empty")

    ascii = ''.join(chr(i) for i in range(256))
    output = ''
    for i in range(0, len(plaintext)):
        output += ascii[(ascii.find(plaintext[i]) + key) % len(ascii)]

    """for char in plaintext:
        if char.isalpha():
            output += chr(int((ord(char) - 65 + key) % 26 + 65))
        else:
            output += char"""

    return output  # Your implementation here


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    key = 3

    if not isinstance(ciphertext, str):
        raise TypeError("Text must be a string")

    if len(ciphertext) == 0:
        raise ValueError("Text cannot be empty")

    ascii = ''.join(chr(i) for i in range(256))
    output = ''
    for i in range(0, len(ciphertext)):
        output += ascii[(ascii.find(ciphertext[i]) - key) % len(ascii)]

    """for char in plaintext:
        if char.isalpha():
            output += chr(int((ord(char) - 65 + key) % 26 + 65))
        else:
            output += char"""

    return output  # Your implementation here


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    if not isinstance(plaintext, str) or not isinstance(keyword, str):
        raise TypeError("Text and keyword must be strings")

    if len(plaintext) == 0:
        raise ValueError("Text cannot be empty")

    if len(keyword) == 0:
        raise ValueError("Keyword cannot be empty")

    if len(plaintext) != len(keyword):
        keyword = (keyword * ((len(plaintext) // len(keyword)) + 1))[:len(plaintext)]

    output = ''
    i = 0
    for char in plaintext:
        if char.isalpha():
            output += chr(int((ord(char) - 65 + (ord(keyword[i]) - 65)) % 26 + 65))
        else:
            output += char

        i += 1

    return output  # Your implementation here


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    if not isinstance(ciphertext, str) or not isinstance(keyword, str):
        raise TypeError("Text and keyword must be strings")

    if len(ciphertext) == 0:
        raise ValueError("Text cannot be empty")

    if len(keyword) == 0:
        raise ValueError("Keyword cannot be empty")

    if len(ciphertext) != len(keyword):
        keyword = (keyword * ((len(ciphertext) // len(keyword)) + 1))[:len(ciphertext)]

    output = ''
    i = 0
    for char in ciphertext:
        if char.isalpha():
            output += chr(int((ord(char) - 65 - (ord(keyword[i]) - 65)) % 26 + 65))
        else:
            output += char

        i += 1

    return output  # Your implementation here

def encrypt_scytale(plaintext, circumference):
    if not isinstance(plaintext, str):
        raise TypeError("Text must be str")
    if not isinstance(circumference, int):
        raise TypeError("Circumference must be int")

    if not plaintext:
        raise ValueError("Text cannot be empty")
    if circumference <= 0:
        raise ValueError("Circumference must be positive")

    while len(plaintext) % circumference != 0:
        plaintext += '~'

    matrix = [[] for _ in range(circumference)]
    cols = len(plaintext) // circumference

    index = 0
    for j in range(cols):
        for i in range(circumference):
            matrix[i].append(plaintext[index])
            index += 1

    ciphertext = ''.join(''.join(row) for row in matrix)
    return ciphertext

def decrypt_scytale(ciphertext, circumference):
    if not isinstance(ciphertext, str):
        raise TypeError("Text must be str")
    if not isinstance(circumference, int):
        raise TypeError("Circumference must be int")

    if not ciphertext:
        raise ValueError("Text cannot be empty")
    if circumference <= 0:
        raise ValueError("Circumference must be positive")

    while len(ciphertext) % circumference != 0:
        ciphertext += "~"

    matrix = [[] for _ in range(circumference)]

    cols = len(ciphertext) // circumference
    index = 0

    for i in range(circumference):
        for j in  range(cols):
            matrix[i].append(ciphertext[index])
            index += 1

    output = ''
    for i in range(cols):
        for j in range(circumference):
            output += matrix[j][i]

    return output.replace('~','');

def encrypt_railfence(plaintext, num_rails):
    if not isinstance(plaintext, str):
        raise TypeError("Text must be str")
    if not isinstance(num_rails, int):
        raise TypeError("Num_rails must be int")

    if not plaintext:
        raise ValueError("Text cannot be empty")
    if num_rails <= 0:
        raise ValueError("Num_rails must be positive")

    while len(plaintext) % num_rails != 0:
        plaintext += '~'

    matrix = [[] for _ in range(num_rails)]

    index = 0
    way = 1
    for j in range(len(plaintext)):
        matrix[index].append(plaintext[j])

        if index == 0:
            way = 1

        if index == (num_rails - 1):
            way = -1

        index += way

    ciphertext = ''.join(''.join(row) for row in matrix)

    return ciphertext

def decrypt_railfence(ciphertext, num_rails):
    if not isinstance(ciphertext, str):
        raise TypeError("Text must be str")
    if not isinstance(num_rails, int):
        raise TypeError("Num_rails must be int")

    if not ciphertext:
        raise ValueError("Text cannot be empty")
    if num_rails <= 0:
        raise ValueError("Num_rails must be positive")

    matrix = [['' for _ in range(len(ciphertext))] for _ in range(num_rails)]

    while len(ciphertext) % num_rails != 0:
        ciphertext += '~'

    index = 0
    way = 1
    for j in range(len(ciphertext)):
        matrix[index][j] = '*'

        if index == 0:
            way = 1

        if index == (num_rails - 1):
            way = -1

        index += way

    index = 0
    way = 1
    for i in range(num_rails):
        for j in range(len(ciphertext)):
            if matrix[i][j] == '*' and index < len(ciphertext):
                matrix[i][j] = ciphertext[index]
                index += 1

    output = ''
    index  = 0
    for i in range(len(ciphertext)):
        output += matrix[index][i]

        if index == 0:
            way = 1

        if index == (num_rails - 1):
            way = -1

        index += way

    output = output.replace('~', '')

    return output

def encrypt_caesar_binary(data):
    key = 3

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be byte or bytearray")
    if len(data) == 0:
        raise ValueError("Data cannot be empty")

    encrypted_bytes = []

    for byte in data:
        encrypted = (byte + key) % 256
        encrypted_bytes.append(encrypted)

    return bytes(encrypted_bytes)

def decrypt_caesar_binary(data):
    key = 3

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be byte or bytearray")
    if len(data) == 0:
        raise ValueError("Data cannot be empty")

    decrypted_bytes = []

    for byte in data:
        decrypted = (byte - key) % 256
        decrypted_bytes.append(decrypted)

    return bytes(decrypted_bytes)


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here