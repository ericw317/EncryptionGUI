import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64

key_val = ""
IV_val = ""
ciphertext_encrypt_val = ""
plaintext_val = ""

def encrypt(message):
    # generate key and AES object
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CFB)

    # encrypt message
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    ciphertext = base64.b64encode(ciphertext).decode('utf-8')

    global key_val, IV_val, ciphertext_encrypt_val
    key_val = key.hex()
    IV_val = cipher.iv.hex()
    ciphertext_encrypt_val = ciphertext

def decrypt(ciphertext, key, iv):
    # convert ciphertext, key, and iv to bytes
    ciphertext = base64.b64decode(ciphertext)
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)

    # decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    plaintext = (cipher.decrypt(ciphertext)).decode('utf-8')
    global plaintext_val
    plaintext_val = plaintext