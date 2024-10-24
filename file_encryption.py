import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import filetype

key_val = ""
IV_val = ""

def read_file_bytes(file):
    with open(file, "rb") as fi:
        byte_data = fi.read()

    return byte_data

def identify_file_type(file_path):
    kind = filetype.guess(file_path)
    kind = filetype.guess(file_path)
    if kind is None:
        return "exe"
    return kind.extension  # Returns the MIME type of the file

def encrypt_file(file_path):
    # generate key and AES object
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CFB)

    # read file data and encrypt it
    file_data = read_file_bytes(file_path)
    encrypted_data = cipher.encrypt(file_data)

    # get necessary paths and names
    file_directory = os.path.dirname(file_path) + "\\"
    plain_file = os.path.splitext(os.path.basename(file_path))[0]

    # write encrypted data to file
    with open(f"{file_directory}{plain_file}.aes", "wb") as fo:
        fo.write(encrypted_data)

    # delete unencrypted file
    os.remove(file_path)

    # output key
    global key_val, IV_val
    key_val = key.hex()
    IV_val = cipher.iv.hex()


def decrypt_file(file_path, key_val, iv_val):
    # get iv and key
    iv = iv_val
    iv_bytes = bytes.fromhex(iv)
    key = key_val
    key_bytes = bytes.fromhex(key)

    # read data from encrypted file
    with open(file_path, "rb") as fi:
        encrypted_data = fi.read()

    # get necessary paths and names
    file_directory = os.path.dirname(file_path) + "\\"
    plain_file = os.path.splitext(os.path.basename(file_path))[0]

    # decrypt the data
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv=iv_bytes)
    decrypted_data = cipher.decrypt(encrypted_data)

    # write the decrypted data to a file
    file_name = file_directory + plain_file
    with open(file_name, "wb") as fo:
        fo.write(decrypted_data)

    # rename file based on type
    os.rename(file_name, file_name + "." + identify_file_type(file_name))

    os.remove(file_path)
