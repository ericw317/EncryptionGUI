import os
import shutil
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

key_val = ""
IV_val = ""

def read_file_bytes(file):
    with open(file, "rb") as fi:
        byte_data = fi.read()

    return byte_data

def encrypt_dir(dir_name):
    # zip the directory
    output_name = f"{os.path.dirname(dir_name)}\\{os.path.basename(dir_name)}"
    shutil.make_archive(output_name, 'zip', dir_name)

    # generate key and AES object
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CFB)

    # read file data and encrypt it
    file_data = read_file_bytes(f"{output_name}.zip")
    encrypted_data = cipher.encrypt(file_data)

    # write encrypted data to file
    with open(f"{output_name}.aes", "wb") as fo:
        fo.write(encrypted_data)

    # delete unencrypted zip file and directory
    os.remove(f"{output_name}.zip")
    shutil.rmtree(dir_name)

    # output key
    print("Key: " + cipher.iv.hex() + key.hex())
    global key_val, IV_val
    key_val = key.hex()
    IV_val = cipher.iv.hex()


def decrypt_dir(dir_name, key_val, iv_val):
    # get iv and key
    iv = iv_val
    iv_bytes = bytes.fromhex(iv)
    key = key_val
    key_bytes = bytes.fromhex(key)

    # read data from encrypted file
    with open(dir_name, "rb") as fi:
        encrypted_data = fi.read()

    # decrypt the data
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv=iv_bytes)
    decrypted_data = cipher.decrypt(encrypted_data)

    # write the decrypted data to a zip file
    zip_name = f"{os.path.dirname(dir_name)}\\{(os.path.basename(dir_name)).split('.')[0]}.zip"
    with open(zip_name, "wb") as fo:
        fo.write(decrypted_data)

    # create directory and unzip to directory
    folder_name = f"{os.path.dirname(dir_name)}\\{(os.path.basename(dir_name)).split('.')[0]}"
    os.mkdir(folder_name)
    shutil.unpack_archive(zip_name, folder_name, "zip")

    # remove the zip file and aes file
    os.remove(zip_name)
    os.remove(dir_name)
