from smartcard.System import readers
from smartcard.util import toHexString
from Cryptodome.Cipher import DES, DES3, AES
from Cryptodome.Util.Padding import pad
from binascii import unhexlify, hexlify
from collections import deque
import secrets
import logging
import os

"""
DEScent - DESFire Authentication Module

Copyright (C) 2025 Trigat
"""

logging.basicConfig(level=logging.DEBUG)

def rotate_left(data):
    # Left rotate the bytes by 1 position.
    d = deque(data)
    d.rotate(-1)
    return bytes(d)

def rotate_right(data):
    # Right rotate the bytes by 1 position.
    d = deque(data)
    d.rotate(1)
    return bytes(d)

def decrypt(data, key, key_type):
    iv = b'\x00' * (16 if key_type == 'AES' else 8)
    if key_type == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif key_type in ["2TDEA", "3TDEA"]:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif key_type == "AES":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported key type")
    return cipher.decrypt(data)

def encrypt(data, key, key_type):
    iv = b'\x00' * (16 if key_type == 'AES' else 8)

    if key_type == "DES":
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif key_type in ["2TDEA", "3TDEA"]:
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
    elif key_type == "AES":
        if len(data) % 16 != 0:
            raise ValueError("AES data must be 16-byte aligned without padding for DESFire authentication.")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Unsupported key type")

    return cipher.encrypt(data)

def to_bytes(hex_str):
    # Convert a hex string to a byte array.
    return unhexlify(hex_str)

def to_hex(byte_array):
    # Convert a byte array to a hex string.
    return hexlify(byte_array).upper().decode("utf-8")

def get_key():
    key_type = input("Enter key type (DES, 2TDEA, 3TDEA, AES) (Default: DES): ").strip().upper() or "DES"
    master_key = input("Enter key: ")
    print("\n")
    # Cryptodome library does not allow 3DES and AES to use a key of all zeros
    if key_type in ["2TDEA", "3TDEA"] and master_key == "0" * len(master_key):
        print("THE DEFAULT KEY OF ALL ZEROS IS NOT ALLOWED FOR 2TDEA and 3TDEA KEY TYPES.")
    return key_type, master_key

def get_auth_instruction_byte(key_type):
    if key_type == "DES":
        return 0x0A
    elif key_type in ["2TDEA", "3TDEA"]:
        return 0x1A
    elif key_type == "AES":
        return 0xAA
    else:
        raise ValueError("Unsupported key type")

def authenticate(connection):

    # DESFire key
    key_type, master_key = get_key()
    default_key = to_bytes(master_key)
    # default_key = to_bytes("0000000000000000")  # DES key test example

    # Send APDU to the card
    auth_ins = get_auth_instruction_byte(key_type)
    apdu = [0x90, auth_ins, 0x00, 0x00, 0x01, 0x00, 0x00]
    print("Sending APDU:", toHexString(apdu))

    # Get the response from the card
    response, sw1, sw2 = connection.transmit(apdu)

    print("Response:", toHexString(response))
    print(f"Status Words: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0xAF:

        # 1
        challenge = response
        print(f"Challenge from card: {toHexString(challenge)}")

        # 2 Use random value for rndA
        key_lengths = {
            "DES": 8,
            "2TDEA": 8,
            "3TDEA": 16,
            "AES": 16
        }

        rndA_len = key_lengths.get(key_type)
        if not rndA_len:
            raise ValueError(f"Unsupported key type: {key_type}")

        rndA = list(secrets.token_bytes(rndA_len))

        # 3 Decrypt the challenge using the default key (this gives rndB)
        rndB = decrypt(bytes(challenge), default_key, key_type)
        print("Decrypted rndB:", to_hex(rndB))

        # 4 Rotate rndB left (64-bit left rotation)
        left_rotated_rndB = rotate_left(rndB)
        print("Left Rotated rndB:", to_hex(left_rotated_rndB))

        # 5 Concatenate rndA and left-rotated rndB
        rndA_rndB = bytes(rndA) + left_rotated_rndB
        print("Concatenated rndA_rndB:", to_hex(rndA_rndB))

        # 6 Encrypt the concatenated value to get the challenge answer
        challenge_answer = encrypt(rndA_rndB, default_key, key_type)
        print("Challenge Answer:", to_hex(challenge_answer))

        # 7 challenge_answer to the card
        apdu_send_auth = [0x90, 0xAF, 0x00, 0x00, len(challenge_answer)] + list(challenge_answer) + [0x00]
        print("Sending Authentication APDU:", toHexString(apdu_send_auth))

        response, sw1, sw2 = connection.transmit(apdu_send_auth)
        print("Response:", toHexString(response))
        print(f"Status Words: {sw1:02X} {sw2:02X}")

        # 8 Get the actual encrypted rndA from the card
        if sw1 == 0x91 and sw2 == 0x00:  # Check if authentication is working
            encrypted_rndA_from_card = bytes(response)  # This is the actual encrypted RndA
            print("Encrypted rndA from card:", to_hex(encrypted_rndA_from_card))
        else:
            print(f"Authentication failed at response step: {sw1:02X} {sw2:02X}")
            exit()

        # 9 Decrypt the rndA sent by the card
        rotated_rndA_from_card = decrypt(encrypted_rndA_from_card, default_key, key_type)
        print("Decrypted rndA from card:", to_hex(rotated_rndA_from_card))

        # 10 Rotate rndA from the card right (64-bit right rotation)
        rndA_from_card = rotate_right(rotated_rndA_from_card)
        print("Rotated rndA from card:", to_hex(rndA_from_card))

        # 11 Verify if the card's rndA matches the original rndA
        if bytes(rndA_from_card[1:]) + bytes(rndA[:1]): # Compare the 1-byte left rotation
            print("Authenticated!")
        else:
            print("Authentication failed.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

if __name__ == "__main__":
    r = readers()
    if not r:
        print("No smartcard readers found!")
        exit()

    connection = r[0].createConnection()
    connection.connect()
    authenticate(connection)
