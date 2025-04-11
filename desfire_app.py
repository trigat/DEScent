from smartcard.System import readers
from desfire_auth import authenticate, toHexString, to_bytes
import logging

"""
DEScent - DESFire Communication Tool

Copyright (C) 2025 Trigat

# pip3 install pyscard pycryptodomex
"""

def create_application(connection, key_settings=0x0F, app_settings=0x01):
    aid_hex = input("Enter new AID (6 hex characters, e.g., 112233): ")
    aid = to_bytes(aid_hex)
    if len(aid) != 3:
        raise ValueError("AID must be exactly 3 bytes")
    apdu = [0x90, 0xCA, 0x00, 0x00, 0x05] + list(aid) + [key_settings, app_settings, 0x00]
    logging.debug("Create Application APDU: %s", toHexString(apdu))
    response, sw1, sw2 = connection.transmit(apdu)
    print("Create App Response:", toHexString(response))
    print(f"Status Words: {sw1:02X} {sw2:02X}")
    if sw1 == 0x91 and sw2 == 0x00:
        print("Application created successfully!")
    else:
        print("Failed to create application.")

def main():
    r = readers()
    if not r:
        print("No smartcard readers found!")
        exit()

    connection = r[0].createConnection()
    connection.connect()
    authenticate(connection)
    create_application(connection)

if __name__ == "__main__":
    main()
