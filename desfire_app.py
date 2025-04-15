from smartcard.System import readers
from desfire_auth import authenticate, toHexString, to_bytes
import logging

"""
DEScent - DESFire Communication Tool

Copyright (C) 2025 Trigat

# pip3 install pyscard pycryptodomex

NOTE Apdu code needs cleaned up.
"""

def get_applications(connection):
    apdu = [0x90, 0x6A, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"\nCard status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00:
        if response:
            # Group response bytes into chunks of 3 and join chunk into 6 digit hex
            aids = [response[i:i+3] for i in range(0, len(response), 3)]
            print("Application ID List:")
            for idx, aid in enumerate(aids, start=1):
                print(f"{idx}. {''.join(f'{b:02X}' for b in aid)}")
        else:
            print("No applications found.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

def create_application(connection, key_settings=0x0F, app_settings=0x01):
    aid_hex = input("\nEnter new AID (6 hex characters, e.g., 112233): ")
    aid = to_bytes(aid_hex)
    if len(aid) != 3:
        raise ValueError("AID must be exactly 3 bytes")
    apdu = [0x90, 0xCA, 0x00, 0x00, 0x05] + list(aid) + [key_settings, app_settings, 0x00]
    logging.debug("Create Application APDU: %s", toHexString(apdu))
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")
    print("Create App Response:", toHexString(response))
    if sw1 == 0x91 and sw2 == 0x00:
        print("Application created successfully!")
    else:
        print("Failed to create application.")

def delete_application(connection):
    aid_hex = input("\nEnter AID to delete (6 hex characters): ")
    if len(aid_hex) != 6:
        raise ValueError("AID must be exactly 3 bytes (6 hex characters).")
    aid = to_bytes(aid_hex)
    apdu = [0x90, 0xDA, 0x00, 0x00, 0x03] + list(aid) + [0x00]
    logging.debug("Create Application APDU: %s", toHexString(apdu))
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")
    print("Create App Response:", toHexString(response))
    if sw1 == 0x91 and sw2 == 0x00:
        print(f"Application {aid_hex} deleted successfully!")
    else:
        print("Failed to delete application.")

def free_memory(connection):
    apdu = [0x90, 0x6E, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00:
        if len(response) == 3:
            # Little-endian to int
            free_mem_bytes = int.from_bytes(response, byteorder='little')
            print(f"Free memory: {free_mem_bytes} bytes")
            print(f"≈ {free_mem_bytes / 1024:.2f} KB")
        else:
            print("Unexpected response length for free memory.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

def format_picc(connection):
    confirm = input("Are you sure you want to format the card? (y/n): ").strip().lower()

    if confirm == "y":
        apdu = [0x90, 0xFC, 0x00, 0x00, 0x00]
        response, sw1, sw2 = connection.transmit(apdu)
        print(f"Card status: {sw1:02X} {sw2:02X}")
    elif confirm == "n":
        print("Formatting cancelled.")
    else:
        print("Invalid input. Please enter 'y' or 'n'.")

    if sw1 == 0x91 and sw2 == 0x00:
        print("Format complete.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

def main():
    r = readers()
    if not r:
        print("No smartcard readers found!")
        exit()

    connection = r[0].createConnection()
    connection.connect()
    authenticate(connection)
    while True:
        print("\nChoose an option:")
        print("1. List AIDs")
        print("2. Create a new AID")
        print("3. Delete an AID")
        print("4. Show Free Memory")
        print("5. Format PICC")
        print("6. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            get_applications(connection)
        elif choice == "2":
            create_application(connection)
        elif choice == "3":
            delete_application(connection)
        elif choice == "4":
            free_memory(connection)
        elif choice == "5":
            format_picc(connection)
        elif choice == "6":
            print("Exiting...\n")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
