from smartcard.System import readers
from desfire_auth import authenticate, toHexString, to_bytes
import logging

"""
DEScent - DESFire Communication Tool

Copyright (C) 2025 Trigat

NOTE Apdu code needs cleaned up.
"""

def get_applications(connection):
    # Verifies AID is valid before displaying result
    def quick_select_aid(aid_bytes):
        apdu = [0x90, 0x5A, 0x00, 0x00, 0x03] + aid_bytes + [0x00]
        _, sw1, sw2 = connection.transmit(apdu)
        return (sw1, sw2)

    apdu = [0x90, 0x6A, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"\nCard status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00 and response:
        chunks = [response[i:i+3] for i in range(0, len(response), 3) if len(response[i:i+3]) == 3]

        valid_aids = []
        for chunk in chunks:
            sw1, sw2 = quick_select_aid(chunk)
            if (sw1, sw2) == (0x91, 0x00):
                valid_aids.append(chunk)
            else:
                break  # stop at first invalid AID

        print("Application ID List:")
        for i, aid in enumerate(valid_aids, start=1):
            print(f"{i}. {''.join(f'{b:02X}' for b in aid)}")
    else:
        print("No applications found.")

def select_application(connection):
    aid_hex = input("\nEnter AID to select (6 hex characters): ")
    if len(aid_hex) != 6:
        raise ValueError("AID must be exactly 3 bytes (6 hex characters).")
    aid = to_bytes(aid_hex)

    apdu = [0x90, 0x5A, 0x00, 0x00, 0x03] + list(aid) + [0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")
    print("AID Selected:", aid_hex)

    if (sw1, sw2) == (0x91, 0x00):
        print("\nAID Authentication... Enter AID key type and key:\n")
        authenticate(connection)   # re-use authentication
        aid_file_menu(connection, aid, aid_hex)
    elif (sw1, sw2) == (0x91, 0xA0):
        print("Requested AID not present on PICC.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

def create_application(connection, key_settings=0x0F, app_settings=0x01):
    print("\n New AID will be created as DES with default key of 0000000000000000.\n")
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
    aid_hex = input("\nVerify AID to delete (6 hex characters): ")
    if len(aid_hex) != 6:
        raise ValueError("AID must be exactly 3 bytes (6 hex characters).")

    aid = to_bytes(aid_hex)
    apdu = [0x90, 0xDA, 0x00, 0x00, 0x03] + list(aid) + [0x00]
    logging.debug("Delete Application APDU: %s", toHexString(apdu))
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")

    if (sw1, sw2) == (0x91, 0x00):
        print(f"\nApplication {aid_hex} deleted successfully!")
        print(f"Returning to main menu.\n")
        # Select the PICC (AID = 000000) after deletion
        apdu = [0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]
        _, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) == (0x91, 0x00):
            print("PICC Master Key Authentication... Enter key type and key:")
            authenticate(connection)
        else:
            print(f"Failed to reselect PICC: {sw1:02X} {sw2:02X}")

        return "deleted"
    else:
        print("Failed to delete application.")
        return False

def free_memory(connection):
    apdu = [0x90, 0x6E, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"Card status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00:
        if len(response) >= 3:
            free_mem_bytes = int.from_bytes(response[:3], byteorder='little')
            print(f"Free memory: {free_mem_bytes} bytes ({free_mem_bytes / 1024:.2f} KB)")
            if len(response) > 3:
                return
        else:
            print("Unexpected response length for free memory.")
    else:
        print(f"Card responded with unexpected status: {sw1:02X} {sw2:02X}")

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

def list_files(connection):
    def quick_get_file_settings(fid_byte):
        # CLA=90, INS=F5, P1=P2=00, Lc=1, Data=fid, Le=0
        apdu = [0x90, 0xF5, 0x00, 0x00, 0x01, fid_byte, 0x00]
        _, sw1, sw2 = connection.transmit(apdu)
        return (sw1, sw2)

    apdu = [0x90, 0x6F, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"\nCard status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00 and response:
        # File IDs are 1 byte each
        fids = [b for b in response]

        valid_fids = []
        for fid in fids:
            # Call file settings to verify fid exists
            sw1, sw2 = quick_get_file_settings(fid)
            if (sw1, sw2) == (0x91, 0x00):
                valid_fids.append(fid)
            else:
                break  # stop at first invalid file

        print("File ID List:")
        for i, fid in enumerate(valid_fids, start=1):
            print(f"{i}. {fid:02X}")
    else:
        print("No files found.")

"""  # Simple Version that doesn't break authentication

def list_files(connection):

    apdu = [0x90, 0x6F, 0x00, 0x00, 0x00]
    response, sw1, sw2 = connection.transmit(apdu)
    print(f"\nCard status: {sw1:02X} {sw2:02X}")

    if sw1 == 0x91 and sw2 == 0x00 and response:
        if response:
            print("File ID List:")
            for i, fid in enumerate(response, start=1):
                print(f"{i}. {fid:02X}")
                print(response)
    else:
        print("\nNo files found.")
"""

def read_file(connection):
    fid_hex = input("\nEnter file ID to read (2 hex characters): ")
    if len(fid_hex) != 2:
        raise ValueError("File ID must be exactly 1 byte (2 hex characters).")
    fid = to_bytes(fid_hex)

    # Read Data: CLA=90, INS=BD, P1=00, P2=00, Lc=07, Data=fid+offset+length+commMode, Le=00
    apdu = [0x90, 0xBD, 0x00, 0x00, 0x07] + list(fid) + [0x00, 0x00, 0x00,  # offset = 0
                                                   0x00, 0x00, 0x00,  # length = 0 (means full file)
                                                   0x00]              # comm mode = plain
    response, sw1, sw2 = connection.transmit(apdu)

    file_data = bytearray(response)

    while (sw1, sw2) == (0x91, 0xAF):
        # Request next frame
        apdu_next = [0x90, 0xAF, 0x00, 0x00, 0x00]
        response, sw1, sw2 = connection.transmit(apdu_next)
        file_data.extend(response)

    print("File content:", file_data.hex().upper())
    print("As text:", file_data.decode("utf-8", errors="ignore"))

    if (sw1, sw2) == (0x91, 0x00):
        print("Read complete.")
    elif (sw1, sw2) == (0x6A, 0x82):
        print("File not found.")
    elif (sw1, sw2) == (0x91, 0xF0):
        print("\nSpecified file number does not exist.")
    else:
        print(f"Card responded with an unexpected status: {sw1:02X} {sw2:02X}")

def aid_file_menu(connection, aid, aid_hex):

    while True:
        print(f"\n[ AID {aid_hex} is open ]")
        print("\nChoose an operation:")
        print("1. List Files")
        print("2. Read a File")
        '''
        # Options currently not implemented

        print("3. Create a Standard Data File")
        print("4. Write to a File")
        print("5. Edit File Restrictions")
        print("6. Delete a File")
        '''
        print("7. Delete current AID")
        print("8. Back")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            list_files(connection)
            print("\nMust reauthenticate after listing AID files.")
            print("AID Authentication... Enter AID key type and key:\n")
            authenticate(connection)
        elif choice == "2":
            read_file(connection)
        elif choice == "3":
            create_file(connection, aid, aid_hex)
        elif choice == "4":
            write_to_file(connection, aid, aid_hex)
        elif choice == "5":
            edit_file_restriction(connection, aid, aid_hex)
        elif choice == "6":
            delete_file(connection, aid, aid_hex)
        elif choice == "7":
            result = delete_application(connection)
            if result == "deleted":
                return
        elif choice == "8":
            print("\nReturning to main menu.")
            print("PICC Master Key Authentication... Enter key type and key:")
            # Select the PICC (AID = 000000)
            apdu = [0x90, 0x5A, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]
            _, sw1, sw2 = connection.transmit(apdu)

            if (sw1, sw2) == (0x91, 0x00):
                authenticate(connection)
            else:
                print(f"Failed to reselect PICC: {sw1:02X} {sw2:02X}")

            break
        else:
            print("\nInvalid choice, please try again.")

def main():
    r = readers()
    if not r:
        print("No smartcard readers found!")
        exit()
    print("""
               .:: DEScent ::.
    
    This app will not function when secondary card readers
    and security keys are plugged in.
    
    Currently:
      - DES options only work with the default key of 00000000000000000.
      - 2TDEA options will not work with the default key of all 00's.
      - AES works well.
    """)
    connection = r[0].createConnection()
    connection.connect()
    authenticate(connection)
    while True:
        print("\nChoose an option:")
        print("1. List AIDs")
        print("2. Select AID")
        print("3. Create a new AID")
        print("4. Show Free Memory")
        print("5. Format PICC")
        print("6. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            get_applications(connection)
        elif choice == "2":
            select_application(connection)
        elif choice == "3":
            create_application(connection)
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
