# DEScent
A Python toolkit for exploring, authenticating, and interacting with MIFARE DESFire PICCs using DES, 3DES, and AES.

# About
DEScent is a personal project built to explore MIFARE DESFire and contribute to NFC communities such as [Dangerous Things](https://forum.dangerousthings.com). It provides a foundation for interacting with DESFire PICCs using DES, 2K3DES, 3K3DES, and AES authentication methods.

This project is a work in progress, and functionality will continue to expand over time.

# Tested Hardware
  ▌ ACS ACR1252U-DOT
  
  ▌ HID Omnikey CL

# Usage

Current functionality:

1. List AID
2. Select AID
3. Create AID
4. Delete AID
5. Show Free Memory
6. Format PICC
7. List Files
8. Read Files

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 desfire_app.py
```
