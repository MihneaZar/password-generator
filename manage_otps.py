from ConsoleListInterface import ConsoleListInterface, MenuInterface
from cryptography.fernet import Fernet
from password_generator import is_hash
from pwinput import pwinput
from hashlib import sha256
from readchar import key
import base64
import json
import yaml
import sys
import os


HOMEPATH = os.path.dirname(os.path.realpath(__file__))
DATAPATH = f"{HOMEPATH}/data"
PASS_HASH_FILE = f"{DATAPATH}/.pass"
OTP_FILE = f"{DATAPATH}.otps.json"
sys.stderr = open(f"{DATAPATH}/errors.txt", "a")

HASH_LENGTH = 64


def create_new_secret():
    print("Add new secret (or leave any field empty to cancel):")
    name = input("Secret name: ")
    if not name or name.isspace():
        return None

    code = pwinput(prompt="Original secret: ", mask='*')
    if not code or code.isspace():
        return None

    password = pwinput(mask='*')
    print()
    while sha256(password.encode('utf-8')).hexdigest() != open(PASS_HASH_FILE).read(HASH_LENGTH):
        if not password or password.isspace():
            print()
            return None
        print("Password is incorrect. Try again, or leave it empty to cancel.")
        password = pwinput(mask='*')
        print()
        
    # fixing password to 32 characters since that's what fernet requires
    key = base64.b64encode(f"{password[:32]:<32}".encode("utf-8"))
    
    return {'name': name, 'secret': Fernet(key=key).encrypt(code.encode("utf-8")).decode()}


def main():
    if not os.path.exists(PASS_HASH_FILE) or not is_hash(open(PASS_HASH_FILE).read(HASH_LENGTH)):
        print("\nPassword hash is missing or is corrupted, please set by running 'password_generator.py'.\n")
        return

    if not os.path.isfile(f'{DATAPATH}/.otps.json'):
        with open(f'{DATAPATH}/.otps.json', 'w', encoding='utf-8') as file:
            json.dump([], file, ensure_ascii=False, indent=4)
        
        otps = []
    else: 
        otps = json.load(open(f'{DATAPATH}/.otps.json', 'r', encoding='utf-8'))

    console = ConsoleListInterface(items=[otp['name'] for otp in otps], specialCommands=[key.CTRL_N, '?', key.ESC])

    console.setTitle("Manage OTP Secrets")
    console.setTopText("Your OTP Secrets:\n")
    
    while True:
        command, curr_pos = console.interact()

        # adding secret
        if command == key.CTRL_N:
            new_secret = console.separateInteraction(function=create_new_secret, showCursor=True)
            if new_secret:
                otps.append(new_secret)

            console.updateList([otp['name'] for otp in otps])
            console.updatePos(len(otps) - 1)

        # changing name of secret
        if command == key.CTRL_R:
            otps[curr_pos]['name'] = console.getItems()[curr_pos]

        # deleting secret
        if command == key.DELETE:
            otps.pop(curr_pos)


        if command == '?':
            console.separateInteraction(function=lambda: MenuInterface.helpMenu(yaml.safe_load(open(f"{DATAPATH}/manage_otps_help_menu.yaml")), 'light_grey', 'light_grey'))

        if command == key.ESC:
            console.exitInterface()
            quit()

        # if the command wasn't Esc, then it changed the otps
        with open(f'{DATAPATH}/.otps.json', 'w', encoding='utf-8') as file:
            json.dump(otps, file, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    main()