import sys
import os


HOMEPATH = os.path.dirname(os.path.realpath(__file__))
PASS_HASH_FILE = f"{HOMEPATH}/.pass"
OTP_FILE = f"{HOMEPATH}.otps.json"
sys.stderr = open(f"{HOMEPATH}/errors.txt", "a")

HASH_LENGTH = 64

def get_path(path, must_exist=True, check_dir=False, check_file=False, replace_quotes=True):
    if path == "":
        raise ValueError("empty")
    
    if path.isspace():
        raise ValueError("space")
    
    realpath = os.path.realpath(path)
    
    if must_exist and not os.path.exists(realpath):
        raise ValueError("not exists")
    
    if check_dir and not os.path.isdir(realpath):
        raise ValueError("not dir")
    
    if check_file and not os.path.isfile(realpath):
        raise ValueError("not file")

    if replace_quotes:
        realpath = realpath.replace('\"', '')
        realpath = realpath.replace('\'', '')
    
    return realpath


if not os.path.isfile(f'{HOMEPATH}/.paths') or not os.path.exists(f'{open(f"{HOMEPATH}/.paths").read()}/ConsoleListInterface.py'):
    print("Please type path to directory of ConsoleListInterface.py (or leave empty to cancel):")

    while True: 
        try:
            console_path = get_path(input(), check_dir=True)
            accepted = os.path.exists(f'{console_path}/ConsoleListInterface.py')
        except Exception as e:
            console_path = ""
            accepted = str(e) in ["empty", "space"]
        finally:
            if accepted:
                break
            else:
                print("ConsoleListInterface.py not found, please try again:")

    if not console_path:
        quit()

    open(f'{HOMEPATH}/.paths', 'w').write(console_path)

sys.path.append(open(f'{HOMEPATH}/.paths').read())

from ConsoleListInterface import ConsoleListInterface # pyright: ignore[reportMissingImports]
from cryptography.fernet import Fernet
from password_generator import is_hash
from pwinput import pwinput
from hashlib import sha256
from readchar import key
import base64
import json


HELP_PAGE = """
Here, you can manage the OTP secrets that can be read by the password generator.

Controls:
    - arrow keys -> moving between secrets in the list.
    - character  -> move cursor to the next secret name which starts with character.
    - ctrl+f     -> search for the next secret name which contains string.
    - '\\'        -> find secret name that contains string.
    - ctrl+n     -> create new secret.
    - ctrl+r     -> rename selected secret.
    - delete     -> delete selected secret.
    - ctrl+u     -> update printed list (if list or console size was changed).
    - '='/'-'    -> increase/decrease length of secret names before they are cut off.
    - '?'        -> display current help page.
    - escape     -> quit application.
""" 


def create_new_secret():
    print("Leave any field empty to cancel.")
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
        
    key = base64.b64encode(f"{password:<32}".encode("utf-8"))
    
    return {'name': name, 'secret': Fernet(key=key).encrypt(code.encode("utf-8")).decode()}


def main():
    os.system('title Manage OTP Secrets')

    if not os.path.exists(PASS_HASH_FILE) or not is_hash(open(PASS_HASH_FILE).read(HASH_LENGTH)):
        print("\nPassword hash is missing or is corrupted, please set by running 'password_generator.py'.\n")
        return

    if not os.path.isfile(f'{HOMEPATH}/.otps.json'):
        with open(f'{HOMEPATH}/.otps.json', 'w', encoding='utf-8') as file:
            json.dump([], file, ensure_ascii=False, indent=4)
        
        otps = []
    else: 
        otps = json.load(open(f'{HOMEPATH}/.otps.json', 'r', encoding='utf-8'))

    console = ConsoleListInterface(items=[otp['name'] for otp in otps], specialCommands=[key.CTRL_N, key.ESC], helpPage=HELP_PAGE)
    
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

        if command == key.ESC:
            console.exitInterface()
            quit()

        # if the command wasn't Esc, then it changed the otps
        with open(f'{HOMEPATH}/.otps.json', 'w', encoding='utf-8') as file:
            json.dump(otps, file, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    main()