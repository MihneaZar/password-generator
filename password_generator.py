from inputimeout import inputimeout, TimeoutOccurred
from termcolor import colored
from pwinput import pwinput
from hashlib import sha256
import cursor
import string
import base64
import pyotp
import json
import sys
import os

try:
    from cryptography.fernet import Fernet
except:
    pass

IS_ANDROID = hasattr(sys, 'getandroidapilevel')
if not IS_ANDROID:
    import pyperclip


cls = lambda: os.system('cls' if os.name=='nt' else 'clear')
HOMEPATH = os.path.dirname(os.path.realpath(__file__))
DATAPATH = f"{HOMEPATH}/data"
PASS_HASH_FILE = f"{DATAPATH}/.pass"
OTP_FILE = f"{DATAPATH}/.otps.json"
if not IS_ANDROID:
    sys.stderr = open(f"{DATAPATH}/errors.txt", "a")

HASH_LENGTH = 64
HASH_CHARS  = string.digits + "abcdef"

MIN_PASS_LEN    = 6
MAX_CHAR_RATIO  = 3
MAX_CONSECUTIVE = 2
GOOD_PASSWORD   = "Yes this is a good password"

# used for generating app/website password
# other special characters are not used to avoid potential issues
ACCEPTED_CHARACTERS = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&\\"

# timeout in seconds after password was introduced
# also for showing generated password on mobile
TIMEOUT = 10

# checks if string is correct sha256 string
def is_hash(hash_string):
    if len(hash_string) != HASH_LENGTH:
        return False
   
    for c in hash_string:
        if c not in HASH_CHARS:
            return False
       
    return True


# checking if password is strong enough, classic
def check_password(password):
    error_message = ""
   
    # at least MIN_PASS_LEN characters
    if len(password) < MIN_PASS_LEN:
        error_message += f'{colored("Warning", "red")}: Password must be at least {MIN_PASS_LEN} characters.\n'
   

    # any character can only appear at most len(password) / MAX_CHAR_RATIO times
    password_histogram = {}
    for c in password:
        if c in password_histogram:
            password_histogram[c] += 1
        else:
            password_histogram[c] = 1

    max_appearances = int(len(password) / MAX_CHAR_RATIO)
    bad_characters = [c for c in password_histogram if password_histogram[c] > max_appearances]
    if bad_characters:
        multiple_characters = (2 <= len(bad_characters))

        print_bad_characters = "'" + bad_characters[0] + "'"
        for c in bad_characters[1:-1]:
            print_bad_characters += f", '{c}'"
        if multiple_characters:
            print_bad_characters += f" and '{bad_characters[-1]}'"
        error_message += f'{colored("Warning", "red")}: The character{"s" if multiple_characters else ""} {print_bad_characters} appear{"s" if not multiple_characters else ""} too often.\n'


    # no more than MAX_CONSECUTIVE adjacent characters can be consecutive (no 123's and abc's allowed - or 321's or cba's)
    seq_len = max(MAX_CONSECUTIVE + 1, 1)
    bad_sequences = []
    pos = 0
    while pos <= len(password) - seq_len:
        direction = ord(password[pos + 1]) - ord(password[pos]) # checking if the first two characters are ascending or descending
        if abs(direction) != 1: # first two aren't consecutive
            pos += 1
            continue

        new_pos = pos + 1
        # adding to sequence while it keeps the same direction (consecutive ascending or descending)
        while (new_pos < len(password) - 1) and (ord(password[new_pos + 1]) == ord(password[new_pos]) + direction):
            new_pos += 1
       
        new_pos += 1
        # print(password[pos:new_pos])
        # input()
        # if the current consecutive sequence is longer than the maximum allowed, it's added to bad sequences
        if MAX_CONSECUTIVE < new_pos - pos:
            bad_sequences.append(password[pos:new_pos])
       
        # we know we've checked until new_pos - 1
        pos = new_pos
               
    if bad_sequences:
        multiple_sequences = (2 <= len(bad_sequences))

        print_bad_sequences = "'" + bad_sequences[0] + "'"
        for seq in bad_sequences[1:-1]:
            print_bad_sequences += f", '{seq}'"
        if multiple_sequences:
            print_bad_sequences += f" and '{bad_sequences[-1]}'"

        error_message += f'{colored("Warning", "red")}: The sequence{"s" if multiple_sequences else ""} {print_bad_sequences} ha{"s" if not multiple_sequences else "ve"} only consecutive characters.\n'


    # at least one password rule was not fulfilled
    if error_message:
        return error_message
    else:
        # password is good
        return GOOD_PASSWORD
       

def generate_password(password, seed):
    # creating a secret code by making seed and password same length
    # and combining them character by character
    if len(seed) < len(password):
        seed = (len(password) // len(seed)) * seed + seed[:len(password) % len(seed)]

    if len(password) < len(seed):
        password = (len(seed) // len(password)) * password + password[:len(seed) % len(password)]

    secret_code = "".join([seed_char + pass_char for (seed_char, pass_char) in zip(seed, password)])

    # getting numerical values from the hash of the secret code
    hashed_values = sha256(secret_code.encode('utf-8')).digest()

    return "".join([ACCEPTED_CHARACTERS[value % len(ACCEPTED_CHARACTERS)] for value in hashed_values])


def generate_otp(password, secret):
    try:
        # fixing key to 32 characters since that's what fernet requires
        key = base64.b64encode(f"{password[:32]:<32}".encode("utf-8"))
        otp_secret = Fernet(key=key).decrypt(secret)
        return pyotp.TOTP(otp_secret).now()
    except:
        
        print(f'{colored("Warning", "red")}: OTP generation failed, this secret is invalid.\n')
        return None


def password_loop():
    if not IS_ANDROID:
        os.system("title Password Generator")
   
    if not os.path.exists(PASS_HASH_FILE) or not is_hash(open(PASS_HASH_FILE).read(HASH_LENGTH)):
        if os.path.exists(PASS_HASH_FILE):
            print(f'{colored("Warning", "red")}: Password hash has been corrupted.')
        else:
            print(f'{colored("Attention", "yellow")}: Password not set.')

        print("\nChoose a new password, or leave empty to exit.")
        print(f'{colored("Warning", "red")}: Typed password will be visible, please do it in a non-public setting.')
        print(f'{colored("Attention", "yellow")}: Once you hit enter, the screen will be cleared, for security.\nSave the inputted password, or, preferably, don\'t forget it!')

        password = input("\nChoose password: ")
        cls()
        
        if not password or password.isspace():
            quit()
       
        password_check = check_password(password)
        if password_check != GOOD_PASSWORD:
            return password_check

        open(PASS_HASH_FILE, 'w').write(sha256(password.encode('utf-8')).hexdigest())

        return
   
    print(f'{colored("Success", "green")}: Password hash found.\n')
    print("Input saved password and app/website to generate password.")
    print(f'{colored("Attention", "yellow")}: You can change the current password by removing the .pass file, but that means losing the previous password.')
    print(f'{colored("Attention", "yellow")}: Exit program by leaving any input field empty.\n')
    password = pwinput(mask='*')
    print()
    while sha256(password.encode('utf-8')).hexdigest() != open(PASS_HASH_FILE).read(HASH_LENGTH):
        if not password or password.isspace():
            print()
            quit()
        print(f'{colored("Warning", "red")}: Password is incorrect.\nPlease try again or leave empty to quit.\n')
        password = pwinput(mask='*')
        print()

    otps = json.load(open(OTP_FILE)) if os.path.exists(OTP_FILE) else []
       
    print(f"{colored('Attention', 'yellow')}: Choose a naming standard for your apps and websites (such as their name, or the domain name of websites).\n{colored('Attention', 'yellow')}: the name you type here must be identical every time to generate the same password.")
    if otps:
        print(f"{colored('Attention', 'yellow')}: For OTP, input 'otp/' then one of the following:{chr(10) if IS_ANDROID else ' '}{', '.join([otp['name'] for otp in otps])}.\n")
    else:
        print("\n")
    try:
        seed = inputimeout(prompt="App/Website: ", timeout=TIMEOUT).lstrip()
    except TimeoutOccurred:
        if not IS_ANDROID:
            print()
        return f'{colored("Warning", "red")}: Timeout occured, insert password again.\n'
   
    print()

    if not seed or seed.isspace():
        print()
        quit()


    if seed.lower().startswith('otp/'):
        app = seed[len('otp/'):].lower()
        
        otp = next((otp for otp in otps if otp['name'].lower().startswith(app)), None)

        if not otp:
            return f'{colored("Warning", "red")}: Unknown OTP name.\n'
        
        print(f'{colored("Success", "green")}: Secret for {otp["name"]} found.')

        secret = otp['secret']
        output_password = generate_otp(password, secret)
    else:
        output_password = generate_password(password, seed)

    
    # issue with generating otp
    if output_password is None:
        return


    if not IS_ANDROID:
        pyperclip.copy(output_password)

        print(f'{colored("Success", "green")}: App/Website password copied to clipboard.\n{colored("Warning", "red")}: Please don\'t forget to overwrite it and remove it from clipboard when finished.\n')

    else:
        cursor.hide()
        input(f'{colored("Warning", "red")}: Screen will be cleared, and the app/website password  will be shown for {TIMEOUT} seconds, to make copying easier.\nPlease don\'t forget to clear it from clipboard when finished.\n\nPress enter now to see password, then again to continue.\n')

        cls()
        try:
            inputimeout(prompt=output_password, timeout=TIMEOUT)
        except TimeoutOccurred:
            pass

        cursor.show()

    return ""


def main():
    while True:
        error_message = password_loop()
        if IS_ANDROID:
            cls()
           
        if error_message:
            print(error_message)


if __name__ == "__main__":
    main()