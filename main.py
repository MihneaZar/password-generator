# kivy imports
from kivy.app import App
from kivy.lang.builder import Builder
from kivy.properties import StringProperty, ColorProperty
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.core.clipboard import Clipboard

# backend imports 
from hashlib import sha256
from time import time
import string
import os

# password generator backend
PASS_HASH_FILE = ".pass"

# password requirements 
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
        return f'Password must be at least {MIN_PASS_LEN} characters.'
   

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
        return f'The character{"s" if multiple_characters else ""} {print_bad_characters} appear{"s" if not multiple_characters else ""} too often.'


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

        return f'The sequence{"s" if multiple_sequences else ""} {print_bad_sequences} ha{"s" if not multiple_sequences else "ve"} only consecutive characters.'


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


# kivy frontend

passgen = """

ScreenManager: 
    MainScreen


<MainScreen>:
    name: 'passgen'

    Label:
        text: 'Password generator'
        font_size: (self.height/20)*1
        pos_hint:{'center_x':0.48, 'center_y': 0.9}

    Label:
        text: 'App:'
        font_size: (self.height/15)* 0.85
        pos_hint: {'center_x':0.13, 'center_y': 0.77}  

    TextInput:
        id: app
        text: ''
        size_hint: 0.7, 0.06
        pos_hint: {'center_x': 0.65, 'center_y': 0.765}    
        multiline: False
        font_size: self.height - 30
        on_text_validate: root.ids.password.focus = True

    Label:
        text: 'Pass:'  
        font_size: (self.height/15)* 0.85
        pos_hint:{'center_x': 0.15, 'center_y': 0.67}
        
    TextInput:
        id: password
        text: ''
        multiline: False
        size_hint: 0.7, 0.06
        font_size: self.height - 30
        pos_hint:{'center_x':0.65,'center_y': 0.665}   
        password: True  
        on_text_validate: root.generate()
        text_validate_unfocus: False
        on_text: root.reset_timeout()

    Button:
        text: 'Generate Password'
        size_hint: .8,.06
        font_size: self.height - 30
        pos_hint:{'center_x': 0.5, 'center_y': 0.55}    
        on_release: root.generate() 

    Label:
        text: root.response   
        color: root.response_color
        font_size: (self.height/30) * 0.85
        pos_hint: {'center_x': 0.5, 'center_y': 0.45}   
        halign: 'center'
        
    Button:
        text: 'Reset Password'
        size_hint: .8,.06
        font_size: self.height - 30
        pos_hint:{'center_x': 0.5, 'center_y': 0.34}    
        on_release: root.reset_password()
        color: 1, 0, 0, 1
"""


class ProfileCreate(App):
    def build(self):
        screen = Builder.load_string(passgen)
        return screen


class MainScreen(Screen):   
    response = StringProperty()
    response_color = ColorProperty()

    timeout = time()


    def show_result(self, result):
        length = len(result) 
        mid = length // 2 + result[length // 2].find(' ')
        result = result[:mid] + '\n' + result[mid:]
        self.response = result


    def generate(self):     
        self.response = ''

        password = self.ids.password.text
        app      = self.ids.app.text

        self.ids.password.text = ''
        self.ids.password.focus = True

        if not os.path.exists(PASS_HASH_FILE) or not is_hash(open(PASS_HASH_FILE).read(HASH_LENGTH)):
            result = check_password(password)

            if result != GOOD_PASSWORD:
                self.response_color = 1, 0, 0, 1
                self.show_result(result)
                self.ids.password.focus = True
                
                return

            else: 
                open(PASS_HASH_FILE, 'w').write(sha256(password.encode('utf-8')).hexdigest())
                self.response_color = 0, 1, 0, 1
                self.show_result("Password has been saved.")
                

        if app and not app.isspace():
            if sha256(password.encode('utf-8')).hexdigest() != open(PASS_HASH_FILE).read(HASH_LENGTH):
                self.response_color = 1, 0, 0, 1
                self.show_result("Incorrect password.")
                
                return
            
            if TIMEOUT < time() - self.timeout:
                self.response_color = 1, 0, 0, 1
                self.show_result("Timeout occured.")
                
                return

            self.ids.app.text = ''

            generated_password = generate_password(password, app)
            Clipboard.copy(generated_password)
            
            self.response_color = 0, 1, 0, 1
            self.show_result("Password saved to clipboard!") 
            
        self.ids.app.focus = True


    def reset_timeout(self):
        self.timeout = time()


    def reset_password(self):
        if os.path.exists(".pass"):
            os.remove(".pass")
            self.response_color = 0, 1, 0, 1
            self.show_result("Password has been reset.")


def main():
    sm = ScreenManager()
    sm.add_widget(MainScreen(name='Main'))

    ProfileCreate().run()


if __name__=="__main__":
    main()
