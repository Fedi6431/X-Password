from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
import getpass
import os 
import hashlib
import random
import string
from colorama import init, Fore as cc

init()
dr = DR = r = R = cc.LIGHTRED_EX

clear = os.system('cls')

def Xpass():
    while True:
        clear = os.system('cls')
        clear
        banner = f'''

{r}▒██   ██▒         ██▓███   ▄▄▄        ██████   ██████  █     █░ ▒█████   ██▀███  ▓█████▄ 
{r}▒▒ █ █ ▒░        ▓██░  ██▒▒████▄    ▒██    ▒ ▒██    ▒ ▓█░ █ ░█░▒██▒  ██▒▓██ ▒ ██▒▒██▀ ██▌
{r}░░  █   ░        ▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   ▒█░ █ ░█ ▒██░  ██▒▓██ ░▄█ ▒░██   █▌
{r} ░ █ █ ▒         ▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒  ▒   ██▒░█░ █ ░█ ▒██   ██░▒██▀▀█▄  ░▓█▄   ▌
{r}▒██▒ ▒██▒ ██▓    ▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒▒██████▒▒░░██▒██▓ ░ ████▓▒░░██▓ ▒██▒░▒████▓ 
{r}▒▒ ░ ░▓ ░ ▒▓▒    ▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▓░▒ ▒  ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░ ▒▒▓  ▒ 
{r}░░   ░▒ ░ ░▒     ░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░  ▒ ░ ░    ░ ▒ ▒░   ░▒ ░ ▒░ ░ ▒  ▒ 
{r} ░    ░   ░      ░░         ░   ▒   ░  ░  ░  ░  ░  ░    ░   ░  ░ ░ ░ ▒    ░░   ░  ░ ░  ░ 
{r} ░    ░    ░                    ░  ░      ░        ░      ░        ░ ░     ░        ░    
{r}           ░                                                                      ░      
{r}Type "Help" to see all the commads
'''
        print(f"{banner}")
        ask = input(f"--> ")

        if ask == 'help':
            helplist = '''
Password        Open the password menu
Hash            Generate Hash
Encrypt         Encrypt a message or a file 
Decrypt         Decrypt a message or a file 
Version         Show versions
Info            Show infos
'''
            print(f"{helplist}")
            input("Press enter to go in the main screen")

        if ask == 'version':
            ver = '''
|--------------------|
|  Version  |  Type  |
|   1.0     |  Beta  |
|--------------------|
'''
            print(f"{ver}")
            input("Press enter to go in the main screen")

        if ask == 'info':
            info_list = ''' 
|-------------------------------------|
|Author: Fedi6431                     |
|-------------------------------------|
|Github: https://Github.com/Fedi6431  |
|-------------------------------------|
''' 
            print(f"{info_list}")
            input("Press enter to go in the main screen")

        if ask == 'hash':
            def generate_hash(input_string):
                sha256_hash = hashlib.sha256()
                sha256_hash.update(input_string.encode('utf-8'))
                hashed_value = sha256_hash.hexdigest()
                return hashed_value
            
            user_input = input("Enter the string to generate in hash: ")
            print("\n")
            hashed_result = generate_hash(user_input)
            print(f"The hash (SHA-256) of '{user_input}' is: {hashed_result}")
            print("\n")
            input("Press enter to go in the main screen")

        if ask == 'password':
            pass_Menu = '''
|-----------------------|
|1 Password Generator   |
|-----------------------|
|2 Password strong test |
|-----------------------|
''' 
            print(f"{pass_Menu}")
            chooo = input("Choose the option: ")
            if chooo == '1':
                def generate_password(length=50, include_uppercase=True, include_digits=True, include_special_chars=True):
                    characters = string.ascii_lowercase
                    if include_uppercase:
                        characters += string.ascii_uppercase
                    if include_digits:
                        characters += string.digits
                    if include_special_chars:
                        characters += string.punctuation

                    if length < 1:
                        raise ValueError("Password length must be at least 1")

                    password = ''.join(random.choice(characters) for _ in range(length))
                    return password
            
                password = generate_password()
                print("\n")
                print("Generated Password:", password)
                print("\n")
                input("Press enter to go in the main screen")
            
            if chooo == '2':
                def is_strong_password(password):

                    if len(password) < 8:
                        return False

                    if not any(char.isupper() for char in password):
                        return False

                    if not any(char.isdigit() for char in password):
                        return False

                    return True

                password = input("Write the password to test: ")
                if is_strong_password(password):
                        print("The password is strong")
                else:
                    print("The password is not strong, please choose a stronger password.")

                input("Press enter to go in the main screen")

        if ask == 'encrypt':
            Encript_list= '''
|---------------------------------|
|1 Encrypt Text                   |
|---------------------------------|
|2 Encrypt File                   |
|---------------------------------|
'''
            print(f"{Encript_list}")

            cho = input("Choose the option: ")
            if cho == '1':
                def encrypt(message, shift):
                    encrypted_message = ""
                    for char in message:
                        if char.isalnum():
                            
                            is_upper = char.isupper()
                            is_digit = char.isdigit()
                            
                            
                            char_code = ord(char) + shift

                            
                            if is_upper:
                                if char_code > ord('Z'):
                                    char_code -= 26
                            elif is_digit:
                                if char_code > ord('9'):
                                    char_code -= 10
                            else:
                                if char_code > ord('z'):
                                    char_code -= 26
                            
                            
                            encrypted_message += chr(char_code)
                        else:
                            
                            encrypted_message += char
                    return encrypted_message

                message_to_encrypt = input("Enter the message to encrypt: ")
                shift_amount = int(input("Enter the encrypt number: "))

                encrypted_message = encrypt(message_to_encrypt, shift_amount)
                print("Encrypted message:", encrypted_message)

                input("Press enter to go in the main screen")
            
            if cho == '2':
                def generate_key():
                    return os.urandom(32)

                def encrypt_file(input_file, output_file, key):
                    iv = os.urandom(16)
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                    encryptor = cipher.encryptor()

                    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        f_out.write(iv)
                        while True:
                            chunk = f_in.read(1024)
                            if not chunk:
                                break
                            ciphertext = encryptor.update(chunk)
                            f_out.write(ciphertext)

                input_file = input("Enter file address: ")
                encrypted_file = input_file + '_en'
                key = generate_key()

                encrypt_file(input_file, encrypted_file, key)
                input("Press enter to go in the main screen")

        if ask == 'decrypt':
            Decript_list= '''
|---------------------------------|
|1 Decrypt Text                   |
|---------------------------------|
|2 Decrypt File                   |
|---------------------------------|
'''
            print(f"{Decript_list}")
            choo = input("Choose the option: ")
            if choo == '1':
                def decrypt(encrypted_message, shift):
                    decrypted_message = ""
                    for char in encrypted_message:
                        if char.isalnum():
                            
                            is_upper = char.isupper()
                            is_digit = char.isdigit()
                            
                            char_code = ord(char) - shift

                            if is_upper:
                                if char_code < ord('A'):
                                    char_code += 26
                            elif is_digit:
                                if char_code < ord('0'):
                                    char_code += 10
                            else:
                                if char_code < ord('a'):
                                    char_code += 26
                            
                            decrypted_message += chr(char_code)
                        else:
                            decrypted_message += char
                    return decrypted_message

                # Example usage:
                encrypted_message = input("Enter the message to decrypt: ")
                shift_amount = int(input("Enter the decrypt number: "))

                decrypted_message = decrypt(encrypted_message, shift_amount)
                print("Decrypted message:", decrypted_message)
                input("Press enter to go in the main screen")
            
            if choo == '2':
                def generate_key():
                    return os.urandom(32)

                def decrypt_file(input_file, output_file, key):
                    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        iv = f_in.read(16)
                        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                        decryptor = cipher.decryptor()

                        while True:
                            chunk = f_in.read(1024)
                            if not chunk:
                                break
                            plaintext = decryptor.update(chunk)
                            f_out.write(plaintext)

                
                input_file = input("Enter file address (write _en too): ")
                decrypted_file = input_file.replace('_en', '')
                key = generate_key()
                decrypt_file(input_file, decrypted_file, key)
                input("Press enter to go in the main screen")

        if ask == 'Help':
            helplist = '''
Password        Open the password menu
Hash            Generate Hash
Encrypt         Encrypt a message or a file 
Decrypt         Decrypt a message or a file 
Version         Show versions
Info            Show infos
'''
            print(f"{helplist}")
            input("Press enter to go in the main screen")

        if ask == 'Version':
            ver = '''
|--------------------|
|  Version  |  Type  |
|   1.0     |  Beta  |
|--------------------|
'''
            print(f"{ver}")
            input("Press enter to go in the main screen")

        if ask == 'Info':
            info_list = ''' 
|-------------------------------------|
|Author: Fedi6431                     |
|-------------------------------------|
|Github: https://Github.com/Fedi6431  |
|-------------------------------------|
''' 
            print(f"{info_list}")
            input("Press enter to go in the main screen")

        if ask == 'Hash':
            def generate_hash(input_string):
                sha256_hash = hashlib.sha256()
                sha256_hash.update(input_string.encode('utf-8'))
                hashed_value = sha256_hash.hexdigest()
                return hashed_value
            
            user_input = input("Enter the string to generate in hash: ")
            print("\n")
            hashed_result = generate_hash(user_input)
            print(f"The hash (SHA-256) of '{user_input}' is: {hashed_result}")
            print("\n")
            input("Press enter to go in the main screen")

        if ask == 'Password':
            pass_Menu = '''
|-----------------------|
|1 Password Generator   |
|-----------------------|
|2 Password strong test |
|-----------------------|
''' 
            print(f"{pass_Menu}")
            chooo = input("Choose the option: ")
            if chooo == '1':
                def generate_password(length=50, include_uppercase=True, include_digits=True, include_special_chars=True):
                    characters = string.ascii_lowercase
                    if include_uppercase:
                        characters += string.ascii_uppercase
                    if include_digits:
                        characters += string.digits
                    if include_special_chars:
                        characters += string.punctuation

                    if length < 1:
                        raise ValueError("Password length must be at least 1")

                    password = ''.join(random.choice(characters) for _ in range(length))
                    return password
            
                password = generate_password()
                print("\n")
                print("Generated Password:", password)
                print("\n")
                input("Press enter to go in the main screen")
            
            if chooo == '2':
                def is_strong_password(password):

                    if len(password) < 8:
                        return False

                    if not any(char.isupper() for char in password):
                        return False

                    if not any(char.isdigit() for char in password):
                        return False

                    return True

                password = input("Write the password to test: ")
                if is_strong_password(password):
                        print("The password is strong")
                else:
                    print("The password is not strong, please choose a stronger password.")

                input("Press enter to go in the main screen")

        if ask == 'Encrypt':
            Encript_list= '''
|---------------------------------|
|1 Encrypt Text                   |
|---------------------------------|
|2 Encrypt File                   |
|---------------------------------|
'''
            print(f"{Encript_list}")

            cho = input("Choose the option: ")
            if cho == '1':
                def encrypt(message, shift):
                    encrypted_message = ""
                    for char in message:
                        if char.isalnum():
                            
                            is_upper = char.isupper()
                            is_digit = char.isdigit()
                            
                            
                            char_code = ord(char) + shift

                            
                            if is_upper:
                                if char_code > ord('Z'):
                                    char_code -= 26
                            elif is_digit:
                                if char_code > ord('9'):
                                    char_code -= 10
                            else:
                                if char_code > ord('z'):
                                    char_code -= 26
                            
                            
                            encrypted_message += chr(char_code)
                        else:
                            
                            encrypted_message += char
                    return encrypted_message

                message_to_encrypt = input("Enter the message to encrypt: ")
                shift_amount = int(input("Enter the encrypt number: "))

                encrypted_message = encrypt(message_to_encrypt, shift_amount)
                print("Encrypted message:", encrypted_message)

                input("Press enter to go in the main screen")
            
            if cho == '2':
                def generate_key():
                    return os.urandom(32)

                def encrypt_file(input_file, output_file, key):
                    iv = os.urandom(16)
                    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                    encryptor = cipher.encryptor()

                    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        f_out.write(iv)
                        while True:
                            chunk = f_in.read(1024)
                            if not chunk:
                                break
                            ciphertext = encryptor.update(chunk)
                            f_out.write(ciphertext)

                input_file = input("Enter file address: ")
                encrypted_file = input_file + '_en'
                key = generate_key()

                encrypt_file(input_file, encrypted_file, key)
                input("Press enter to go in the main screen")

        if ask == 'Decrypt':
            Decript_list= '''
|---------------------------------|
|1 Decrypt Text                   |
|---------------------------------|
|2 Decrypt File                   |
|---------------------------------|
'''
            print(f"{Decript_list}")
            choo = input("Choose the option: ")
            if choo == '1':
                def decrypt(encrypted_message, shift):
                    decrypted_message = ""
                    for char in encrypted_message:
                        if char.isalnum():
                            
                            is_upper = char.isupper()
                            is_digit = char.isdigit()
                            
                            char_code = ord(char) - shift

                            if is_upper:
                                if char_code < ord('A'):
                                    char_code += 26
                            elif is_digit:
                                if char_code < ord('0'):
                                    char_code += 10
                            else:
                                if char_code < ord('a'):
                                    char_code += 26
                            
                            decrypted_message += chr(char_code)
                        else:
                            decrypted_message += char
                    return decrypted_message

                # Example usage:
                encrypted_message = input("Enter the message to decrypt: ")
                shift_amount = int(input("Enter the decrypt number: "))

                decrypted_message = decrypt(encrypted_message, shift_amount)
                print("Decrypted message:", decrypted_message)
                input("Press enter to go in the main screen")
            
            if choo == '2':
                def generate_key():
                    return os.urandom(32)

                def decrypt_file(input_file, output_file, key):
                    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        iv = f_in.read(16)
                        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                        decryptor = cipher.decryptor()

                        while True:
                            chunk = f_in.read(1024)
                            if not chunk:
                                break
                            plaintext = decryptor.update(chunk)
                            f_out.write(plaintext)

                
                input_file = input("Enter file address (write _en too): ")
                decrypted_file = input_file.replace('_en', '')
                key = generate_key()
                decrypt_file(input_file, decrypted_file, key)
                input("Press enter to go in the main screen")


Xpass()
