import hashlib
from cryptography.fernet import Fernet
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import secrets
import bcrypt

def main():
    while True:
        choice = 0
        print("***INFOST 325-202 Group Set 2 Final Project***")
        print("TEXT ENCRYPTER/DECRYPTER/HASHER\n")
        print("Choose Method of Text Manipulation:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Hash")
        print("4) Quit Program")
        choice = verifyInput()

        #Encryption
        if choice == 1:
            encryption_type = 0
            print("Choose encryption algorithm:")
            print("1) Fernet (AES-128)")
            print("2) Caesar Cipher (modified)")
            print("3) Blowfish")

            encryption_type = verifyInput()
            text_to_encrypt = input("Enter the text to encrypt: ")
            
            #Fernet
            if encryption_type == 1:
                encrypted_text, key = encryptText(text_to_encrypt, encryption_type)
                print("Your Key:")
                print(key.decode('utf-8'))
                print("Encrypted Text:")
                print(encrypted_text.decode('utf-8'))

            #Caesar
            elif encryption_type == 2:
                key = getInt()
                encrypted_text = encrypt_text(text_to_encrypt, key)
                print("Encrypted Text:")
                print(encrypted_text)

            #Blowfish
            elif encryption_type == 3:
                key_length = secrets.randbelow(9) + 8  # Random number between 8 and 16
                key = secrets.token_bytes(key_length)
                encrypted_text = encrypt_blowfish(text_to_encrypt, key)
                hkey = key.hex()
                print("Your Key:")
                print(hkey)
                print("Encrypted Text:")
                print(encrypted_text)

            else:
                print("Invalid encryption algorithm choice.")
            
            printing()

        #Decryption
        elif choice == 2:
            decryption_type = 0
            print("Choose decryption algorithm:")
            print("1) Fernet")
            print("2) Caesar Cipher")
            print("3) Blowfish")

            decryption_type = verifyInput()

            text_to_decrypt = input("Enter the text to decrypt: ")
            decrypt_key = input("Enter your key: ")

            #Fernet
            if decryption_type == 1:
                decrypted_text = decryptText(text_to_decrypt, decrypt_key)
                print("Decrypted Text:")
                print(decrypted_text)
                printing()

            #Caesar
            elif decryption_type == 2:
                decrypted_text = decrypt_text(text_to_decrypt, key)
                print("Decrypted Text:")
                print(decrypted_text)
                printing()

            #Blowfish
            elif decryption_type == 3:
                decrypted_text = decrypt_blowfish(text_to_decrypt, key)
                print("Decrypted Text:")
                print(decrypted_text)
                printing()
            
            else:
                print("Invalid decryption algorithm choice.")

        #Hash
        elif choice == 3:
            hashtype = 0
            print("Choose hash algorithm:")
            print("1) Bcrypt")
            print("2) SHA-256")
            print("3) RipeMD-160")
            hashtype = int(input())

            #blowfish/bcrypt
            if hashtype == 1:
                password = input("Enter Text to Hash: ")
                bytes = password.encode("utf-8")
                hashed = bcrypt.hashpw(bytes, bcrypt.gensalt())
                print("string:", hashed.decode('utf-8'))
                printing()

            #SHA256
            elif hashtype == 2:
                print("Enter Text to Hash: ")
                hash_object = hashlib.sha256()
                hashtext = str(input())
                hash_object.update(hashtext.encode())
                hashHexaString = hash_object.hexdigest()
                print("string:", hashHexaString)
                printing()

            #ripemd
            elif hashtype == 3:
                print("Enter Text to Hash: ")
                hashtext = str(input())
                hash_object = hashlib.new('ripemd160')
                hash_object.update(hashtext.encode())
                hashHexaString = hash_object.hexdigest()
                print("Hash length (RIPEMD-160):", len(hashHexaString) * 4)
                print("string:", hashHexaString)
                printing()

        elif choice == 4:
            break

        else:
            print("Program terminated")
            return


def encryptText(text, encryption_type):
    if encryption_type == 1:
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_text = cipher.encrypt(text.encode())
        return encrypted_text, key

def decryptText(text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(text).decode()
    return decrypted_text

def encrypt_text(text, key):
    encrypted_text = ""
    for char in text:
        encrypted_text += chr(ord(char) + key)
    return encrypted_text

def decrypt_text(text, key):
    decrypted_text = ""
    for char in text:
        decrypted_text += chr(ord(char) - key)
    return decrypted_text

def encrypt_blowfish(text, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_text = pad(text.encode(), Blowfish.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return b64encode(encrypted_text).decode()

def decrypt_blowfish(encrypted_text, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    encrypted_text_bytes = b64decode(encrypted_text)
    decrypted_text = unpad(cipher.decrypt(encrypted_text_bytes), Blowfish.block_size)
    return decrypted_text.decode()


def printing():
    print("")
    print("Going back to the main menu...")
    print("")

def verifyInput():
    while True:
        choice = input()
        try:
            choice = int(choice)
            if 1 <= choice <= 3:
                return choice
            elif choice == 4:
                break
            else:
                print("Please enter a number 1-4")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def getInt():
    while True:
        choice = input("Enter your key: ")
        try:
            choice = int(choice)
            if choice:
                return choice
            else:
                print("Please enter a number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

if __name__ == "__main__":
    main()
