from Crypto.Hash import SHA256
import bcrypt
from cryptography.fernet import Fernet


def main():

    while True:
        choice = 0
        print("***INFOST 325-202 Group Set 2 Final Project***")
        print("TEXT ENCRYPTER/DECRYPTER/HASHER")
        print("Choose Method of Text Manipulation:")
        print("1) Encrypt")
        print("2) Decrypt")
        print("3) Hash")
        print("4) Quit")
        choice = int(input())

        if choice == 1:
            text_to_encrypt = input("Enter the text to encrypt: ")
            encrypted_text = encryptText(text_to_encrypt)
            print(encrypted_text)
            printing()

        elif choice == 2:
            text_to_decrypt = input("Enter the text to decrypt: ")
            decryptKey = input("Enter your key: ")
            decrypted_text = decryptText(text_to_decrypt,decryptKey)
            print(decrypted_text)
            printing()

        #hash
        elif choice == 3:
            hashtype = 0
            print("Choose hash algorithm:")
            print("1) Blowfish")
            print("2) SHA-256")
            hashtype = int(input())

            #blowfish hash
            if hashtype == 1:
                password = input("Enter Text to Hash:")
                bytes = password.encode("utf-8")
                hashed = bcrypt.hashpw(bytes, bcrypt.gensalt())
                print("string:", hashed)
                printing()

            #SHA256 hash
            if hashtype == 2:
                print("Enter Text to Hash:")
                hash_object = SHA256.new(data=b'')
                hashtext = str(input())
                hash_object.update(hashtext.encode())
                hashBinaryRaw = hash_object.digest()
                print("Hash length (SHA-256):", len(hashBinaryRaw)*8)
                print("binary:", hashBinaryRaw)
                hashHexaString = hash_object.hexdigest()
                print("string:", hashHexaString)
                printing()

            elif choice == 4:
                break
            
        else:
            print("Program terminated")
            return


def printing():
    print("Going back to main menu...")
    print("")

def encryptText (text):
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print("Your Key (you will need this to decrypt):")
    print(key)
    print("Encrypted Text:")
    encrypted_text = cipher.encrypt(text.encode())
    return encrypted_text

def decryptText (text, key):
    cipher = Fernet(key)
    decrypted_text = cipher.decrypt(text).decode()
    print("Decrypted Text:")
    return decrypted_text

if __name__ == "__main__":
    main()
