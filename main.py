from Crypto.Hash import SHA256


def main():

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
        print("todo")


    elif choice == 2:
        print("todo")


    elif choice == 3:
        print("Enter Text to Hash:")
        hash_object = SHA256.new(data=b'')
        hashtext = str(input())
        hash_object.update(hashtext.encode())
        hashBinaryRaw = hash_object.digest()
        print("Hash length (SHA-256):", len(hashBinaryRaw)*8)
        print("binary:", hashBinaryRaw)
        hashHexaString = hash_object.hexdigest()
        print("string:", hashHexaString)


    elif choice == 4:
        print("Quitting program...")
    print("Program Terminated")





if __name__ == "__main__":
    main()
