# finalproject

This code creates a text encryption/decryption and hashing tool using various cryptographic algorithms. 
It's a command-line program that provides a menu-driven interface allowing users to choose between encryption, decryption, and hashing methods.

Here's a breakdown of what the code does:

Encryption:

Offers three encryption methods: Fernet (AES-128), Caesar Cipher, and Blowfish.
For Fernet encryption, it generates a key and encrypts the input text.
Caesar Cipher shifts characters by a given key value (in this case converts the text to unicode and shifts that, then converts back).
Blowfish encryption uses a randomly generated key to encrypt the text.

Decryption:

Corresponding decryption methods are provided for the encryption algorithms.
Users can input the encrypted text and, if necessary, the key to decrypt it.

Hashing:

Offers three hashing algorithms: Bcrypt, SHA-256, and RIPEMD-160.
Bcrypt hashes the input text using a salted hash.
SHA-256 and RIPEMD-160 hash algorithms are available for text input.

Input Verification:

The code includes input verification functions to ensure the user inputs valid choices and data types. 

Main Loop:

The main function runs an infinite loop presenting a menu of options (encryption, decryption, or hashing).
Based on the user's choice, it executes the corresponding functionality and loops back to the menu.

Error Handling:

It incorporates error handling for incorrect inputs or choices made by the user.

Have fun!
