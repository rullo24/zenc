# Zenc - Zig Secure File Encryption

This project encrypts files to ensure both their privacy and integrity. The process follows a series of best practices to achieve strong security.

### Zig Version
0.15.1

## Encryption Steps

1. Generate a Secure Key: A strong encryption key is created from a password using a Key Derivation Function (KDF).
2. Read Plaintext: The program reads the original, unencrypted file content.
3. Generate a Unique Nonce: A one-time-use number (nonce) is generated for each encryption to ensure uniqueness.
4. Encrypt Data: An Authenticated Encryption with Associated Data (AEAD) algorithm scrambles the plaintext into ciphertext.
5. Create a Tamper-Proof Tag: A unique tag is generated to verify that the file has not been altered after encryption.
6. Package the File: The nonce, ciphertext, and authentication tag are saved together in a new encrypted file.
7. Securely Erase Data: The key and other sensitive information are securely wiped from memory using `std.crypto.secureZero`

## Decryption Steps

Read Encrypted Data: The program reads the encrypted file, which contains the ciphertext, nonce, and authentication tag.
1. Get the Same Key: The same key used for encryption is required to decrypt the file.
2. Verify and Decrypt: The AEAD algorithm first verifies the authentication tag to ensure the file has not been tampered with. If the tag is valid, it then uses the key and nonce to decrypt the ciphertext back into the original plaintext.
3. Save the File: The decrypted plaintext is saved to a new, unencrypted file.
4. Securely Erase Data: The decryption key and any other sensitive data are securely wiped from memory.
