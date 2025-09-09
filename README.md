# EX-8-ADVANCED-ENCRYPTION-STANDARD ALGORITHM
# Aim:
To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

# ALGORITHM:
AES is based on a design principle known as a substitution–permutation.
AES does not use a Feistel network like DES, it uses variant of Rijndael.
It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
AES operates on a 4 × 4 column-major order array of bytes, termed the state
# PROGRAM:
```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    padding_len = AES.block_size - len(text) % AES.block_size
    return text + chr(padding_len) * padding_len

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

def aes_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(iv + ciphertext).decode()

def aes_decrypt(ciphertext_b64, key):
    ciphertext = base64.b64decode(ciphertext_b64)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[AES.block_size:]).decode()
    return unpad(decrypted)

def main():
    # take user inputs
    key_input = input("Enter a key (16/24/32 characters): ").encode()
    plaintext = input("Enter the plaintext: ")

    # ensure key is valid size
    if len(key_input) not in [16, 24, 32]:
        print("Error: Key must be 16, 24, or 32 bytes long.")
        return

    encrypted = aes_encrypt(plaintext, key_input)
    print("\nEncrypted (Base64):", encrypted)

    decrypted = aes_decrypt(encrypted, key_input)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main()

```
# OUTPUT:

<img width="735" height="133" alt="image" src="https://github.com/user-attachments/assets/17dd87e0-f8ed-4c12-8629-d5cb6faefbba" />

# RESULT:
Thus AES has been implemented successfully.

