import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# AES-128: 16 bytes (128 bits) key
KEY = b"thisisasecretkey"

def encrypt_message(key, message):
    '''
    Encrypts a message using Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC) mode. 

    Args:
      key (bytes): The symmetric encryption key.
      message (str): The message to be encrypted.

    Returns:
      bytes: The concatenated initialization vector (IV) and ciphertext.
    '''
    # Generate random 16-byte IV
    iv = os.urandom(16)

    # AES cipher with CBC mode Initialization
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Padding of Message to ensure length is a multiple of 16 bytes
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    
    # Encrypt the Padded Message
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, encrypted_message):
    '''
    Decrypts an AES-encrypted ciphertext using the provided key and Cipher Block Chaining (CBC) mode. 

    Args:
      key (bytes): The symmetric decryption key.
      encrypted_message (bytes): The encrypted message which includes the IV and ciphertext.

    Returns: 
      str: The decrypted message.
    '''
    # Separate the IV and the ciphertext
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    # AES cipher with CBC mode Initialization
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding of Message
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()

def generate_nonce():
    '''
    Generates a random nonce for use in the authentication protocol.

    Returns:
      str: The generated nonce in hexadecimal format (8-byte, 16 hex characters).
    '''
    return os.urandom(8).hex()

def alice():
    '''
    Main function for Alice in the protocol.
    '''
    host = "127.0.0.1"
    port = 8000

    # Generate a nonce for Alice
    nonce_a = generate_nonce()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Prepare message for Bob
        message = f"identity = Alice; nonce = {nonce_a}"
        print("\nSending Message 1:", message)
        s.sendall(message.encode())

        # Receive and parse response from Bob
        response = s.recv(1024).decode()
        print("\nReceived Encrypted Message 2:", response)
        nonce_b = response.split(';')[0].split('=')[1]
        encrypted_message = response.split(';')[1].split('=')[1]

        # Decrypt the message sent by Bob
        decrypted_message = decrypt_message(KEY, bytes.fromhex(encrypted_message))
        print("Decrypted Message 2:", decrypted_message)

        # Alice sends encrypted response message including her identity and nonce of Bob
        response_message = f"identity = Alice; nonce = {nonce_b}"
        encrypted_response_message = encrypt_message(KEY, response_message)
        print("\nSending Message 3:", response_message)
        s.sendall(encrypted_response_message.hex().encode())

if __name__ == "__main__":
    alice()