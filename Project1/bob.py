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

def bob():
    '''
    Main function for Bob in the protocol.
    '''
    host = "127.0.0.1"
    port = 8000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("Bob is listening for connections...")
        conn, addr = s.accept()
        with conn:
            print(f"Connection established with {addr}")
            
            # Receive Message 1 from Alice
            message = conn.recv(1024).decode()
            print("\nReceived Message 1:", message)

            # Parse Message 1
            identity = message.split(';')[0].split('=')[1]
            nonce_a = message.split(';')[1].split('=')[1]

            print(f"Received Identity:{identity}, Nonce:{nonce_a}")

            # Prepare message and generate nonce for Bob
            nonce_b = generate_nonce()
            response_message = f"identity = Bob; nonce = {nonce_a}"
            encrypted_response_message = encrypt_message(KEY, response_message)

            # Send response with nonce and encrypted response message
            response = f"nonce = {nonce_b}; encrypted_message = {encrypted_response_message.hex()}"
            print("\nSending Message 2:", response)
            conn.sendall(response.encode())

            # Receive and decrypt response from Alice
            response_a = conn.recv(1024).decode()
            print("\nReceived Message 3:", response_a)
            decrypted_response_a = decrypt_message(KEY, bytes.fromhex(response_a))
            print("Decrypted Message 3:", decrypted_response_a)

if __name__ == "__main__":
    bob()