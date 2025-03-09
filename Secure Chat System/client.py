import socket
import threading
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from datetime import datetime

# Set of Used Timestamps to Prevent Replay Attacks
used_timestamps = set()

def encrypt_message(message, key):
    '''
    Encrypts a message using AES in EAX mode.

    Args:
        message (str): The message to be encrypted.
        key (bytes): The symmetric encryption key.
    
    Returns:
        str: The base64-encoded concatenation of nonce, tag, and ciphertext.
    '''
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, key):
    '''
    Decrypts an AES-encrypted message in EAX mode.

    Args:
        encrypted_message (str): The base64-encoded message to be decrypted.
        key (bytes): The symmetric encryption key.
    
    Returns:
        str: The decrypted message.
    '''
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def sign_message(message, private_key):
    '''
    Signs a message using RSA and the SHA-256 hash algorithm.

    Args:
      message (str): The message to be signed.
      private_key (RSA.RsaKey): The private key used for signing the message.

    Returns:
      bytes: The signature of the message.
    '''
    message_hash = SHA256.new(message.encode())
    return pkcs1_15.new(private_key).sign(message_hash)

def verify_signature(message, signature, public_key):
    '''
    Verifies the signature of a message using RSA and the SHA-256 hash algorithm.

    Args:
      message (str): The original message whose signature needs to be verified.
      signature (bytes): The signature to verify.
      public_key (RSA.RsaKey): The public key used for verifying the signature.

    Returns:
      bool: True if the signature is valid, False otherwise.
    '''
    message_hash = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False

def receive_messages(client_socket, Ks, known_public_keys):
    '''
    Receives and processes messages from other clients, verifying signatures and decrypting the message.

    Args:
      client_socket (socket.socket): The socket used for communication.
      Ks (bytes): The group key used for decrypting messages.
      known_public_keys (dict): A dictionary of known public keys of clients.
    '''
    while True:
        try:
            message = client_socket.recv(4096).decode()

            sender_id, encrypted_message, signature_b64 = message.split("||")
            signature = base64.b64decode(signature_b64)
            decrypted_message = decrypt_message(encrypted_message, Ks)

            # Retrieve Sender's Public Key if not known
            if sender_id not in known_public_keys:
                client_socket.sendall(f"REQUEST_PUBKEY||{sender_id}".encode())
                public_key_pem = client_socket.recv(4096)
                known_public_keys[sender_id] = RSA.import_key(public_key_pem)

            sender_public_key = known_public_keys.get(sender_id)

            if sender_public_key and verify_signature(decrypted_message, signature, sender_public_key):
                print(f"\n[{client_id}] Message From [{sender_id}]: {decrypted_message}")
            else:
                print(f"\n[{client_id}] Invalid Signature From {sender_id}!")

        except Exception as e:
            print(f"\n[{client_id}] Error Receiving Message: {e}")
            break

def start_client(client_id, kdc_host, kdc_port):
    '''
    Starts the client registeration with the KDC for sending and receiving messages.

    Args:
        client_id (str): The client identifier.
        kdc_host (str): The host address of the KDC. 
        kdc_port (int): The port number of the KDC.
    '''
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((kdc_host, kdc_port))
    print(f"[{client_id}] Connection Established with KDC")

    # Generate RSA Key Pair
    client_private_key = RSA.generate(2048)
    client_public_key = client_private_key.publickey()

    # Register With KDC
    client_socket.sendall(client_id.encode())
    client_socket.sendall(client_public_key.export_key())
    
    # Receive KDC Public Key
    known_public_keys = {}
    kdc_public_key_pem = client_socket.recv(4096)
    kdc_public_key = RSA.import_key(kdc_public_key_pem)
    known_public_keys['KDC'] = kdc_public_key

    # Receive Group Key (Ks)
    encrypted_ks = client_socket.recv(4096)
    rsa_cipher = PKCS1_OAEP.new(client_private_key)
    Ks = rsa_cipher.decrypt(encrypted_ks)
    print(f"[{client_id}] Successfully Received Group Key (Ks)")

    threading.Thread(target=receive_messages, args=(client_socket, Ks, known_public_keys), daemon=True).start()

    # Handle Sending Messages to KDC for Relaying to Other Clients
    while True:
        message = input(f"\n[{client_id}] Type Message: ")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")        
        message_with_timestamp = f"ID_{client_id} || {message} [{timestamp}]"

        if timestamp in used_timestamps:
            print(f"[{client_id}] Replay Attack Detected, Skipping This Message!")
            continue

        used_timestamps.add(timestamp)

        encrypted_message = encrypt_message(message_with_timestamp, Ks)
        signature = sign_message(message_with_timestamp, client_private_key)
        signature_b64 = base64.b64encode(signature).decode()

        message_to_send = f"{client_id}||{encrypted_message}||{signature_b64}"
        client_socket.sendall(message_to_send.encode())

if __name__ == "__main__":
    client_id = input("Enter Client ID: ")
    start_client(client_id, '127.0.0.1', 8000)
