import socket
import rsa
import os
import hashlib

# Digital Signature Authentication Protocol
# Generate RSA key pair for Bob
bob_public_key, bob_private_key = rsa.newkeys(2048)

# Store used nonces to prevent replay attacks
used_nonces = set()

def generate_nonce():
    '''
    Generates a random nonce for use in the authentication protocol.
    
    Returns:
        str: The generated nonce in hexadecimal format (8-byte, 16 hex characters).
    '''
    return os.urandom(8).hex()

def sign_message(message, private_key):
    '''
    Signs a message using the provided RSA private key.

    Args:
        message (bytes): The message to be signed.
        private_key (rsa.PrivateKey): The RSA private key used for signing.

    Returns:
        bytes: The generated signature for the message.
    '''
    message_hash = hashlib.sha256(message).digest()
    signature = rsa.sign(message_hash, private_key, 'SHA-256')
    return signature

def verify_signature(message, signature, public_key):
    '''
    Verifies the authenticity of a signed message using the RSA public key.

    Args:
        message (bytes): The original message that was signed.
        signature (bytes): The signature to be verified.
        public_key (rsa.PublicKey): The RSA public key corresponding to the private key used for signing.

    Returns:
        bool: True if the signature is valid, False otherwise.
    '''
    message_hash = hashlib.sha256(message).digest()
    try: 
        rsa.verify(message_hash, signature, public_key)
        return True
    except rsa.VerificationError:
        return False

def is_nonce_replayed(nonce):
    '''
    Checks if a nonce has been used before to prevent replay attacks.

    Args:
        nonce (str): The nonce to be checked.

    Returns:
        bool: True if the nonce has been used before (indicating a replay attack), False otherwise.
    '''
    if nonce in used_nonces:
        return True  # Replay attack detected
    used_nonces.add(nonce)
    return False

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

            # Receive Alice's Public Key
            alice_public_key_pem = conn.recv(4096).decode()
            alice_public_key = rsa.PublicKey.load_pkcs1(alice_public_key_pem.encode())
            print("\nSuccessfully Received Alice's Public Key")

            # Sending My (Bob's) Public Key
            print("Sending Bob's Public Key to Alice")
            conn.sendall(bob_public_key.save_pkcs1().decode().encode())

            # Receive Message 1 from Alice
            message_1_with_signature = conn.recv(4096)
            print("\nReceived Message 1 with Signature:", message_1_with_signature)
            message_1, signature_a = message_1_with_signature.split(b'||')
            print(f"\nAlice's Signature for Message 1: {signature_a}")
            print("\nReceived Message 1:", message_1.decode())

            # Parse the message
            identity_a, nonce_a = message_1.decode().split(":")
            print(f"Received identity: {identity_a}|| Nonce:{nonce_a}")

            if is_nonce_replayed(nonce_a):
                print("Replay attack detected! Nonce was already used.")
                return
            else:
                print("Nonce is fresh. Proceeding with authentication.")

            # Verify Alice's Signature
            if verify_signature(message_1, signature_a, alice_public_key):
                print("Alice's Signature Verified Successfully!")
            else:
                print("Signature Verification Failed!")
                return

            # Construct Message 2 to Alice: encrypted_message || nonce_b
            nonce_b = generate_nonce()
            encrypted_nonce_a = rsa.encrypt(nonce_a.encode(), alice_public_key)
            message_2 = encrypted_nonce_a + b'|:|' + nonce_b.encode()
            signature_b = sign_message(message_2, bob_private_key)
            print(f"\nSending Message 2 and Signature to Alice: {message_2} || {signature_b}")
            conn.sendall(message_2 + b'||' + signature_b)

            # Receive and Decrypt Message 3 from Alice
            message_3_with_signature = conn.recv(4096)
            print("\nReceived Message 3 with Signature:", message_3_with_signature)
            message_3, signature_a = message_3_with_signature.split(b'||')
            decrypted_message_3 = rsa.decrypt(message_3, bob_private_key).decode().strip()
            print(f"\nAlice's Signature for Message 3: {signature_a}")

            if is_nonce_replayed(decrypted_message_3):
                print("\nReplay attack detected! Nonce was already used.")
                return
            else:
                print("\nNonce is fresh. Proceeding with authentication.")
            
            # Verify the signature of the message
            if verify_signature(message_3, signature_a, alice_public_key):
                print("Alice's Signature Verified Successfully")

                if decrypted_message_3 == nonce_b:
                    print(f"Decrypted Message 3: {decrypted_message_3}")
                else:
                    print("Verification of Nonce_B failed!")
                    return  
            else:
                print("Signature Verification Failed!")
                return 

if __name__ == "__main__":
    bob()
