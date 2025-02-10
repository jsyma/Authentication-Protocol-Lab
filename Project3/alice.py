import socket
import rsa
import os
import hashlib

# Digital Signature Authentication Protocol
# Generate RSA key pair for Alice
alice_public_key, alice_private_key = rsa.newkeys(2048)

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

def alice():
    '''
    Main function for Alice in the protocol.
    '''
    host = "127.0.0.1"
    port = 8000

    nonce_a = generate_nonce()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Sending My (Alice's) Public Key
        print("\nSending Alice's Public Key to Bob")
        s.sendall(alice_public_key.save_pkcs1().decode().encode())

        # Receive Bob's Public Key
        bob_public_key_pem = s.recv(4096).decode()
        bob_public_key = rsa.PublicKey.load_pkcs1(bob_public_key_pem.encode())
        print("Successfully Received Bob's Public Key")

        if is_nonce_replayed(nonce_a):
            print("Replay attack detected! Nonce was already used.")
            return

        # Prepare and Send Message 1 to Bob
        message_1 = f"ID_Alice : {nonce_a}"
        signature_a = sign_message(message_1.encode(), alice_private_key)

        print("\nSending Message 1 and Signature to Bob")
        s.sendall(message_1.encode() + b'||' + signature_a)

        # Receive and Parse Message 2 from Bob
        message_2_with_signature = s.recv(4096)
        print("\nReceived Message 2 with Signature:", message_2_with_signature)
        encrypted_message_2, signature_b = message_2_with_signature.split(b'||')
        print(f"\nBob's Signature for Message 2: {signature_b}")

        # Decrypt the Encrypted Message 2 (nonce_a)
        encrypted_nonce_a, nonce_b = encrypted_message_2.split(b'|:|')
        decrypted_nonce_a = rsa.decrypt(encrypted_nonce_a, alice_private_key).decode().strip()

        if is_nonce_replayed(nonce_b.decode()):
            print("\nReplay attack detected! Nonce was already used.")
            return
        else:
            print("\nNonce is fresh. Proceeding with authentication.")

        # Verify the signature of the message
        if verify_signature(encrypted_message_2, signature_b, bob_public_key):
            print("Bob's Signature Verified Successfully")

            if decrypted_nonce_a == nonce_a:
                print(f"Decrypted Message 2: {decrypted_nonce_a} || {nonce_b.decode()}")
            else:
                print("Verification of Nonce_A failed!")
                return
        else:
            print("Signature Verification Failed!")
            return
        
        # Encrypt and Send Message 3 to Bob
        message_3 = rsa.encrypt(nonce_b, bob_public_key)
        signature_a = sign_message(message_3, alice_private_key)
        print(f"\nSending Message 3 and Signature to Bob: {message_3} || {signature_a}")
        s.sendall(message_3 + b'||' + signature_a)

if __name__ == "__main__":
    alice()
