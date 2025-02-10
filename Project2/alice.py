import socket
import rsa
import os

# Public Key-Based Authentication Protocol
# Generate RSA key pair for Alice
alice_public_key, alice_private_key = rsa.newkeys(2048)

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

        # Prepare and Send Message 1 to Bob
        message_1 = f"ID_Alice||{nonce_a}"
        print("\nSending Message 1:", message_1)
        s.sendall(message_1.encode())

        # Receive and Parse Message 2 from Bob
        message_2 = s.recv(4096)
        encrypted_message, nonce_b = message_2.split(b'||')
        print(f"\nReceived Encrypted Message 2: {message_2}||Nonce = {nonce_b}")

        # Verify and Decrypt the Encrypted Message 2
        decrypted_message = rsa.decrypt(encrypted_message, alice_private_key).decode()
        if decrypted_message == nonce_a:
            print("Verified Nonce_A successfully")
            print("Decrypted Message 2:", decrypted_message)
        else:
            print("Verification of Nonce_A failed!")
            return

        # Encrypt and Send Message 3 to Bob
        encrypted_message_3 = rsa.encrypt(nonce_b, bob_public_key)
        print("\nSending Message 3:", encrypted_message_3)
        s.sendall(encrypted_message_3)

if __name__ == "__main__":
    alice()
