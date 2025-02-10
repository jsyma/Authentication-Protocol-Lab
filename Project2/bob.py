import socket
import rsa
import os

# Public Key-Based Authentication Protocol
# Generate RSA key pair for Bob
bob_public_key, bob_private_key = rsa.newkeys(2048)

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

            # Receive Alice's Public Key
            alice_public_key_pem = conn.recv(4096).decode()
            alice_public_key = rsa.PublicKey.load_pkcs1(alice_public_key_pem.encode())
            print("\nSuccessfully Received Alice's Public Key")

            # Sending My (Bob's) Public Key
            print("Sending Bob's Public Key to Alice")
            conn.sendall(bob_public_key.save_pkcs1().decode().encode())

            # Receive Message 1 from Alice
            message_1 = conn.recv(1024).decode()
            print("\nReceived Message 1:", message_1)

            identity_a, nonce_a = message_1.split("||")
            print(f"Received identity: {identity_a}||Nonce: {nonce_a}")

            # Construct Message 2 to Alice: encrypted_message || nonce_b
            nonce_b = generate_nonce()
            encrypted_nonce_a = rsa.encrypt(nonce_a.encode(), alice_public_key)
            message_2 = encrypted_nonce_a + b'||' + nonce_b.encode()
            print("\nSending Message 2 to Alice")
            conn.sendall(message_2)

            # Receive and Decrypt Message 3 from Alice
            message_3 = conn.recv(4096)
            print("\nReceived Message 3:", message_3)
            decrypted_message_3 = rsa.decrypt(message_3, bob_private_key).decode()
            print("Decrypted Message 3:", decrypted_message_3)

if __name__ == "__main__":
    bob()
