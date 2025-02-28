import socket
import rsa
import os

# Generate RSA key pair for Alice
alice_public_key, alice_private_key = rsa.newkeys(2048)

def generate_nonce():
    return os.urandom(8).hex()

def send_request():
    host, port = "127.0.0.1", 8000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        ''' 
        Phase 1 
        '''
        print("\nSending Alice's ID and Public Key to KDC")
        alice_id = "Alice"
        public_key_pem = alice_public_key.save_pkcs1().decode()
        initial_message = f"{alice_id}||{public_key_pem}"
        s.sendall(initial_message.encode())

        # Receive KDC's Public Key
        kdc_public_key_pem = s.recv(4096).decode()
        kdc_public_key = rsa.PublicKey.load_pkcs1(kdc_public_key_pem.encode())
        print("Successfully Received KDC's Public Key")

        # Receive Encrypted Message 1 from KDC
        encrypted_message_1 = s.recv(4096)
        print(f"\nReceived Encrypted Message 1: {encrypted_message_1}")
        decrypted_message_1 = rsa.decrypt(encrypted_message_1, alice_private_key).decode()
        print(f"Decrypted Message 1: {decrypted_message_1}")
        nonce_k1, id_kdc = decrypted_message_1.split("||")
        print(f"Alice received nonce: {nonce_k1} and ID {id_kdc}")
    
        # Prepare and Send Message 2 to KDC 
        nonce_a = generate_nonce()
        message_2 = f"{nonce_a}||{nonce_k1}"
        print(f"\nSending Message 2 to KDC: {message_2}")
        encrypted_message_2 = rsa.encrypt(message_2.encode(), kdc_public_key)
        s.sendall(encrypted_message_2)

        # Receive Message 3 confirming Nonce_K1 
        encrypted_message_3 = s.recv(4096)
        print(f"\nReceived Encrypted Message 3: {encrypted_message_3}")
        received_nonce_k1 = rsa.decrypt(encrypted_message_3, alice_private_key).decode()
        print(f"Decrypted Message 3: {received_nonce_k1}")

        if received_nonce_k1 != nonce_k1:
            print("Nonce Mismatch!")
            return

        print("Nonce_K1 Verified - Communication is Fresh")

        # Receive Message 4 (Master Key) and Decrypt Message to get K_A
        encrypted_message_4 = s.recv(4096)
        print(f"\nReceived Message 4 (Master Key): {encrypted_message_4.hex()}")
        decrypted_message_4 = rsa.decrypt(encrypted_message_4, alice_private_key)
        print(f'Decrypted Master Key K_A: {decrypted_message_4}')
        '''
        Phase 2
        '''
        # Send Alice and Bob's ID to KDC
        s.sendall("Alice||Bob".encode())
        print("\nSent ID_A and ID_B to KDC")

        # Receive Encrypted Session Key K_AB
        encrypted_session_key = s.recv(4096)
        decrypted_session_key = rsa.decrypt(encrypted_session_key, alice_private_key).decode()
        K_AB, id_b = decrypted_session_key.split("||")
        print(f"\nAlice received the shared session key (K_AB): {K_AB} for communication with {id_b}")

if __name__ == "__main__":
    try:
        send_request()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")