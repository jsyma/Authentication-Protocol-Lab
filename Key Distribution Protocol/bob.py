import socket
import rsa
import os

# Generate RSA key pair for Bob
bob_public_key, bob_private_key = rsa.newkeys(2048)

def generate_nonce():
    return os.urandom(8).hex()

def send_request():
    host, port = "127.0.0.1", 8000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        '''
        Phase 1
        '''
        print("\nSending Bob's ID and Public Key to KDC")
        bob_id = "Bob"
        public_key_pem = bob_public_key.save_pkcs1().decode()
        initial_message = f"{bob_id}||{public_key_pem}"
        s.sendall(initial_message.encode())

        # Receive KDC's Public Key
        kdc_public_key_pem = s.recv(4096).decode()
        kdc_public_key = rsa.PublicKey.load_pkcs1(kdc_public_key_pem.encode())
        print("Successfully Received KDC's Public Key")

        # Receive Encrypted Message 1 from KDC
        encrypted_message_1 = s.recv(4096)
        print(f"\nReceived Encrypted Message 1: {encrypted_message_1}")
        decrypted_message_1 = rsa.decrypt(encrypted_message_1, bob_private_key).decode()
        print(f"Decrypted Message 1: {decrypted_message_1}")
        nonce_k2, id_kdc = decrypted_message_1.split("||")
        print(f"Bob received nonce: {nonce_k2} and ID {id_kdc}")

        # Prepare and Send Message 2 to KDC 
        nonce_b = generate_nonce()
        message_2 = f"{nonce_b}||{nonce_k2}"
        print(f"\nSending Message 2 to KDC: {message_2}")
        encrypted_message_2 = rsa.encrypt(message_2.encode(), kdc_public_key)
        s.sendall(encrypted_message_2)

        # Receive Message 3 confirming Nonce_K2 
        encrypted_message_3 = s.recv(4096)
        print(f"\nReceived Encrypted Message 3: {encrypted_message_3}")
        received_nonce_k2 = rsa.decrypt(encrypted_message_3, bob_private_key).decode()
        print(f"Decrypted Message 3: {received_nonce_k2}")

        if received_nonce_k2 != nonce_k2:
            print("Nonce Mismatch!")
            return

        print("Nonce_K2 Verified - Communication is Fresh")

        # Receive Message 4 (Master Key) and Decrypt Message to get K_B
        encrypted_message_4 = s.recv(4096)
        print(f"\nReceived Message 4 (Master Key): {encrypted_message_4.hex()}")
        decrypted_message_4 = rsa.decrypt(encrypted_message_4, bob_private_key)
        print(f'Decrypted Master Key K_B: {decrypted_message_4}')
        '''
        Phase 2
        '''
        # Receive Encrypted Session Key K_AB
        encrypted_session_key = s.recv(4096)
        decrypted_session_key = rsa.decrypt(encrypted_session_key, bob_private_key).decode()
        K_AB, id_a = decrypted_session_key.split("||")
        print(f"\nBob received the shared session key (K_AB): {K_AB} for communication with {id_a}")

if __name__ == "__main__":
    try:
        send_request()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")