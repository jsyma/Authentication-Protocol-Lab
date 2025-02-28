import socket
import rsa
import os
import threading
import time 

# Generate RSA key pair for KDC
kdc_public_key, kdc_private_key = rsa.newkeys(2048)

# Store nonces for verification
nonces = {}

# Master keys for Alice and Bob
K_A = os.urandom(16)
K_B = os.urandom(16)

# Session Key for Alice and Bob
K_AB = os.urandom(16)

def generate_nonce():
    return os.urandom(8).hex()

def handle_client(client_socket):
    '''
    Phase 1
    '''
    # Receive client's (Alice or Bob) identity and public key
    phase_1_data = client_socket.recv(4096).decode()
    client_id, client_public_key_pem = phase_1_data.split("||")
    client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_pem.encode())
    print(f"\nKDC Received Public Key from ID: {client_id}")

    # Send KDC Public Key to Client 
    print("Sending KDC's Public Key to Client")
    client_socket.sendall(kdc_public_key.save_pkcs1().decode().encode())

    # Generate Nonce and Send Message 1 to Client
    if client_id not in ["Alice", "Bob"]:
        print(f"Unknown Client ID: {client_id}")
        client_socket.close()
        return

    nonce_k = generate_nonce()
    nonces[client_id] = nonce_k
    message_1 = f"{nonce_k}||KDC".encode()
    
    print(f"\nSending Message 1 to Client: {message_1}")
    encrypted_message_1 = rsa.encrypt(message_1, client_public_key)
    client_socket.sendall(encrypted_message_1)

    # Receive Message 2 from Client 
    encrypted_message_2 = client_socket.recv(4096)
    print(f"\nReceived Encrypted Message 2: {encrypted_message_2}")
    decrypted_message_2 = rsa.decrypt(encrypted_message_2, kdc_private_key).decode()
    nonce_client, received_nonce_k = decrypted_message_2.split("||")
    print(f"Decrypted Message 2: Nonce Client: {nonce_client} || Nonce K: {received_nonce_k}")

    if received_nonce_k != nonces[client_id]:
        print("Nonce Mismatch, Possible Replay Attack")
        client_socket.close()
        return

    # Send Message 3 to Client for Nonce Confirmation
    print(f"\nSending Message 3 (nonce confirmation) to Client")
    encrypted_message_3 = rsa.encrypt(nonces[client_id].encode(), client_public_key)
    client_socket.sendall(encrypted_message_3)

    # Prepare and Send Message 4 to Client (Master Key)
    if client_id == "Alice":
        encrypted_message_4 = rsa.encrypt(K_A, client_public_key)
    elif client_id == "Bob":
        encrypted_message_4 = rsa.encrypt(K_B, client_public_key)
    print("\nSending Message 4 with Master Key to Client")
    client_socket.sendall(encrypted_message_4)

    '''
    Phase 2
    '''
    time.sleep(5)
    
    # Prepare and Send Session Key Message to Client
    session_key = prepare_session_key_message(client_id, client_socket, client_public_key)
    print(f"\nSending Session Key Message to {client_id}")
    client_socket.sendall(session_key)

def prepare_session_key_message(client_id, client_socket, client_public_key):
    if client_id == "Alice":
        phase_2_data = client_socket.recv(4096).decode()
        id_a, id_b = phase_2_data.split("||")
        print(f"\nReceived IDs: {id_a} and {id_b}")
        session_key_message = f"{K_AB}||{id_b}"
        encrypted_session_key_message = rsa.encrypt(session_key_message.encode(), client_public_key)
    else:
        session_key_message = f"{K_AB}||Alice"
        encrypted_session_key_message = rsa.encrypt(session_key_message.encode(), client_public_key)

    return encrypted_session_key_message

def start_kdc():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8000))
    server.listen(2)
    print("KDC is running...")
    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_kdc()