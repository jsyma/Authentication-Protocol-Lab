import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA Key Pair
kdc_private_key = RSA.generate(2048)
kdc_public_key = kdc_private_key.publickey()

# Group Key
Ks = os.urandom(16)

# Client Directory
clients = {}

def handle_client(client_socket):
    '''
    Handles the registration and communication with the client, and relays incoming messages to other clients. 

    Args: 
        client_socket (socket.socket): The socket object representing the client connection.
    '''
    try:
        # Receive Client ID
        client_id = client_socket.recv(1024).decode()

        # Receive Client Public Key
        client_public_key_pem = client_socket.recv(4096)
        client_public_key = RSA.import_key(client_public_key_pem)

        # Register Client
        clients[client_id] = (client_public_key, client_socket)
        print(f"[KDC] Client {client_id} Registered")

        # Send KDC's Public Key To Client
        client_socket.sendall(kdc_public_key.export_key())

        # Create and Send Group Key (Ks)
        rsa_cipher = PKCS1_OAEP.new(client_public_key)
        encrypted_ks = rsa_cipher.encrypt(Ks)
        client_socket.sendall(encrypted_ks)

        # Handle and Relay Incoming Messages
        while True:
            message = client_socket.recv(4096).decode()

            if message.startswith("REQUEST_PUBKEY"):
                _, requested_id = message.split("||")
                if requested_id in clients:
                    requested_pubkey = clients[requested_id][0].export_key()
                    client_socket.sendall(requested_pubkey)
            else:
                sender_id, _, _ = message.split("||")
                print(f"[KDC] Relaying Message From {sender_id} to Other Clients")
                for other_client_id, (_, other_client_socket) in clients.items():
                    if other_client_id != sender_id:
                        other_client_socket.sendall(message.encode())

    except Exception as e:
        print(f"[KDC] Error With Client: {e}")
    finally:
        print(f"[KDC] Client {client_id} Disconnected")
        clients.pop(client_id, None)
        client_socket.close()

def start_kdc():
    '''
    Starts the KDC server to listen and handle incoming client connections.
    '''
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8000))
    server.listen(5)
    print("[KDC] Server is Listening for Connections...")

    while True:
        client_socket, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_kdc()
