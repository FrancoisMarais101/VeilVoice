import socket
import threading
import signal
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Load the encryption keys from file
with open("encryption_keys.bin", "rb") as f:
    key = f.read(32)
    iv = f.read(16)

# Server configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9999
clients = []
server_socket = None
shutdown_flag = False


# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    global shutdown_flag
    print("\n[Server] Shutdown initiated...")
    shutdown_flag = True
    if server_socket:
        server_socket.close()
    for client in clients:
        client.close()
    sys.exit(0)


# Register the signal handler for SIGINT (Ctrl + C)
signal.signal(signal.SIGINT, signal_handler)


# Decrypt a message with AES
def decrypt_message(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_message = (
        decryptor.update(encrypted_message) + decryptor.finalize()
    )
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()


# Broadcast a message to all clients except the sender
def broadcast_message(message, sending_socket):
    for client in clients:
        if client != sending_socket:
            try:
                client.send(message)
            except:
                clients.remove(client)


# Handle each client connection
def handle_client_encrypted(client_socket):
    while not shutdown_flag:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message or shutdown_flag:
                break
            message = decrypt_message(encrypted_message, key, iv)
            print(f"[Received Encrypted]: {message}")

            # Broadcast to other clients
            broadcast_message(encrypted_message, client_socket)
        except:
            clients.remove(client_socket)
            break

    client_socket.close()


# Start the server
def start_server_encrypted():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    server_socket.settimeout(1)
    print(f"[Server Encrypted] Listening on {SERVER_HOST}:{SERVER_PORT}")
    while not shutdown_flag:
        try:
            client_socket, addr = server_socket.accept()
            print(f"[Connection] Accepted from {addr}")
            clients.append(client_socket)
            client_handler = threading.Thread(
                target=handle_client_encrypted, args=(client_socket,)
            )
            client_handler.start()
        except socket.timeout:
            continue
        except:
            if shutdown_flag:
                break


if __name__ == "__main__":
    start_server_encrypted()
