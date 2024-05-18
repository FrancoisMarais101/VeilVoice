import socket
import threading
import signal
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Load the encryption keys from file
def load_keys(file_path):
    try:
        with open(file_path, "rb") as f:
            key = f.read(32)
            iv = f.read(16)
        return key, iv
    except FileNotFoundError:
        print("[Server] Encryption keys file not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[Server] Failed to load encryption keys: {e}")
        sys.exit(1)


key, iv = load_keys("encryption_keys.bin")

# Server configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 9999
clients = []
server_socket = None
shutdown_flag = False
lock = threading.Lock()


def signal_handler(sig, frame):
    global shutdown_flag, server_socket, clients
    print("\n[Server] Shutdown initiated...")
    shutdown_flag = True
    if server_socket:
        server_socket.close()
    with lock:
        for client in clients:
            client.close()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def decrypt_message(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_message = (
        decryptor.update(encrypted_message) + decryptor.finalize()
    )
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()


def broadcast_message(message, sending_socket):
    with lock:
        for client in clients.copy():
            if client != sending_socket:
                try:
                    client.send(message)
                except socket.error:
                    clients.remove(client)


def handle_client_encrypted(client_socket, addr):
    while not shutdown_flag:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message or shutdown_flag:
                break
            message = decrypt_message(encrypted_message, key, iv)
            print(f"[Received Encrypted] From {addr}: {message}")
            broadcast_message(encrypted_message, client_socket)
        except socket.error:
            break

    with lock:
        if client_socket in clients:
            clients.remove(client_socket)
        print(f"[Disconnection] Client {addr} disconnected")
    client_socket.close()


def start_server_encrypted():
    global server_socket, clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    server_socket.settimeout(1)
    clients = []
    print(f"[Server Encrypted] Listening on {SERVER_HOST}:{SERVER_PORT}")
    while not shutdown_flag:
        try:
            client_socket, addr = server_socket.accept()
            print(f"[Connection] Accepted from {addr}")
            with lock:
                clients.append(client_socket)
            threading.Thread(
                target=handle_client_encrypted, args=(client_socket, addr)
            ).start()
        except socket.timeout:
            continue
        except Exception as e:
            if shutdown_flag:
                break
            print(f"[Server] Unhandled exception: {e}")


if __name__ == "__main__":
    start_server_encrypted()
