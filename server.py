import socket
import threading
import signal
import sys
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Configure logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)


class EncryptedServer:
    def __init__(self, host, port, key_file):
        self.host = host
        self.port = port
        self.key, self.iv = self.load_keys(key_file)
        self.clients = []
        self.server_socket = None
        self.shutdown_flag = False
        self.lock = threading.Lock()

    @staticmethod
    def load_keys(file_path):
        try:
            with open(file_path, "rb") as f:
                key = f.read(32)
                iv = f.read(16)
            return key, iv
        except FileNotFoundError:
            logging.error("Encryption keys file not found.")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Failed to load encryption keys: {e}")
            sys.exit(1)

    def signal_handler(self, sig, frame):
        logging.info("Shutdown initiated...")
        self.shutdown_flag = True
        if self.server_socket:
            self.server_socket.close()
        with self.lock:
            for client in self.clients:
                client.close()
        sys.exit(0)

    def decrypt_message(self, encrypted_message):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        decrypted_padded_message = (
            decryptor.update(encrypted_message) + decryptor.finalize()
        )
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = (
            unpadder.update(decrypted_padded_message) + unpadder.finalize()
        )
        return decrypted_message.decode()

    def broadcast_message(self, message, sending_socket):
        with self.lock:
            for client in self.clients.copy():
                if client != sending_socket:
                    try:
                        client.send(message)
                    except socket.error:
                        self.clients.remove(client)

    def handle_client_encrypted(self, client_socket, addr):
        while not self.shutdown_flag:
            try:
                encrypted_message = client_socket.recv(1024)
                if not encrypted_message or self.shutdown_flag:
                    break
                message = self.decrypt_message(encrypted_message)
                logging.info(f"Received Encrypted message from {addr}: {message}")
                self.broadcast_message(encrypted_message, client_socket)
            except socket.error:
                break

        with self.lock:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            logging.info(f"Client {addr} disconnected")
        client_socket.close()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1)
        self.clients = []
        logging.info(f"Server Encrypted listening on {self.host}:{self.port}")

        while not self.shutdown_flag:
            try:
                client_socket, addr = self.server_socket.accept()
                logging.info(f"Accepted connection from {addr}")
                with self.lock:
                    self.clients.append(client_socket)
                threading.Thread(
                    target=self.handle_client_encrypted, args=(client_socket, addr)
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.shutdown_flag:
                    break
                logging.error(f"Unhandled exception: {e}")

    def run(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        self.start_server()


if __name__ == "__main__":
    server = EncryptedServer("0.0.0.0", 9999, "encryption_keys.bin")
    server.run()
