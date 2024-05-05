import socket
import threading
import tkinter as tk
from tkinter import messagebox
from pystray import Icon, MenuItem, Menu
from PIL import Image, ImageDraw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Load encryption keys (ensure this matches the server)
with open("encryption_keys.bin", "rb") as f:
    key = f.read(32)
    iv = f.read(16)

# Server configuration
SERVER_IP = "127.0.0.1"  # Update with the correct IP address
SERVER_PORT = 9999
client_socket = None


# Encryption functions
def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return encrypted_message


def decrypt_message(encrypted_message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_message = (
        decryptor.update(encrypted_message) + decryptor.finalize()
    )
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return decrypted_message.decode()


# Function to flash the window title to indicate new messages
def flash_title():
    global flash_count, flashing
    if flash_count > 5:
        root.title(original_title)
        flashing = False
        return

    current_title = root.title()
    new_title = "New Message!" if current_title == original_title else original_title
    root.title(new_title)

    flash_count += 1
    root.after(500, flash_title)


# Function to receive messages and indicate new messages
def receive_messages():
    global flash_count, flashing
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            message = decrypt_message(encrypted_message, key, iv)
            chat_box.config(state=tk.NORMAL)
            chat_box.insert(tk.END, "Received: " + message + "\n")
            chat_box.config(state=tk.DISABLED)
            chat_box.see(tk.END)

            # Bring the window to the front and focus on it
            root.deiconify()
            root.lift()
            root.focus_force()

            # Flash the window title
            if not flashing:
                flashing = True
                flash_count = 0
                flash_title()

        except Exception as e:
            print(f"Error receiving message: {e}")
            break


# Function to send messages
def send_message():
    message = message_entry.get()
    if message:
        encrypted_message = encrypt_message(message, key, iv)
        client_socket.send(encrypted_message)
        chat_box.config(state=tk.NORMAL)
        chat_box.insert(tk.END, "Sent: " + message + "\n")
        chat_box.config(state=tk.DISABLED)
        chat_box.see(tk.END)
        message_entry.delete(0, tk.END)


# Function to start the client and receive messages
def start_client():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    receive_thread = threading.Thread(target=receive_messages, daemon=True)
    receive_thread.start()


# Function to show the application window from the system tray
def show_window(icon, item):
    icon.stop()
    root.deiconify()


# Function to quit the application
def quit_app(icon, item):
    icon.stop()  # Stop the tray icon
    root.quit()  # Exit the Tkinter main loop


# Function to minimize the application to the system tray
def minimize_to_tray():
    root.withdraw()  # Hide the Tkinter window

    # Create a simple icon for the system tray
    width = 16
    height = 16
    image = Image.new("RGB", (width, height), "blue")
    draw = ImageDraw.Draw(image)
    draw.rectangle([1, 1, width - 2, height - 2], fill="yellow")

    # Create system tray icon menu with Show and Quit options
    menu = Menu(MenuItem("Show", show_window), MenuItem("Quit", quit_app))
    icon = Icon("Chat Client", image, "Chat Client", menu)
    icon.run()


# Tkinter GUI setup
root = tk.Tk()
root.title("Secure Etienne Intercom")

# Global variables for the original window title and flashing state
original_title = "Secure Etienne Intercom"
flash_count = 0
flashing = False

chat_box = tk.Text(root, state=tk.DISABLED, width=50, height=15)
chat_box.pack(pady=10)

message_entry = tk.Entry(root, width=40)
message_entry.pack(side=tk.LEFT, padx=(10, 0))

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.LEFT, padx=10)

# Bind the minimize function to the close button
root.protocol("WM_DELETE_WINDOW", minimize_to_tray)

# Start the client connection
start_client()
root.mainloop()
