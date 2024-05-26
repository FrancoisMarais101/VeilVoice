import socket
import threading
import tkinter as tk
from tkinter import messagebox
from pystray import Icon, MenuItem, Menu
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import ctypes
from dotenv import load_dotenv
import time


class SecureChatClient:
    def __init__(self, root, icon_path):
        self.root = root
        self.icon_path = icon_path
        self.key, self.iv = self.load_keys("encryption_keys.bin")
        load_dotenv()
        self.server_ip = os.environ.get("SERVER_IP")
        self.server_port = int(os.environ.get("SERVER_PORT"))
        self.client_socket = None
        self.original_title = "Secure Etienne Intercom System"
        self.flash_count = 0
        self.flashing = False
        self.reconnect_interval = 5  # Interval between reconnection attempts in seconds

        self.setup_ui()
        self.set_taskbar_icon()
        self.start_client()
        self.update_taskbar_icon()

    def load_keys(self, file_path):
        try:
            with open(file_path, "rb") as f:
                key = f.read(32)
                iv = f.read(16)
            return key, iv
        except FileNotFoundError:
            messagebox.showerror("Error", "Encryption keys file not found.")
            exit()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load encryption keys: {e}")
            exit()

    def encrypt_message(self, message):
        try:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_message = padder.update(message.encode()) + padder.finalize()
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
            return encrypted_message
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_message):
        try:
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
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    def flash_title(self):
        if self.flash_count > 5:
            self.root.title(self.original_title)
            self.flashing = False
            return
        current_title = self.root.title()
        new_title = (
            "New Message!"
            if current_title == self.original_title
            else self.original_title
        )
        self.root.title(new_title)
        self.flash_count += 1
        self.root.after(500, self.flash_title)

    def handle_received_message(self, message):
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, message + "\n")
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)
        self.bring_window_to_foreground()
        if not self.flashing:
            self.flashing = True
            self.flash_count = 0
            self.flash_title()

    def bring_window_to_foreground(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        if os.name == "nt":
            self.set_foreground_window()

    def set_foreground_window(self):
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        ctypes.windll.user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0001 | 0x0002)
        ctypes.windll.user32.SetWindowPos(hwnd, -2, 0, 0, 0, 0, 0x0001 | 0x0002)

    def send_disconnection_reason(self, reason):
        if self.client_socket:
            try:
                encrypted_message = self.encrypt_message(reason)
                if encrypted_message:
                    self.client_socket.send(encrypted_message)
            except Exception as e:
                print(f"Failed to send disconnection reason: {e}")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    self.send_disconnection_reason(
                        "Client disconnected: No message received."
                    )
                    break
                message = self.decrypt_message(encrypted_message)
                if message:
                    self.root.after(0, self.handle_received_message, message)
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.send_disconnection_reason(f"Client disconnected: {e}")
                break
        self.reconnect()

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            encrypted_message = self.encrypt_message(message)
            if encrypted_message:
                try:
                    self.client_socket.send(encrypted_message)
                    self.chat_box.config(state=tk.NORMAL)
                    self.chat_box.insert(tk.END, "Sent: " + message + "\n")
                    self.chat_box.config(state=tk.DISABLED)
                    self.chat_box.see(tk.END)
                    self.message_entry.delete(0, tk.END)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to send message: {e}")

    def start_client(self):
        while True:
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.server_ip, self.server_port))
                receive_thread = threading.Thread(
                    target=self.receive_messages, daemon=True
                )
                receive_thread.start()
                break
            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect to server: {e}")
                time.sleep(self.reconnect_interval)

    def reconnect(self):
        self.client_socket.close()
        while True:
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.server_ip, self.server_port))
                receive_thread = threading.Thread(
                    target=self.receive_messages, daemon=True
                )
                receive_thread.start()
                break
            except Exception as e:
                time.sleep(self.reconnect_interval)

    def show_window(self, icon, item):
        icon.stop()
        self.root.deiconify()
        self.set_taskbar_icon()

    def confirm_quit(self):
        response = messagebox.askyesno(
            "Wat maak jy Bro??",
            "Moenie nou quit nie, ek sien wat jy doen. Jy gaan spyt wees. Wil jy regtig quit?",
        )
        if response:
            self.send_disconnection_reason(
                "Client disconnected: User quit the application."
            )
            self.root.quit()

    def quit_app(self, icon=None, item=None):
        self.confirm_quit()

    def minimize_to_tray(self):
        self.root.withdraw()
        try:
            icon_image = Image.open(self.icon_path)
            menu = Menu(
                MenuItem("Restore", self.show_window), MenuItem("Quit", self.quit_app)
            )
            icon = Icon("Chat Client", icon_image, "Chat Client", menu)
            icon.run()
        except Exception as e:
            print(f"Error creating tray icon: {e}")

    def set_taskbar_icon(self):
        try:
            self.root.iconbitmap(self.icon_path)
        except Exception as e:
            print(f"Error setting taskbar icon: {e}")
        if os.name == "nt":
            try:
                myappid = "mycompany.myproduct.subproduct.version"
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
                self.root.iconbitmap(self.icon_path)
            except Exception as e:
                print(f"Error setting taskbar icon with ctypes: {e}")

    def setup_ui(self):
        self.root.title(self.original_title)
        self.chat_box = tk.Text(self.root, state=tk.DISABLED, width=50, height=15)
        self.chat_box.pack(pady=10)

        self.message_entry = tk.Entry(self.root, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=(10, 0))

        send_button = tk.Button(self.root, text="Send", command=self.send_message)
        send_button.pack(side=tk.LEFT, padx=10)

        self.message_entry.bind("<Return>", self.send_message)
        self.root.protocol("WM_DELETE_WINDOW", self.confirm_quit)
        self.root.bind("<Escape>", lambda event: self.confirm_quit())

    def update_taskbar_icon(self):
        self.root.withdraw()
        self.root.after(100, lambda: self.root.deiconify())


if __name__ == "__main__":
    root = tk.Tk()
    icon_path = "veil_voice_ckf_icon.ico"
    app = SecureChatClient(root, icon_path)
    root.mainloop()
