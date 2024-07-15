import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Function to derive a key from the user's passphrase
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# Function to encrypt the File Encryption Key (FEK) with the derived key
def encrypt_fek(fek, derived_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(fek) + encryptor.finalize()
    return base64.b64encode(iv + encryptor.tag + ciphertext)

# Function to decrypt the File Encryption Key (FEK) with the derived key
def decrypt_fek(encrypted_fek, derived_key):
    encrypted_fek = base64.b64decode(encrypted_fek)
    iv = encrypted_fek[:16]
    tag = encrypted_fek[16:32]
    ciphertext = encrypted_fek[32:]
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to encrypt a file with the File Encryption Key (FEK)
def encrypt_file(file_path, fek):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(fek), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(base64.b64encode(iv + encryptor.tag + ciphertext))

# Function to decrypt a file with the File Encryption Key (FEK)
def decrypt_file(file_path, fek):
    with open(file_path, 'rb') as file:
        encrypted_data = base64.b64decode(file.read())

    iv = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    cipher = Cipher(algorithms.AES(fek), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = file_path[:-10] + '.decrypted'  # Change extension to .decrypted
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)

# Tkinter GUI
class FileEncryptorDecryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor/Decryptor")

        # Maximize window
        self.root.state('zoomed')

        self.filepath = ''
        self.salt = os.urandom(16)
        self.fek = os.urandom(32)

        self.create_widgets()

    def create_widgets(self):
        self.file_label = tk.Label(self.root, text="No file selected")
        self.file_label.pack(pady=10)

        self.select_button = tk.Button(self.root, text="Select File", command=self.select_file)
        self.select_button.pack(pady=5)

        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.file_label.config(text=self.filepath)

    def encrypt(self):
        if not self.filepath:
            messagebox.showwarning("Warning", "Please select a file first")
            return

        passphrase = simpledialog.askstring("Input", "Enter a passphrase:", show='*')
        if not passphrase:
            return

        derived_key = derive_key(passphrase, self.salt)
        encrypted_fek = encrypt_fek(self.fek, derived_key)

        with open('encrypted_fek.bin', 'wb') as file:
            file.write(encrypted_fek)

        encrypt_file(self.filepath, self.fek)
        messagebox.showinfo("Success", f"File encrypted and saved as {self.filepath}.encrypted")

    def decrypt(self):
        if not self.filepath:
            messagebox.showwarning("Warning", "Please select a file first")
            return

        passphrase = simpledialog.askstring("Input", "Enter the passphrase to decrypt the file:", show='*')
        if not passphrase:
            return

        derived_key = derive_key(passphrase, self.salt)

        with open('encrypted_fek.bin', 'rb') as file:
            encrypted_fek = file.read()

        try:
            self.fek = decrypt_fek(encrypted_fek, derived_key)
            decrypt_file(self.filepath, self.fek)
            messagebox.showinfo("Success", f"File decrypted and saved as {self.filepath[:-10]}.decrypted")
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt the file. Check the passphrase and try again.")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorDecryptorApp(root)
    root.mainloop()
