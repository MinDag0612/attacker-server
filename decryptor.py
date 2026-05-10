from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import tkinter as tk
from tkinter import filedialog, messagebox


# =========================
# DECRYPT FUNCTIONS
# =========================

def _aes_decrypt(ct, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def _rsa_decrypt(data, priv):
    print("[INFO - execute] Decrypting data with RSA")
    return PKCS1_OAEP.new(priv).decrypt(data)


def decrypt_file(path, private_key):
    with open(path, "rb") as f:

        kl = int.from_bytes(f.read(4), "big")
        enc_key = f.read(kl)

        nl = int.from_bytes(f.read(4), "big")
        nonce = f.read(nl)

        tl = int.from_bytes(f.read(4), "big")
        tag = f.read(tl)

        cl = int.from_bytes(f.read(4), "big")
        ct = f.read(cl)

    aes_key = _rsa_decrypt(enc_key, private_key)

    data = _aes_decrypt(ct, aes_key, nonce, tag)

    out = path.replace(".locked", "")

    with open(out, "wb") as f:
        f.write(data)

    return out


def decrypt_sandbox(folder, private_key):
    results = []

    for f in os.listdir(folder):

        if f.endswith(".locked"):

            path = os.path.join(folder, f)

            decrypted_path = decrypt_file(path, private_key)

            results.append(decrypted_path)

    return results


# =========================
# TKINTER FUNCTIONS
# =========================

def browse_key():
    path = filedialog.askopenfilename(
        title="Select Private Key",
        filetypes=[("PEM Files", "*.pem")]
    )

    if path:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, path)


def browse_folder():
    path = filedialog.askdirectory(
        title="Select Folder Containing .locked Files"
    )

    if path:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, path)


def start_decrypt():

    key_path = key_entry.get().strip()
    folder_path = folder_entry.get().strip()

    if not key_path or not folder_path:
        messagebox.showerror(
            "Error",
            "Please select private key and folder"
        )
        return

    try:

        with open(key_path, "rb") as f:
            private_key = RSA.import_key(f.read())

        decrypted_files = decrypt_sandbox(
            folder_path,
            private_key
        )

        status_var.set(
            f"Decrypt success ({len(decrypted_files)} files)"
        )

        messagebox.showinfo(
            "Success",
            f"Decrypted {len(decrypted_files)} files successfully"
        )

        print("[INFO - execute] Decryption completed")
        print("\n".join(decrypted_files))

    except Exception as e:

        status_var.set("Decrypt failed")

        messagebox.showerror(
            "Error",
            str(e)
        )


# =========================
# GUI
# =========================

root = tk.Tk()

root.title("File Decryptor")
root.geometry("650x280")
root.resizable(False, False)


# =========================
# PRIVATE KEY
# =========================

tk.Label(
    root,
    text="Private Key (.pem)"
).pack(pady=(15, 5))

key_frame = tk.Frame(root)
key_frame.pack(fill="x", padx=10)

key_entry = tk.Entry(key_frame)

key_entry.pack(
    side="left",
    fill="x",
    expand=True
)

tk.Button(
    key_frame,
    text="Browse",
    command=browse_key
).pack(side="left", padx=5)


# =========================
# FOLDER
# =========================

tk.Label(
    root,
    text="Encrypted Folder"
).pack(pady=(15, 5))

folder_frame = tk.Frame(root)
folder_frame.pack(fill="x", padx=10)

folder_entry = tk.Entry(folder_frame)

folder_entry.pack(
    side="left",
    fill="x",
    expand=True
)

tk.Button(
    folder_frame,
    text="Browse",
    command=browse_folder
).pack(side="left", padx=5)


# =========================
# BUTTON
# =========================

tk.Button(
    root,
    text="Decrypt Files",
    height=2,
    width=20,
    command=start_decrypt
).pack(pady=25)


# =========================
# STATUS
# =========================

status_var = tk.StringVar()

status_var.set("Waiting...")

status_label = tk.Label(
    root,
    textvariable=status_var,
    fg="blue"
)

status_label.pack(pady=10)


# =========================
# START GUI
# =========================

root.mainloop()