from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import sys

def _aes_decrypt(ct, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

def _rsa_decrypt(data, priv):
    print("[INFO - excute] Decrypting data with RSA")
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
    out = path + ".decrypted"
    
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

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decrypt.py <private_key.pem> <folder>")
        sys.exit(1)

    private_key = "KEY.pem"
    decrypt_path = sys.argv[1]

    with open(private_key, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Example usage
    decrypted_files = decrypt_sandbox(decrypt_path, private_key)
    print("[INFO - excute] Decryption completed. Decrypted files:")
    print("\n".join(decrypted_files))