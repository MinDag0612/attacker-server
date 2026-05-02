from sqlalchemy import Column, Integer, String, Text
from db import Base
from pydantic import BaseModel


class Keys(Base):
    __tablename__ = "KEYS_LIST"

    id = Column(Integer, primary_key=True, autoincrement=True)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    machine_id = Column(String(255), nullable=False)
    aes_key = Column(Text, nullable=True)
    content = Column(Text, nullable=True)


class KeyCreate(BaseModel):
    public_key: str
    private_key: str
    machine_id: str
    content: str | None = None


class AddAES(BaseModel):
    machine_id: str
    aes_key: str
    content: str | None = None


class MachineId(BaseModel):
    machine_id: str