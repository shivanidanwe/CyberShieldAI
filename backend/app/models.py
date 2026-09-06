from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

from app.database import Base

class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String, unique=True)

    email = Column(String, unique=True)

    password = Column(String)

    role = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)
    
class Packet(Base):
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String, nullable=False)

    destination_ip = Column(String, nullable=False)

    protocol = Column(String, nullable=False)

    source_port = Column(Integer, nullable=True)

    destination_port = Column(Integer, nullable=True)

    packet_length = Column(Integer)

    timestamp = Column(DateTime, default=datetime.utcnow)
    
class Alert(Base):

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String, nullable=False)

    destination_ip = Column(String, nullable=False)

    attack_type = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    description = Column(String)

    timestamp = Column(DateTime, default=datetime.utcnow)