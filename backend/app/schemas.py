from __future__ import annotations

from datetime import datetime
from typing import Optional, Dict, Any, List

from pydantic import BaseModel, ConfigDict, field_serializer


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class UserRead(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PacketCreate(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_length: int
    timestamp: Optional[datetime] = None
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    service: Optional[str] = None
    info: Optional[str] = None
    dns_info: Optional[Dict[str, Any]] = None
    http_info: Optional[Dict[str, Any]] = None
    payload_preview: Optional[Dict[str, Any]] = None
    layers: Optional[List[Dict[str, Any]]] = None


class CaptureToggleRequest(BaseModel):
    enabled: bool


class PacketRead(BaseModel):
    id: int
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_length: int
    timestamp: datetime
    ttl: Optional[int] = None
    tcp_flags: Optional[str] = None
    service: Optional[str] = None
    info: Optional[str] = None
    dns_info: Optional[Dict[str, Any]] = None
    http_info: Optional[Dict[str, Any]] = None
    payload_preview: Optional[Dict[str, Any]] = None
    layers: Optional[List[Dict[str, Any]]] = None

    model_config = ConfigDict(from_attributes=True)

    @field_serializer('timestamp')
    def serialize_ts(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat()


class AlertCreate(BaseModel):
    source_ip: str
    destination_ip: str
    attack_type: str
    severity: str
    description: Optional[str] = None
    timestamp: Optional[datetime] = None


class AlertRead(BaseModel):
    id: int
    source_ip: str
    destination_ip: str
    attack_type: str
    severity: str
    description: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer('timestamp')
    def serialize_ts(self, dt: datetime, _info):
        return dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    message: str
    username: str
    role: str
