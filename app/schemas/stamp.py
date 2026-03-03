from typing import Optional
from pydantic import BaseModel, Field


class StampRequest(BaseModel):
    stampId: int = Field(..., ge=1)
    sha256: str = Field(..., min_length=64, max_length=64)
    originalFilename: Optional[str] = None
    fileBase64: str


class StampResponse(BaseModel):
    stampId: int
    status: str
    otsProofB64: str
    txid: Optional[str] = None


class UpgradeRequest(BaseModel):
    stampId: int = Field(..., ge=1)
    otsProofB64: str = Field(..., min_length=1)


class UpgradeResponse(BaseModel):
    stampId: int
    status: str
    otsProofB64: str
    txid: Optional[str] = None


class VerifyRequest(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)
    otsProofB64: str


class VerifyResponse(BaseModel):
    valid: bool
    status: str
    message: str
    txid: Optional[str] = None