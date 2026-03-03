import re
from fastapi import HTTPException

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def normalize_sha256(s: str) -> str:
    v = (s or "").strip().lower()
    if not SHA256_RE.fullmatch(v):
        raise HTTPException(status_code=400, detail="sha256 inválido (se esperan 64 hex)")
    return v