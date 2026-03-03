import base64
import re
from typing import Optional
from fastapi import HTTPException

# Extrae el hash embebido en el .ots desde `ots info`
FILE_SHA256_RE = re.compile(r"File\s+sha256\s+hash:\s*([0-9a-f]{64})", re.IGNORECASE)

# Detecta TXID cuando ya hay anclaje en una transacción (aunque falten confirmaciones)
TXID_RE = re.compile(
    r"(?:#\s*Transaction id|Timestamped by transaction)\s+([0-9a-f]{64})",
    re.IGNORECASE,
)


def safe_b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s)
    except Exception:
        raise HTTPException(status_code=400, detail="Base64 inválido")


def extract_txid(text: str) -> Optional[str]:
    m = TXID_RE.search(text or "")
    return m.group(1) if m else None


def extract_embedded_sha256(info_stdout: str) -> Optional[str]:
    m = FILE_SHA256_RE.search(info_stdout or "")
    return m.group(1).lower() if m else None