import base64
import logging
import os
import re
import subprocess
import tempfile
from typing import Optional, List, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("stamper")

app = FastAPI(title="BitSealer Stamper", version="0.8.0")


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
]

OTS_CALENDARS = [c.strip() for c in os.getenv("OTS_CALENDARS", "").split(",") if c.strip()] or DEFAULT_CALENDARS


# Detecta "completo" (Bitcoin block header attestation en el proof)
BTC_ATTESTATION_RE = re.compile(r"BitcoinBlockHeaderAttestation", re.IGNORECASE)

# Detecta TXID cuando ya hay anclaje en una transacción (aunque falten confirmaciones)
# Detecta TXID: soporta formatos de ots-cli
# - "# Transaction id <txid>" (muy común en ots info)
# - "Timestamped by transaction <txid>" (otros outputs)
TXID_RE = re.compile(
    r"(?:#\s*Transaction id|Timestamped by transaction)\s+([0-9a-f]{64})",
    re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────


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
    fileBase64: str
    otsProofB64: str


class VerifyResponse(BaseModel):
    valid: bool
    message: str


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _require_ots():
    try:
        subprocess.run(["ots", "--version"], check=True, capture_output=True, text=True)
    except Exception as e:
        raise RuntimeError(
            "No encuentro el comando `ots`.\n"
            "Solución (local):\n"
            "  python3 -m venv .venv\n"
            "  source .venv/bin/activate\n"
            "  pip install -r requirements.txt\n"
            "  which ots && ots --version\n"
        ) from e


def _run_ots(args: List[str]) -> subprocess.CompletedProcess:
    cmd = ["ots"] + args
    log.info("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def _build_calendar_args() -> List[str]:
    args: List[str] = []
    for cal in OTS_CALENDARS:
        args += ["-l", cal]
    return args


def _safe_b64decode(s: str) -> bytes:
    try:
        return base64.b64decode(s)
    except Exception:
        raise HTTPException(status_code=400, detail="Base64 inválido")


def _extract_txid(text: str) -> Optional[str]:
    m = TXID_RE.search(text or "")
    return m.group(1) if m else None


def _ots_info_and_state(ots_path: str) -> Tuple[bool, Optional[str], str]:
    """Devuelve (sealed, txid, raw_info_stdout)."""
    p = _run_ots(["info", ots_path])
    sealed = bool(BTC_ATTESTATION_RE.search(p.stdout))
    txid = _extract_txid(p.stdout)
    return sealed, txid, p.stdout


def _write_temp_file(raw: bytes, suffix: str = "") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(raw)
        return tmp.name


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────


@app.on_event("startup")
def on_startup():
    _require_ots()
    log.info("Stamper listo. calendars=%s", OTS_CALENDARS)


@app.get("/health")
def health():
    return {"ok": True, "service": "bitsealer-stamper"}


@app.post("/stamp", response_model=StampResponse)
def stamp(req: StampRequest):
    # Validación sha256 (hex)
    try:
        int(req.sha256, 16)
    except Exception:
        raise HTTPException(status_code=400, detail="sha256 inválido (no es hex)")

    raw = _safe_b64decode(req.fileBase64)

    suffix = ""
    if req.originalFilename and "." in req.originalFilename:
        suffix = "." + req.originalFilename.rsplit(".", 1)[-1]

    tmp_path = _write_temp_file(raw, suffix=suffix)

    try:
        _run_ots(_build_calendar_args() + ["stamp", tmp_path])

        ots_path = tmp_path + ".ots"
        with open(ots_path, "rb") as f:
            ots_bytes = f.read()

        return StampResponse(
            stampId=req.stampId,
            status="PENDING",
            otsProofB64=base64.b64encode(ots_bytes).decode("ascii"),
            txid=None,
        )

    except subprocess.CalledProcessError as e:
        log.error("ots error (stamp): %s", (e.stderr or e.stdout or "").strip())
        raise HTTPException(status_code=500, detail=f"ots error: {(e.stderr or e.stdout or '').strip()}")
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        try:
            if os.path.exists(tmp_path + ".ots"):
                os.remove(tmp_path + ".ots")
        except Exception:
            pass


@app.post("/upgrade", response_model=UpgradeResponse)
def upgrade(req: UpgradeRequest):
    ots_bytes = _safe_b64decode(req.otsProofB64)
    tmp_ots_path = _write_temp_file(ots_bytes, suffix=".ots")

    try:
        upgrade_err = ""
        try:
            _run_ots(["upgrade", tmp_ots_path])
        except subprocess.CalledProcessError as e:
            upgrade_err = (e.stderr or e.stdout or "").strip()
            log.info("upgrade: aún no completo (%s)", upgrade_err)

        sealed, txid_info, _info_stdout = _ots_info_and_state(tmp_ots_path)
        txid = txid_info or _extract_txid(upgrade_err)

        with open(tmp_ots_path, "rb") as f:
            updated = f.read()

        status = "SEALED" if sealed else ("ANCHORING" if txid else "PENDING")

        return UpgradeResponse(
            stampId=req.stampId,
            status=status,
            otsProofB64=base64.b64encode(updated).decode("ascii"),
            txid=txid,
        )

    except subprocess.CalledProcessError as e:
        log.error("ots error (upgrade): %s", (e.stderr or e.stdout or "").strip())
        raise HTTPException(status_code=500, detail=f"ots error: {(e.stderr or e.stdout or '').strip()}")
    finally:
        try:
            if os.path.exists(tmp_ots_path):
                os.remove(tmp_ots_path)
        except Exception:
            pass


@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    raw = _safe_b64decode(req.fileBase64)
    ots_bytes = _safe_b64decode(req.otsProofB64)

    tmp_file_path = _write_temp_file(raw)
    tmp_ots_path = tmp_file_path + ".ots"

    try:
        with open(tmp_ots_path, "wb") as f:
            f.write(ots_bytes)

        try:
            _run_ots(["verify", tmp_file_path])
            return VerifyResponse(valid=True, message="Proof válido")
        except subprocess.CalledProcessError as e:
            msg = (e.stderr or e.stdout or "").strip() or "Proof inválido"
            return VerifyResponse(valid=False, message=msg)

    finally:
        try:
            if os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)
        except Exception:
            pass
        try:
            if os.path.exists(tmp_ots_path):
                os.remove(tmp_ots_path)
        except Exception:
            pass
