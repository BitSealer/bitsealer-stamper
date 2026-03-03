import base64
import os
import subprocess
from fastapi import APIRouter, HTTPException

from app.core.logging import get_logger
from app.schemas.stamp import (
    StampRequest,
    StampResponse,
    UpgradeRequest,
    UpgradeResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.services.ots_service import (
    build_calendar_args,
    run_ots,
    ots_info_and_state,
)
from app.utils.files import write_temp_file
from app.utils.parsing import safe_b64decode, extract_txid, extract_embedded_sha256
from app.utils.crypto import normalize_sha256

log = get_logger("stamper")

router = APIRouter()


@router.get("/health")
def health():
    return {"ok": True, "service": "bitsealer-stamper"}


@router.post("/stamp", response_model=StampResponse)
def stamp(req: StampRequest):
    # Validación sha256 (hex) — se mantiene tal cual el comportamiento original
    try:
        int(req.sha256, 16)
    except Exception:
        raise HTTPException(status_code=400, detail="sha256 inválido (no es hex)")

    raw = safe_b64decode(req.fileBase64)

    suffix = ""
    if req.originalFilename and "." in req.originalFilename:
        suffix = "." + req.originalFilename.rsplit(".", 1)[-1]

    tmp_path = write_temp_file(raw, suffix=suffix)

    try:
        run_ots(build_calendar_args() + ["stamp", tmp_path])

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


@router.post("/upgrade", response_model=UpgradeResponse)
def upgrade(req: UpgradeRequest):
    ots_bytes = safe_b64decode(req.otsProofB64)
    tmp_ots_path = write_temp_file(ots_bytes, suffix=".ots")

    try:
        upgrade_err = ""
        try:
            run_ots(["upgrade", tmp_ots_path])
        except subprocess.CalledProcessError as e:
            upgrade_err = (e.stderr or e.stdout or "").strip()
            log.info("upgrade: aún no completo (%s)", upgrade_err)

        sealed, txid_info, _info_stdout = ots_info_and_state(tmp_ots_path)
        txid = txid_info or extract_txid(upgrade_err)

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


# ✅ VERIFY DEFINITIVO SIN NODO:
# - No recibimos el archivo original (privacidad)
# - Comparamos sha256(front) con el hash embebido en el .ots (ots info)
@router.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    sha = normalize_sha256(req.sha256)
    ots_bytes = safe_b64decode(req.otsProofB64)

    tmp_ots_path = write_temp_file(ots_bytes, suffix=".ots")

    try:
        try:
            sealed, txid, info_stdout = ots_info_and_state(tmp_ots_path)
        except subprocess.CalledProcessError as e:
            msg = (e.stderr or e.stdout or "").strip() or "No se pudo leer el .ots"
            return VerifyResponse(valid=False, status="INVALID", message=msg, txid=None)

        embedded = extract_embedded_sha256(info_stdout)
        if not embedded:
            return VerifyResponse(
                valid=False,
                status="INVALID",
                message="El .ots no parece válido (ots info no devolvió el File sha256 hash).",
                txid=txid,
            )

        if embedded != sha:
            return VerifyResponse(
                valid=False,
                status="MISMATCH",
                message="El SHA-256 del archivo no coincide con el embebido en el .ots.",
                txid=txid,
            )

        status = "SEALED" if sealed else ("ANCHORING" if txid else "PENDING")

        return VerifyResponse(
            valid=True,
            status=status,
            message="Hash coincidente: el .ots corresponde a ese archivo.",
            txid=txid,
        )

    finally:
        try:
            if os.path.exists(tmp_ots_path):
                os.remove(tmp_ots_path)
        except Exception:
            pass