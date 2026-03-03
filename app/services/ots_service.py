import re
import subprocess
from typing import List, Optional, Tuple

from app.core.config import settings
from app.core.logging import get_logger
from app.utils.parsing import extract_txid

log = get_logger("stamper")

# Detecta "completo" (Bitcoin block header attestation en el proof)
BTC_ATTESTATION_RE = re.compile(r"BitcoinBlockHeaderAttestation", re.IGNORECASE)


def require_ots() -> None:
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


def run_ots(args: List[str]) -> subprocess.CompletedProcess:
    cmd = ["ots"] + args
    log.info("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def build_calendar_args() -> List[str]:
    args: List[str] = []
    for cal in settings.OTS_CALENDARS:
        args += ["-l", cal]
    return args


def ots_info_and_state(ots_path: str) -> Tuple[bool, Optional[str], str]:
    """Devuelve (sealed, txid, raw_info_stdout)."""
    p = run_ots(["info", ots_path])
    sealed = bool(BTC_ATTESTATION_RE.search(p.stdout))
    txid = extract_txid(p.stdout)
    return sealed, txid, p.stdout