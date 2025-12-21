import os
import base64
import requests
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

app = FastAPI()

BACKEND_CALLBACK_URL = os.getenv("BACKEND_CALLBACK_URL", "http://app:8080/api/stamps/callback")
STAMPER_CALLBACK_TOKEN = os.getenv("STAMPER_CALLBACK_TOKEN", "change_me")

CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://finney.calendar.eternitywall.com",
]

class StampRequest(BaseModel):
    stampId: int
    sha256: str

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/stamp")
def stamp(req: StampRequest, background_tasks: BackgroundTasks):
    background_tasks.add_task(process_stamp, req.stampId, req.sha256)
    return {"received": True, "stampId": req.stampId}

def process_stamp(stamp_id: int, sha256_hex: str):
    try:
        digest = bytes.fromhex(sha256_hex)
        ots_bytes = stamp_digest(digest)
        callback(stamp_id, "SEALED", ots_bytes=ots_bytes)
    except Exception as e:
        callback(stamp_id, "ERROR", error=str(e))

def stamp_digest(digest: bytes) -> bytes:
    last_err = None
    for cal in CALENDARS:
        try:
            r = requests.post(f"{cal}/digest", data=digest, timeout=15)
            if r.status_code == 200 and r.content:
                return r.content
            last_err = RuntimeError(f"{cal} -> {r.status_code}")
        except Exception as e:
            last_err = e
    raise RuntimeError(f"All calendars failed: {last_err}")

def callback(stamp_id: int, status: str, ots_bytes: bytes | None = None, error: str | None = None):
    payload = {
        "stampId": stamp_id,
        "status": status,
        "otsProofB64": base64.b64encode(ots_bytes).decode("ascii") if ots_bytes else None,
        "errorMessage": error,
    }
    headers = {"X-Stamp-Token": STAMPER_CALLBACK_TOKEN}
    requests.post(BACKEND_CALLBACK_URL, json=payload, headers=headers, timeout=10)
