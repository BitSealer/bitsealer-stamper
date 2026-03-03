import os
from dataclasses import dataclass
from typing import List


DEFAULT_CALENDARS = [
    "https://alice.btc.calendar.opentimestamps.org",
    "https://bob.btc.calendar.opentimestamps.org",
]


def _parse_calendars_env(value: str) -> List[str]:
    calendars = [c.strip() for c in (value or "").split(",") if c.strip()]
    return calendars or DEFAULT_CALENDARS


@dataclass(frozen=True)
class Settings:
    OTS_CALENDARS: List[str]


settings = Settings(
    OTS_CALENDARS=_parse_calendars_env(os.getenv("OTS_CALENDARS", "")),
)