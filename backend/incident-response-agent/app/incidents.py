"""Load synthetic historical and current incidents."""
from __future__ import annotations

import json
from pathlib import Path

from .errors import DataFileError, NotFoundError, ValidationFailed

REQUIRED_CURRENT = ["incident_id", "incident_type", "summary"]
REQUIRED_HISTORICAL = ["incident_id", "incident_type", "summary", "actions_taken", "outcome"]


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise DataFileError(f"Malformed JSON in {path.name}: {e}")
    except OSError as e:
        raise DataFileError(f"Cannot read {path.name}: {e}")


def validate_incident(inc: dict, required: list[str] = REQUIRED_CURRENT) -> dict:
    if not isinstance(inc, dict):
        raise ValidationFailed("Incident must be a JSON object")
    missing = [k for k in required if not inc.get(k)]
    if missing:
        raise ValidationFailed(f"Incident is missing required fields: {missing}")
    if "telemetry" in inc and not isinstance(inc["telemetry"], dict):
        raise ValidationFailed("'telemetry' must be an object")
    return inc


class IncidentStore:
    def __init__(self, directory: Path):
        self.dir = Path(directory)

    def _load_dir(self, sub: str, required: list[str]) -> dict[str, dict]:
        out = {}
        for p in sorted((self.dir / sub).glob("*.json")):
            inc = validate_incident(_read(p), required)
            out[inc["incident_id"]] = inc
        return out

    def historical(self) -> dict[str, dict]:
        return self._load_dir("historical", REQUIRED_HISTORICAL)

    def current(self) -> dict[str, dict]:
        return self._load_dir("current", REQUIRED_CURRENT)

    def get_current(self, incident_id: str) -> dict:
        cur = self.current()
        if incident_id not in cur:
            raise NotFoundError(f"Unknown incident '{incident_id}'",
                                hint=f"Known current incidents: {sorted(cur)}")
        return cur[incident_id]


def incident_entities(inc: dict) -> set[str]:
    """Targets the agent is allowed to act on (users, hosts, indicators) for this incident."""
    ents = set()
    for k in ("affected_user", "affected_host"):
        if inc.get(k):
            ents.add(inc[k])
    for k in ("users", "hosts", "indicators"):
        ents.update(inc.get(k) or [])
    tel = inc.get("telemetry") or {}
    for k in ("user_profiles", "authentication_history", "user_activity", "endpoint_activity"):
        ents.update((tel.get(k) or {}).keys())
    ents.update((tel.get("indicators") or {}).keys())
    return ents
