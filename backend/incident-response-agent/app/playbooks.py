"""Load and validate the organization's approved playbooks (the POLICY source)."""
from __future__ import annotations

from pathlib import Path

import yaml

from .errors import DataFileError, NotFoundError

REQUIRED_KEYS = ["name", "incident_type", "steps", "containment", "eradication", "recovery", "post_incident"]
STEP_KEYS = ["id", "name", "objective", "actions", "requires_approval"]

# incident_type -> playbook file key
ALIASES = {
    "suspicious_login": "suspicious_login",
    "account_compromise": "account_compromise",
    "credential_compromise": "account_compromise",
    "privileged_access": "account_compromise",
    "suspicious_access": "account_compromise",
    "phishing": "phishing",
    "generic": "generic_incident_response",
}
GENERIC = "generic_incident_response"


def validate_playbook(pb: dict, source: str = "playbook") -> dict:
    if not isinstance(pb, dict):
        raise DataFileError(f"{source}: top level must be a mapping")
    missing = [k for k in REQUIRED_KEYS if k not in pb]
    if missing:
        raise DataFileError(f"{source}: missing keys {missing}")
    if not isinstance(pb["steps"], list) or not pb["steps"]:
        raise DataFileError(f"{source}: 'steps' must be a non-empty list")
    ids = set()
    for s in pb["steps"]:
        bad = [k for k in STEP_KEYS if not isinstance(s, dict) or k not in s]
        if bad:
            raise DataFileError(f"{source}: step {s!r} missing keys {bad}")
        if s["id"] in ids:
            raise DataFileError(f"{source}: duplicate step id {s['id']}")
        ids.add(s["id"])
    return pb


def load_playbook_file(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise DataFileError(f"Malformed YAML in {path.name}: {e}")
    except OSError as e:
        raise DataFileError(f"Cannot read {path.name}: {e}")
    return validate_playbook(data, path.name)


class PlaybookLibrary:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def list(self) -> list[dict]:
        out = []
        for p in sorted(self.directory.glob("*.yaml")):
            pb = load_playbook_file(p)
            out.append({"file": p.stem, "name": pb["name"], "incident_type": pb["incident_type"],
                        "version": pb.get("version"), "steps": len(pb["steps"])})
        return out

    def get(self, incident_type: str) -> dict:
        """Return the playbook for a type. Unknown types fall back to the generic playbook;
        the generic playbook itself must exist."""
        key = ALIASES.get((incident_type or "").lower(), None)
        if key is None:
            key = GENERIC
            fallback = True
        else:
            fallback = key == GENERIC and incident_type != "generic"
        path = self.directory / f"{key}.yaml"
        if not path.exists():
            raise NotFoundError(f"No playbook file for incident type '{incident_type}'",
                                hint=f"Expected {path.name} in {self.directory}")
        pb = load_playbook_file(path)
        pb = dict(pb)
        pb["_resolved_from"] = incident_type
        pb["_fallback_to_generic"] = fallback
        return pb
