"""Settings from environment (.env is loaded by a tiny built-in parser; no extra dependency)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path | None = None) -> None:
    path = path or ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    hindsight_api_key: str = ""
    hindsight_base_url: str = ""
    hindsight_bank_id: str = "soc-incident-response"
    llm_api_key: str = ""
    llm_provider: str = "anthropic"          # anthropic | openai (any OpenAI-compatible endpoint)
    llm_model: str = ""
    llm_base_url: str = ""
    llm_mode: str = "live"                    # live | mock
    memory_backend: str = "hindsight"         # hindsight | local (offline test double, NOT Hindsight)
    use_hindsight: bool = False
    playbook_dir: Path = ROOT / "playbooks"
    incident_dir: Path = ROOT / "incidents"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        e = os.environ
        return cls(
            hindsight_api_key=e.get("HINDSIGHT_API_KEY", ""),
            hindsight_base_url=e.get("HINDSIGHT_BASE_URL", ""),
            hindsight_bank_id=e.get("HINDSIGHT_BANK_ID", "") or "soc-incident-response",
            llm_api_key=e.get("LLM_API_KEY", ""),
            llm_provider=(e.get("LLM_PROVIDER", "anthropic") or "anthropic").lower(),
            llm_model=e.get("LLM_MODEL", ""),
            llm_base_url=e.get("LLM_BASE_URL", ""),
            llm_mode=(e.get("LLM_MODE", "live") or "live").lower(),
            memory_backend=(e.get("MEMORY_BACKEND", "hindsight") or "hindsight").lower(),
            use_hindsight=_bool(e.get("USE_HINDSIGHT"), False),
        )
