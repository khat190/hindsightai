"""Thin wrapper around Hindsight (historical experience memory) with retain() and recall().

Backends
--------
* HindsightBackend : the real thing. Uses the official `hindsight-client` package if installed,
                     otherwise a best-effort REST call with `requests`.
* LocalBackend     : OFFLINE TEST DOUBLE (keyword overlap). Only for tests / running the demo
                     without credentials. It is NOT Hindsight and is labelled as such in every
                     API response (`memory_backend: "local"`).

Playbook = policy.  Hindsight = experience.  Memories returned here are context for the LLM,
never instructions that override the approved playbook.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Any

from .config import Settings
from .errors import ConfigError, UpstreamError, ValidationFailed


@dataclass
class MemoryHit:
    ref: str                 # M1, M2 ... stable label used in prompts/responses
    text: str
    memory_id: str | None = None
    type: str | None = None
    context: str | None = None
    score: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ text builders
def incident_to_memory_text(rec: dict) -> str:
    """Turn a completed incident record into a narrative that Hindsight can extract facts from."""
    def bullets(key: str) -> str:
        items = rec.get(key) or []
        return "; ".join(str(i) for i in items) if items else "none recorded"

    lines = [
        f"INCIDENT {rec.get('incident_id', '?')} ({rec.get('incident_type', 'unknown')}): {rec.get('summary', '')}",
        f"Affected user: {rec.get('affected_user', 'n/a')}. Affected host: {rec.get('affected_host', 'n/a')}.",
        f"Evidence observed: {bullets('evidence')}.",
        f"Investigation performed: {bullets('investigation')}.",
        f"Actions taken (in order): {bullets('actions_taken')}.",
        f"Outcome: {rec.get('outcome', 'unknown')}",
        f"Analyst feedback: {rec.get('analyst_feedback', 'none')}",
        f"Lessons learned: {bullets('lessons_learned')}.",
        f"Detection gaps: {bullets('detection_gaps')}.",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ backends
class HindsightBackend:
    name = "hindsight"

    def __init__(self, s: Settings):
        missing = [k for k, v in (("HINDSIGHT_API_KEY", s.hindsight_api_key),
                                  ("HINDSIGHT_BASE_URL", s.hindsight_base_url)) if not v]
        if missing:
            raise ConfigError(f"Hindsight is not configured: missing {', '.join(missing)}",
                              hint="Set them in .env (see .env.example) or run with MEMORY_BACKEND=local for an offline demo.")
        self.bank = s.hindsight_bank_id
        self.base_url = s.hindsight_base_url.rstrip("/")
        self.api_key = s.hindsight_api_key
        self._client = None
        try:  # official client (pip install hindsight-client)
            from hindsight_client import Hindsight  # type: ignore
            self._client = Hindsight(base_url=self.base_url, api_key=self.api_key)
        except ImportError:
            self._client = None

    @property
    def transport(self) -> str:
        return "hindsight-client" if self._client is not None else "rest-fallback"

    # -- retain
    def retain(self, text: str, context: str | None, document_id: str | None, metadata: dict | None) -> dict:
        try:
            if self._client is not None:
                kwargs: dict[str, Any] = {"bank_id": self.bank, "content": text}
                if context:
                    kwargs["context"] = context
                if document_id:
                    kwargs["document_id"] = document_id
                if metadata:
                    kwargs["metadata"] = {k: str(v) for k, v in metadata.items()}
                try:
                    self._client.retain(**kwargs)
                except TypeError:  # older/newer client signature: retry with the minimal call
                    self._client.retain(bank_id=self.bank, content=text, context=context)
            else:
                import requests
                item = {"content": text}
                if context:
                    item["context"] = context
                if document_id:
                    item["document_id"] = document_id
                r = requests.post(f"{self.base_url}/v1/default/banks/{self.bank}/memories",
                                  json={"items": [item]}, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=60)
                r.raise_for_status()
            return {"retained": True, "backend": self.name, "transport": self.transport, "bank_id": self.bank, "document_id": document_id}
        except Exception as e:  # network/auth/API errors
            raise UpstreamError(f"Hindsight retain failed: {e}", hint="Check HINDSIGHT_BASE_URL / HINDSIGHT_API_KEY and that the service is reachable.")

    # -- recall
    def recall(self, query: str, max_results: int) -> list[MemoryHit]:
        try:
            if self._client is not None:
                resp = self._client.recall(bank_id=self.bank, query=query)
                raw = getattr(resp, "results", None)
                if raw is None and isinstance(resp, dict):
                    raw = resp.get("results", [])
            else:
                import requests
                r = requests.post(f"{self.base_url}/v1/default/banks/{self.bank}/memories/recall",
                                  json={"query": query}, headers={"Authorization": f"Bearer {self.api_key}"}, timeout=60)
                r.raise_for_status()
                raw = r.json().get("results", [])
        except Exception as e:
            raise UpstreamError(f"Hindsight recall failed: {e}", hint="Check HINDSIGHT_BASE_URL / HINDSIGHT_API_KEY and that the service is reachable.")
        hits = []
        for i, item in enumerate((raw or [])[:max_results], start=1):
            g = (lambda k: item.get(k)) if isinstance(item, dict) else (lambda k: getattr(item, k, None))
            text = g("text") or g("content") or ""
            if not text:
                continue
            hits.append(MemoryHit(ref=f"M{i}", text=str(text), memory_id=str(g("id")) if g("id") else None,
                                  type=g("type") or g("fact_type"), context=g("context")))
        return hits


_STOP = set("the a an of to and or in on for with at by from is was were be been it this that as after before then into over under user account".split())


def _tokens(s: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_.-]+", s.lower()) if t not in _STOP and len(t) > 2}


class LocalBackend:
    """Offline test double: in-process keyword-overlap store. NOT Hindsight."""
    name = "local"
    transport = "in-process"

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self._n = 0

    def retain(self, text, context, document_id, metadata) -> dict:
        self._n += 1
        key = document_id or f"doc-{self._n}"
        self.docs[key] = {"text": text, "context": context}
        return {"retained": True, "backend": self.name, "transport": self.transport, "bank_id": "local", "document_id": key}

    def recall(self, query: str, max_results: int) -> list[MemoryHit]:
        q = _tokens(query)
        scored = []
        for key, d in self.docs.items():
            overlap = len(q & _tokens(d["text"]))
            if overlap:
                scored.append((overlap / (len(q) or 1), key, d))
        scored.sort(key=lambda x: -x[0])
        return [MemoryHit(ref=f"M{i}", text=d["text"], memory_id=key, type="experience", context=d["context"], score=round(sc, 3))
                for i, (sc, key, d) in enumerate(scored[:max_results], start=1)]


# ------------------------------------------------------------------ service
class MemoryService:
    """What the rest of the app talks to."""

    def __init__(self, settings: Settings, backend=None):
        self.settings = settings
        self._backend = backend

    @property
    def backend(self):
        if self._backend is None:
            kind = self.settings.memory_backend
            if kind == "local":
                self._backend = LocalBackend()
            elif kind == "hindsight":
                self._backend = HindsightBackend(self.settings)
            else:
                raise ConfigError(f"Unknown MEMORY_BACKEND '{kind}'", hint="Use 'hindsight' or 'local'.")
        return self._backend

    def status(self) -> dict:
        s = self.settings
        if s.memory_backend == "local":
            return {"backend": "local", "configured": True, "note": "offline test double, NOT Hindsight"}
        return {"backend": "hindsight", "configured": bool(s.hindsight_api_key and s.hindsight_base_url), "bank_id": s.hindsight_bank_id}

    def retain(self, text: str, context: str | None = None, document_id: str | None = None, metadata: dict | None = None) -> dict:
        if not text or not text.strip():
            raise ValidationFailed("Nothing to retain: 'text' is empty")
        return self.backend.retain(text, context, document_id, metadata)

    def retain_incident(self, record: dict) -> dict:
        return self.retain(incident_to_memory_text(record), context="Security incident response experience",
                           document_id=record.get("incident_id"), metadata={"incident_type": record.get("incident_type", "")})

    def recall(self, query: str, max_results: int = 5) -> list[MemoryHit]:
        if not query or not query.strip():
            raise ValidationFailed("Recall query is empty")
        return self.backend.recall(query, max_results)
