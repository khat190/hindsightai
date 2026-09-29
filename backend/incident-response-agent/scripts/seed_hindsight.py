"""Seed Hindsight with the synthetic HISTORICAL incidents.

Usage:  python scripts/seed_hindsight.py            # uses .env (MEMORY_BACKEND=hindsight)
Re-running is safe: each incident is retained with document_id = incident_id.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent import AgentController  # noqa: E402
from app.errors import AppError  # noqa: E402

if __name__ == "__main__":
    try:
        out = AgentController().seed()
    except AppError as e:
        print(f"Seeding failed: {e.message}" + (f"\nHint: {e.hint}" if e.hint else ""))
        sys.exit(1)
    for r in out["results"]:
        print(f"retained {r['incident_id']} -> {r['backend']} ({r['transport']})")
    print(f"Done: {out['seeded']} incidents seeded.")
