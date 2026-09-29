import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent import AgentController  # noqa: E402
from app.config import Settings  # noqa: E402


def make_controller(**kw) -> AgentController:
    """Controller in offline mode: mock LLM + local memory test double (no credentials needed)."""
    return AgentController(Settings(llm_mode="mock", memory_backend="local", **kw))
