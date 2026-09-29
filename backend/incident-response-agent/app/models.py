"""Request bodies for the API (pydantic). Responses are plain JSON dicts produced by the controller."""
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    incident_id: Optional[str] = Field(None, description="ID of a current incident, e.g. CUR-001")
    incident: Optional[dict[str, Any]] = Field(None, description="Inline incident object (alternative to incident_id)")
    use_hindsight: Optional[bool] = Field(None, description="Override USE_HINDSIGHT for this request")


class ApprovalRequest(BaseModel):
    action_id: str
    decision: Literal["approve", "reject"]
    analyst_comment: Optional[str] = None
    lessons_learned: Optional[list[str]] = None


class RecallRequest(BaseModel):
    query: str
    max_results: int = Field(5, ge=1, le=20)


class RetainRequest(BaseModel):
    text: Optional[str] = None
    incident: Optional[dict[str, Any]] = None
    context: Optional[str] = None


class SeedRequest(BaseModel):
    incident_ids: Optional[list[str]] = None
