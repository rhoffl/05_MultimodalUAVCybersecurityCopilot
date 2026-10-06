from typing import Any, Literal
from pydantic import BaseModel, Field

class Event(BaseModel):
    source: Literal["mavlink", "suricata", "zeek", "mission", "vision", "threat_intel"]
    event_type: str
    timestamp: float
    drone_id: str = "UAV-01"
    severity: int = Field(default=1, ge=1, le=5)
    attributes: dict[str, Any] = Field(default_factory=dict)
    ground_truth_attack: bool = False

class Evidence(BaseModel):
    id: str
    source: str
    summary: str
    citation: str
    timestamp: float

class Alert(BaseModel):
    id: str
    drone_id: str
    title: str
    confidence: float
    severity: Literal["low", "medium", "high", "critical"]
    attack: bool
    techniques: list[str]
    evidence: list[Evidence]
    explanation: str
    recommendations: list[str]
    detected_at: float
    first_malicious_at: float | None = None
    status: Literal["open", "approved", "dismissed"] = "open"

class Approval(BaseModel):
    action: str
    approved_by: str
    reason: str

