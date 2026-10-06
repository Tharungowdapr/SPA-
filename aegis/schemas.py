"""Event and decision schemas. `event_type` keeps the schema extensible (ad_click, ad_view, ...)."""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

_ID = re.compile(r"^[A-Za-z0-9_\-.:]{1,64}$")


def new_event_id() -> str:
    return "evt_" + uuid.uuid4().hex[:12]


class ClickEvent(BaseModel):
    event_id: str = Field(default_factory=new_event_id)
    timestamp: float = Field(default_factory=time.time)  # epoch seconds (event time)
    event_type: str = "ad_click"
    user_id: str
    ad_id: str
    campaign_id: str
    publisher_id: str = "PUB0"
    session_id: str = "S0"
    ip_address: str = "0.0.0.0"
    device_id: str
    user_agent: str = ""
    country: str = "IN"
    latitude: float = 0.0
    longitude: float = 0.0
    referrer: str = ""
    click_position: str = ""
    page_id: str = ""
    account_age_days: float = 180.0
    # Ground truth is attached ONLY by the server-side simulator. It is never used for decisions.
    label: Optional[int] = None
    attack_type: Optional[str] = None
    # Provenance is attached ONLY by the server. Untrusted callers may not set it.
    source: str = "live"
    run_id: Optional[str] = None

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        return v[:24] or "live"

    @field_validator("event_id", "user_id", "ad_id", "campaign_id", "publisher_id", "device_id", "session_id")
    @classmethod
    def _ids(cls, v: str) -> str:
        if not _ID.match(v):
            raise ValueError("invalid identifier")
        return v

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v: str) -> str:
        if not re.match(r"^[0-9a-fA-F:.]{3,45}$", v):
            raise ValueError("invalid ip")
        return v

    @field_validator("user_agent", "referrer", "page_id", "click_position")
    @classmethod
    def _clip(cls, v: str) -> str:
        return v.replace("<", "").replace(">", "")[:256]

    @field_validator("timestamp")
    @classmethod
    def _ts(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("invalid timestamp")
        return float(v)

    def public(self) -> "ClickEvent":
        """Copy with ground truth and provenance stripped (what untrusted callers may submit)."""
        return self.model_copy(update={"label": None, "attack_type": None, "source": "live", "run_id": None})


class Decision(BaseModel):
    event_id: str
    timestamp: float
    user_id: str
    ad_id: str
    campaign_id: str
    device_id: str
    ip_mask: str
    risk: float
    level: str            # LOW | MEDIUM | HIGH | CRITICAL
    action: str           # ALLOW | MONITOR | FLAG | BLOCK | REJECTED
    confidence: str       # LOW | MEDIUM | HIGH (layer coverage)
    scores: dict[str, Optional[float]]
    rules_fired: list[str] = []
    top_factors: list[dict[str, Any]] = []
    model_version: str = "none"
    latency_ms: float = 0.0
    label: Optional[int] = None
    attack_type: Optional[str] = None
    blocked_now: bool = False
    reason: str = ""
    reason_title: str = ""
    incident_id: int | None = None
