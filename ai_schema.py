"""
Pydantic models for the /ask-ai endpoint.

The request/response shape is kept IDENTICAL to the original rule-based
assistant so the existing frontend app.js needs zero changes:
  Request:  { "message": "..." }
  Response: { "reply": "..." }
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class AIRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=2000,
        description="User's question for the CyberGuard AI assistant.",
    )

    @field_validator("message")
    @classmethod
    def not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("message must not be empty or whitespace-only")
        return stripped


class AIResponse(BaseModel):
    reply: str
    timestamp: str
