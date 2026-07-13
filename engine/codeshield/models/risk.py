"""Risk scoring models."""

from pydantic import BaseModel, Field

from codeshield.models.enums import RecommendedAction, Severity


class RiskFactor(BaseModel):
    name: str
    value: str
    weight: int = Field(ge=0, le=100)
    contribution: int = Field(ge=0, le=100)
    explanation: str


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Severity
    recommended_action: RecommendedAction
    factors: list[RiskFactor]

