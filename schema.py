from typing import List
from pydantic import BaseModel, EmailStr, field_validator, Field

class StatsResponse(BaseModel):
    email: EmailStr
    count: int
    sum: int
    min: int
    max: int
    mean: float


class TokenRequest(BaseModel):
    token: str


class Event(BaseModel):
    user: str
    amount: float
    ts: int

class AnalyticsRequest(BaseModel):
    events: List[Event]


class InvoiceRequest(BaseModel):
    text: str = Field(
        ...,
        description="The raw unstructured text extracted from the invoice document."
    )

class InvoiceResponse(BaseModel):
    vendor: str = Field(..., description="The vendor or company name.")
    amount: float = Field(..., description="The total amount due as a number.")
    currency: str = Field(..., description="The 3-letter currency code (e.g. USD).")
    date: str = Field(..., description="The payment due date formatted strictly as YYYY-MM-DD.")

    @field_validator("currency")
    @classmethod
    def enforce_uppercase_iso(cls, v: str) -> str:
        cleaned = v.strip().upper()
        if len(cleaned) != 3:
            raise ValueError("Currency must be a valid 3-letter ISO code.")
        return cleaned
