from pydantic import BaseModel, EmailStr

class StatsResponse(BaseModel):
    email: EmailStr
    count: int 
    sum: int 
    min: int
    max: int 
    mean: float


class TokenRequest(BaseModel):
    token: str
