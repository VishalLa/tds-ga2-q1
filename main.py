from fastapi import FastAPI, HTTPExceptip
from pydantic import BaseModel

app = FastAPI()

class ProratmaionRequest:
    old_price: float
    new_price: float
    days_remaining: int 
    days_in_actual_month: int 
    spec: str 

@app.post("/prorate")
def calculate_proration(req: ProratmaionRequest):
    price_difference = req.new_price - req.old_price

    if req.spec == "v1":
        charge = price_difference * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        charge = price_difference * (req.days_remaining / float(req.days_in_actual_month))
    else:
        raise HTTPException(status_code=400, detail="Unknown spec. Must be 'v1' or 'v2'.")
    return {"charge": charge}
