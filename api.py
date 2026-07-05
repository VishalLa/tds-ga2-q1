import os
import jwt
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from schema import StatsResponse, TokenRequest
from config import get_setting

app = APIRouter()


@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/stats", response_model=StatsResponse, status_code=200)
def stats(values: str): 
    str_values = values.split(",")
    
    try: 
        int_values = [int(i) for i in str_values]
    except ValueError:
        raise HTTPException(status_code=400, detail="Query values must be comma-separated integers.")

    stats_dict = {
        "email": "23f2003086@ds.study.iitm.ac.in",
        "count": len(int_values),
        "sum": sum(int_values),
        "min": min(int_values),
        "max": max(int_values),
        "mean": sum(int_values) / len(int_values)
    }

    return stats_dict


@app.post("/verify")
def verify(payload: TokenRequest, settings = Depends(get_setting)):
    try: 
        public_key = settings.idp_public_key.replace("\\n", "\n")
        
        decoded_claims = jwt.decode(
            payload.token,
            public_key,
            algorithms=["RS256"],
            audience=settings.expected_audience,
            issuer=settings.expected_issuer
        )
        
        return {
            "valid": True,
            "email": decoded_claims.get("email"),
            "sub": decoded_claims.get("sub"),
            "aud": decoded_claims.get("aud")
        }
    
    except jwt.PyJWTError:
        return JSONResponse(
            status_code=401,
            content={"valid": False}
        )

