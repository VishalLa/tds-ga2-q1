import os
import json
import httpx
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from schema import InvoiceRequest, InvoiceResponse
from config import get_setting

app = APIRouter()

@app.post("/extract", response_model=InvoiceResponse)
async def extract_invoice(payload: InvoiceRequest, settings=Depends(get_setting)):
    if not payload.text or len(payload.text.strip()) < 5:
        raise HTTPException(
            status_code=422,
            detail="Malformed, empty, or insufficient input text provided."
        )

    system_prompt = """
You are a strict, automated data extraction API. Your ONLY job is to parse invoice text and return a single, valid JSON object. 

### OBJECTIVE
Extract the following exact fields from the provided invoice text:
1. "vendor": The legal name of the company or person issuing the invoice.
2. "amount": The total balance due as a raw number (e.g., 150.00). Do not include currency symbols.
3. "currency": The exact 3-letter uppercase ISO currency code (e.g., USD, EUR, GBP).
4. "date": The payment due date, formatted strictly as YYYY-MM-DD.

### STRICT RULES & CONSTRAINTS
- CRITICAL: You must output ONLY raw, valid JSON. 
- DO NOT wrap the JSON in markdown formatting (no ```json ... ``` blocks).
- DO NOT include any conversational text, greetings, explanations, or pleasantries.
- DO NOT invent or hallucinate data. If a field is completely missing, return null for that field.
- The JSON keys must be exactly: "vendor", "amount", "currency", "date".

### EXAMPLE OUTPUT FORMAT
{
  "vendor": "Acme Industries Ltd.",
  "amount": 1499.50,
  "currency": "USD",
  "date": "2026-07-15"
}

Begin extraction now. Return ONLY the JSON object.
"""

    llm_payload = {
        "model": settings.model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Invoice text:\n{payload.text}"}
        ],
        "temperature": 0.0,
        "stream": False,
        "response_format": {
            "type": "json_object",
            "schema": InvoiceResponse.model_json_schema()
        }
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.post(settings.ollama_api_url, json=llm_payload)

            if response.status_code != 200:
                raise HTTPException(status_code=502, detail="Upstream LLM error.")

            response_data = response.json()
            raw_content = response_data["choices"][0]["message"]["content"]

            cleaned_content = raw_content.replace("```json", "").replace("```", "").strip()

            parsed_json = json.loads(cleaned_content)

            if "vendor_name" in parsed_json and "vendor" not in parsed_json:
                parsed_json["vendor"] = parsed_json["vendor_name"]
                
            if "total_amount" in parsed_json and "amount" not in parsed_json:
                parsed_json["amount"] = parsed_json["total_amount"]
                
            if "due_date" in parsed_json and "date" not in parsed_json:
                parsed_json["date"] = parsed_json["due_date"]

            validated_output = InvoiceResponse.model_validate(parsed_json)
            return validated_output

        except (httpx.RequestError, KeyError, ValueError, json.JSONDecodeError) as e:
            raise HTTPException(
                status_code=422,
                detail=f"Failed to reliably extract or validate invoice fields: {str(e)}"
            )
        
@app.post("/v1/chat/completions")
async def chat_response(request: Request, settings=Depends(get_setting)):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload provided.")
    
    payload["model"] = settings.model_name
    payload["temperature"] = 0.0

    if "messages" in payload and isinstance(payload["messages"], list):
        has_system = any(msg.get("role") == "system" for msg in payload["messages"])
        if not has_system:
            payload["messages"].insert(0, {
                "role": "system",
                "content": "You are a highly logical math assistant. Double-check your arithmetic and ALWAYS solve problems step-by-step to ensure perfect accuracy."
            })

    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            response = await client.post(settings.ollama_api_url, json=payload)

            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
            
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=502, 
                detail=f"FastAPI failed to reach the internal LLM container: {str(e)}"
            )
        