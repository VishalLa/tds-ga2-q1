import os
import io 
import re
import base64 
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image 
from google import genai
from google.genai import types
from dotenv import load_dotenv

from typing import Optional
from dateutil import parser as dateparser

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY environment variable not set")


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RequestData(BaseModel):
    image_base64: str 
    question: str 

class InvoiceRequest(BaseModel):
    invoice_text: str

PROMPT = """
You are an expert document analysis AI for the IITM Online Degree Curation Cell. Your task is to extract precise, accurate information from the provided scanned document, which may be an invoice, receipt, academic record, sales chart, pie chart, or data table.

Carefully analyze the image and answer the user's question based strictly on the visible content. 

CRITICAL RULES:
1. Exact Extraction: Return numbers, dates, names, and totals exactly as they appear in the image. Do not round numbers or reformat dates unless explicitly asked.
2. Zero Hallucination: If the requested information is not present, obscured, or illegible in the image, you must reply exactly with: "DATA_NOT_FOUND". Do not guess, infer, or calculate missing values.
3. Spatial Awareness: When reading tables, ensure you map the correct column header to the correct row value. When reading charts, map the legend and axis labels to the correct data points.
4. Formatting: Provide the direct answer clearly and concisely. Do not add conversational filler like "The image shows..." or "Based on the document...". 
"""

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

@app.get("/")
async def health_check():
    return {"status": "API is running"}

@app.post("/answer-image")
async def answer_image(data: RequestData):
    try:
        base64_str = data.image_base64
        mime_type = "image/jpeg"
        
        if "," in base64_str:
            header, base64_str = base64_str.split(",", 1)
            if "data:" in header and ";" in header:
                mime_type = header.split(":")[1].split(";")[0]

        image_bytes = base64.b64decode(base64_str)
        
    except Exception as e:
        print(f"Base64 Error: {e}")
        raise HTTPException(status_code=400, detail="Invalid base64 image data")
    
    try:
        image_part = types.Part.from_bytes(
            data=image_bytes, 
            mime_type=mime_type
        )
        
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=[image_part, data.question],
            config=types.GenerateContentConfig(
                system_instruction=PROMPT,
            )
        )

        return {"answer": response.text.strip()}

    except Exception as e:
        print(f"\n❌ GEMINI API CRASHED: {str(e)}\n")
        raise HTTPException(status_code=500, detail=f"Gemini API Error: {str(e)}")
    

def find_first(pattern: str, text: str, flags=re.IGNORECASE) -> Optional[str]:
    """Return the first regex group match, or None if not found."""
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else None

def extract_invoice_no(text: str) -> Optional[str]:
    # Matches: "Invoice No: INV-2026-0041", "Invoice #: 123", "Invoice Number - X1"
    return find_first(r"invoice\s*(?:no\.?|number|#)?\s*[:\-]\s*([A-Za-z0-9\-\/]+)", text)


def extract_date(text: str) -> Optional[str]:
    raw = find_first(r"date\s*[:\-]\s*([^\n\r]+)", text)
    if not raw:
        return None
    try:
        # dateutil understands "15 March 2026", "15/03/2026", "March 15, 2026", etc.
        parsed = dateparser.parse(raw, dayfirst=True, fuzzy=True)
        return parsed.strftime("%Y-%m-%d")
    except (ValueError, OverflowError):
        return None
    
def extract_vendor(text: str) -> Optional[str]:
    patterns = [
        r"vendor\s*(?:name)?\s*[:\-]\s*([^\n\r]+)",
        r"(?:billed|sold)\s*by\s*[:\-]\s*([^\n\r]+)",
        r"seller\s*(?:name)?\s*[:\-]\s*([^\n\r]+)",
        r"supplier\s*(?:name)?\s*[:\-]\s*([^\n\r]+)",
        r"company\s*(?:name)?\s*[:\-]\s*([^\n\r]+)",
        r"^from\s*[:\-]\s*([^\n\r]+)",
        r"merchant\s*[:\-]\s*([^\n\r]+)",
    ]
    for pattern in patterns:
        result = find_first(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if result:
            return result
    return None


def _money_to_float(raw: Optional[str]) -> Optional[float]:
    if raw is None:
        return None
    cleaned = raw.replace(",", "").strip()
    try:
        return round(float(cleaned), 2)
    except ValueError:
        return None


def extract_amount(text: str) -> Optional[float]:
    # "amount" = subtotal BEFORE tax. Look for "Subtotal" first.
    raw = find_first(r"sub\s*-?\s*total\s*[:\-]?\s*(?:rs\.?|inr|₹|\$|usd|eur|€)?\s*([\d,]+\.?\d*)", text)
    if raw is None:
        # Fallback: some invoices just say "Amount:" for the pre-tax value
        raw = find_first(r"amount\s*[:\-]\s*(?:rs\.?|inr|₹|\$|usd|eur|€)?\s*([\d,]+\.?\d*)", text)
    return _money_to_float(raw)


def extract_tax(text: str) -> Optional[float]:
    # Covers "GST (18%): Rs. 395.82", "Tax: 395.82", "VAT: 395.82"
    raw = find_first(r"(?:gst|vat|tax)[^:\n\r]*[:\-]\s*(?:rs\.?|inr|₹|\$|usd|eur|€)?\s*([\d,]+\.?\d*)", text)
    return _money_to_float(raw)


def extract_currency(text: str) -> Optional[str]:
    if re.search(r"rs\.?|inr|₹", text, re.IGNORECASE):
        return "INR"
    if re.search(r"\$|usd", text, re.IGNORECASE):
        return "USD"
    if re.search(r"€|eur\b", text, re.IGNORECASE):
        return "EUR"
    if re.search(r"£|gbp", text, re.IGNORECASE):
        return "GBP"
    return None

@app.post("/extract")
def extract(req: InvoiceRequest):
    text = req.invoice_text

    return {
        "invoice_no": extract_invoice_no(text),
        "date": extract_date(text),
        "vendor": extract_vendor(text),
        "amount": extract_amount(text),
        "tax": extract_tax(text),
        "currency": extract_currency(text),
    }


