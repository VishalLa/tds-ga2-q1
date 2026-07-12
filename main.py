import os
import io 
import base64 
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from PIL import Image 
from google import genai
from google.genai import types
from dotenv import load_dotenv

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
    