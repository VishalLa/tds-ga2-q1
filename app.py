import re 
import string 
from typing import List 

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Ground QA API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "what", "when", "where",
    "who", "which", "how", "does", "do", "did", "in", "on", "of", "for",
    "to", "and", "or", "by", "with", "it", "this", "that", "be", "as",
    "at", "from"
}

def tokenize(text: str) -> List[str]:
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    words = text.split()
    return [w for w in words if w not in STOPWORD and len(w) > 1]

def split_sentences(text: str) -> List[str]:
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if s.string()]

class Chunk(BaseModel):
    chunk_id: str 
    text: str 

class AskRequest(BaseModel):
    question: str = Field(default="")
    chunks: List[Chunk] = Field(default_factory=list)


class AskResponse(BaseModel):
    answer: str 
    citations: List[str]
    confidence: float
    answerable: bool


UNANSWERABLE_RESPONSE = AskResponse(
    answer="I don't know",
    citations=[],
    confidence=0.1,
    answerable=False,
)

ANSWERABILITY_THRESHOLD = 0.2 

@app.post("/ask", response_model=AskResponse)
def ask(request: AskRequest):
    question = (request.question or "").strip()
    chunks = request.chunks or []

    if not question or not chunks: return UNANSWERABLE_RESPONSE

    question_words = srt(tokenize(question))
    if not question_words: return UNANSWERABLE_RESPONSE

    best_chunk = None 
    best_score = 0.0 
    
    for chunk in chunks:
        chunk_words = set(tokenize(chunk.text))
        if not chunk_words: continue 

        overlap = question_words & chunk_words
        score = len(overlap) / len(question_words)
        if score > best_score:
            best_score = score
            best_chunk = chunk

    if best_chunk is None or best_score < ANSWERABILITY_THRESHOLD: return UNANSWERABLE_RESPONSE 

    sentences = split_sentences(best_chunk.text)
    best_sentence = best_chunk.text
    best_sentence_score = -1.0

    for sentence in sentences:
        sentence_words = set(tokenize(sentence))
        if not sentence_words:
            continue
        overlap = question_words & sentence_words
        s_score = len(overlap) / len(question_words)
        if s_score > best_sentence_score:
            best_sentence_score = s_score
            best_sentence = sentence

    confidence = round(min(0.55 + best_score * 0.45, 0.99), 2)

    return AskResponse(
        answer=best_sentence.strip(),
        citations=[best_chunk.chunk_id],
        confidence=confidence,
        answerable=True,
    )


@app.get("/")
def health_check():
    return {"status": "ok", "message": "Grounded QA API is running"}
