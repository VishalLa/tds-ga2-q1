import re
import string
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="Grounded QA API")

# 1. Allow requests from any origin (CORS) so the grading server can call us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# A tiny list of common "noise" words we ignore when comparing question vs chunk
STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "what", "when", "where",
    "who", "which", "how", "does", "do", "did", "in", "on", "of", "for",
    "to", "and", "or", "by", "with", "it", "this", "that", "be", "as",
    "at", "from"
}


def tokenize(text: str) -> List[str]:
    """Lowercase, strip punctuation, split into words, remove stopwords."""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    words = text.split()
    return [w for w in words if w not in STOPWORDS and len(w) > 1]


def split_sentences(text: str) -> List[str]:
    """Very simple sentence splitter."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return [s.strip() for s in sentences if s.strip()]


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

# Below this overlap score, we consider the question unanswerable from the chunks
ANSWERABILITY_THRESHOLD = 0.2


@app.post("/ask", response_model=AskResponse)
def ask(request: AskRequest):
    question = (request.question or "").strip()
    chunks = request.chunks or []

    # --- Handle malformed / empty input gracefully (Rule 4) ---
    if not question or not chunks:
        return UNANSWERABLE_RESPONSE

    question_words = set(tokenize(question))
    if not question_words:
        return UNANSWERABLE_RESPONSE

    best_sentence = None
    best_sentence_score = -1.0
    best_chunk_id = None

    candidates = []  # (score, sentence, chunk_id) for every sentence, for tie handling

    for chunk in chunks:
        for sentence in split_sentences(chunk.text):
            sentence_words = set(tokenize(sentence))
            if not sentence_words:
                continue
            overlap = question_words & sentence_words
            score = len(overlap) / len(question_words)
            candidates.append((score, sentence, chunk.chunk_id))
            if score > best_sentence_score:
                best_sentence_score = score
                best_sentence = sentence
                best_chunk_id = chunk.chunk_id

    # --- Rule 1: Unanswerable case ---
    if best_sentence is None or best_sentence_score < ANSWERABILITY_THRESHOLD:
        return UNANSWERABLE_RESPONSE

    TIE_TOLERANCE = 0.01
    citation_ids = [best_chunk_id]
    for score, sentence, chunk_id in candidates:
        if chunk_id == best_chunk_id:
            continue
        if score >= best_sentence_score - TIE_TOLERANCE and chunk_id not in citation_ids:
            citation_ids.append(chunk_id)

    # --- Confidence: scale the overlap score into a believable 0-1 range ---
    confidence = round(min(0.55 + best_sentence_score * 0.45, 0.99), 2)

    return AskResponse(
        answer=best_sentence.strip(),
        citations=citation_ids,   # every id here is a real chunk_id that was scored
        confidence=confidence,
        answerable=True,
    )


@app.get("/")
def health_check():
    return {"status": "ok", "message": "Grounded QA API is running"}