import os
import secrets
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from backend.feedback import add_feedback
from backend.predict import predict_url

load_dotenv()

app = FastAPI(title="Adaptive Phishing URL Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Key"],
)


class PredictRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class FeedbackRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    label: int = Field(ge=0, le=1)


@app.get("/")
def root():
    return {"message": "Adaptive Phishing URL Detection API"}


@app.post("/predict")
def predict(data: PredictRequest):
    return predict_url(data.url)


@app.post("/feedback")
def feedback(data: FeedbackRequest, x_admin_key: str | None = Header(default=None)):
    configured_key = os.getenv("ADMIN_API_KEY")
    if not configured_key:
        raise HTTPException(status_code=503, detail="Admin feedback is not configured")
    if not x_admin_key or not secrets.compare_digest(x_admin_key, configured_key):
        raise HTTPException(status_code=401, detail="Invalid admin key")

    parsed = urlparse(data.url if "://" in data.url else f"http://{data.url}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="url must be a valid HTTP or HTTPS URL")

    add_feedback(data.url, data.label)
    return {"message": "Feedback saved and model retrained"}