import csv
import os

from backend.predict import reload_model
from backend.train import train_model

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDBACK_PATH = os.path.join(BASE_DIR, "model", "feedback.csv")


def add_feedback(url: str, label: int):
    os.makedirs(os.path.dirname(FEEDBACK_PATH), exist_ok=True)
    file_exists = os.path.exists(FEEDBACK_PATH)

    with open(FEEDBACK_PATH, "a", newline="", encoding="utf-8") as feedback_file:
        writer = csv.DictWriter(feedback_file, fieldnames=["url", "label"])
        if not file_exists:
            writer.writeheader()
        writer.writerow({"url": url.strip(), "label": label})

    model = train_model(FEEDBACK_PATH)
    reload_model()
    return model