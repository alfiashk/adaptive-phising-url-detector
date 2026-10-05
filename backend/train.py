import os
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from backend.constants import LEGITIMATE_LABEL, MODEL_FEATURES, PHISHING_LABEL
from backend.feature_extractor import extract_url_features

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
FEEDBACK_PATH = os.path.join(BASE_DIR, "model", "feedback.csv")


def _valid_url(value: object) -> bool:
    url = str(value).strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _features_from_urls(urls: pd.Series) -> pd.DataFrame:
    return pd.DataFrame(
        [extract_url_features(str(url)) for url in urls],
        columns=MODEL_FEATURES,
    )


def train_model(feedback_path: str | None = None):
    feedback_path = feedback_path or FEEDBACK_PATH
    df = pd.read_csv(DATASET_PATH, usecols=["URL", "label"])
    df = df.rename(columns={"label": "Label"})

    if feedback_path and os.path.exists(feedback_path):
        feedback = pd.read_csv(feedback_path, usecols=["url", "label"])
        feedback = feedback.rename(columns={"url": "URL", "label": "Label"})
        feedback = feedback[feedback["URL"].map(_valid_url)]
        df = pd.concat([df, feedback], ignore_index=True)

    if not set(df["Label"].unique()).issubset({PHISHING_LABEL, LEGITIMATE_LABEL}):
        raise ValueError("Labels must be 0 (phishing) or 1 (legitimate)")

    X = _features_from_urls(df["URL"])
    y = df["Label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
    print(classification_report(y_test, predictions))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model


if __name__ == "__main__":
    trained_model = train_model()
    print(f"Model saved to {MODEL_PATH}")
    print("classes_:", trained_model.classes_)
    print("n_features_in_:", trained_model.n_features_in_)