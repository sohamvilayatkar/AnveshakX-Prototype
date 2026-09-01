import os
import json
from datetime import datetime, timezone
import joblib
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

from ml.datasets.dataset_loader import DatasetLoader
from ml.preprocessing.text_cleaner import TextCleaner


MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PIPELINE_PATH = os.path.join(MODEL_DIR, "email_classifier_pipeline.joblib")
MODEL_METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def train_classifier():
    """Train the primary multi-class TF-IDF + Logistic Regression threat detector."""
    os.makedirs(MODEL_DIR, exist_ok=True)
    print("Loading email training dataset...")
    df = DatasetLoader.load_corpus()

    # Preprocess all texts
    df["cleaned_text"] = df["text"].apply(TextCleaner._clean_raw_text)

    X = df["cleaned_text"].values
    y = df["label"].values

    classes = sorted(list(set(y)))
    print(f"Training on {len(X)} samples across {len(classes)} classes: {classes}")

    # Build Pipeline with English stop words and tuned regularization
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            stop_words="english",
            min_df=1,
            max_features=5000,
            token_pattern=r'(?u)\b[a-zA-Z]{2,}\b|\$[\d,]+'
        )),
        ("clf", LogisticRegression(
            C=8.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ))
    ])

    print("Fitting TF-IDF and Logistic Regression classifier...")
    pipeline.fit(X, y)

    # Evaluate
    y_pred = pipeline.predict(X)
    acc = accuracy_score(y, y_pred)
    report = classification_report(y, y_pred, output_dict=True, zero_division=0)

    print(f"Model Training Complete! Training Accuracy: {acc * 100:.2f}%")

    # Serialize Model Pipeline
    joblib.dump(pipeline, MODEL_PIPELINE_PATH)
    print(f"Model saved to: {MODEL_PIPELINE_PATH}")

    # Save Model Metadata
    metadata = {
        "model_name": "anveshakx-email-classifier",
        "model_version": "v2.0",
        "algorithm": "TF-IDF (1-2 ngrams) + Calibrated Logistic Regression",
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(X),
        "classes": classes,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_avg_f1": round(report.get("macro avg", {}).get("f1-score", 1.0), 4)
        }
    }

    with open(MODEL_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Metadata saved to: {MODEL_METADATA_PATH}")
    return pipeline, metadata


if __name__ == "__main__":
    train_classifier()
