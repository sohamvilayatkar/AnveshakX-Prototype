import os
import json
from typing import List, Dict, Tuple, Optional
import pandas as pd


class DatasetLoader:
    """
    Dataset loader supporting JSON, CSV, and Parquet formats for multi-class
    email threat detection (legitimate, phishing, bec, credential_theft, financial_fraud).
    """

    DEFAULT_DATASET_PATH = os.path.join(
        os.path.dirname(__file__), "synthetic_email_corpus.json"
    )

    @classmethod
    def load_corpus(cls, file_path: Optional[str] = None) -> pd.DataFrame:
        target_path = file_path or cls.DEFAULT_DATASET_PATH

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Dataset corpus file not found at: {target_path}")

        if target_path.endswith(".json"):
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            df = pd.DataFrame(data)
        elif target_path.endswith(".csv"):
            df = pd.read_csv(target_path)
        elif target_path.endswith(".parquet"):
            df = pd.read_parquet(target_path)
        else:
            raise ValueError(f"Unsupported dataset format: {target_path}")

        # Normalize columns: expect 'subject', 'body', 'label' or 'text', 'label'
        if "text" not in df.columns:
            if "subject" in df.columns and "body" in df.columns:
                df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
            elif "body" in df.columns:
                df["text"] = df["body"].fillna("")
            elif "subject" in df.columns:
                df["text"] = df["subject"].fillna("")
            else:
                raise ValueError("Dataset must contain either 'text' or 'subject'/'body' columns.")

        # Clean labels
        df["label"] = df["label"].astype(str).str.strip().str.lower()
        df = df.dropna(subset=["text", "label"])
        df = df.drop_duplicates(subset=["text"])

        return df
