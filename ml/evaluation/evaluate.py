import os
import json
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

from ml.datasets.dataset_loader import DatasetLoader
from ml.preprocessing.text_cleaner import TextCleaner
from ml.inference.classifier_service import EmailClassifierService


def run_evaluation():
    """Evaluate trained ML classifier pipeline against dataset corpus."""
    pipeline, metadata = EmailClassifierService.load_model()
    if pipeline is None:
        print("[Error] No trained model pipeline found.")
        return

    df = DatasetLoader.load_corpus()
    df["cleaned_text"] = df["text"].apply(TextCleaner._clean_raw_text)

    X = df["cleaned_text"].values
    y_true = df["label"].values

    y_pred = pipeline.predict(X)
    classes = sorted(list(set(y_true)))

    acc = accuracy_score(y_true, y_pred)
    report_dict = classification_report(y_true, y_pred, target_names=classes, output_dict=True, zero_division=0)
    report_text = classification_report(y_true, y_pred, target_names=classes, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=classes)

    print("=" * 65)
    print("ANVESHAKX ML MODEL EVALUATION REPORT")
    print(f"Model Name:    {metadata.get('model_name', 'anveshakx-email-classifier')}")
    print(f"Model Version: {metadata.get('model_version', 'v2.0')}")
    print(f"Total Samples: {len(X)}")
    print(f"Accuracy:      {acc * 100:.2f}%")
    print("=" * 65)
    print("\nClassification Report:\n")
    print(report_text)
    print("\nConfusion Matrix:")
    print(cm)
    print("=" * 65)

    return {
        "accuracy": acc,
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
        "classes": classes
    }


if __name__ == "__main__":
    run_evaluation()
