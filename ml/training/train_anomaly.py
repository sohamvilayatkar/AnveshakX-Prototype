import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
ANOMALY_MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_detector.joblib")


def train_anomaly_detector():
    """Train an unsupervised Isolation Forest anomaly detector on email structural profiles."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Feature matrix shape: [text_len, url_count, att_count, recipient_count, relay_count, urgency_sig, financial_sig]
    # Synthetic baseline of normal & abnormal patterns
    normal_data = [
        [350, 1, 0, 1, 2, 0.1, 0.0],
        [420, 2, 1, 2, 2, 0.0, 0.0],
        [600, 0, 0, 1, 3, 0.2, 0.1],
        [280, 1, 0, 3, 2, 0.0, 0.0],
        [510, 2, 1, 1, 2, 0.1, 0.2],
        [800, 1, 1, 4, 3, 0.0, 0.0],
        [300, 1, 0, 1, 2, 0.0, 0.0]
    ]

    anomaly_samples = [
        [150, 8, 3, 1, 1, 0.95, 0.9],
        [1200, 12, 4, 15, 6, 0.8, 0.7],
        [90, 0, 2, 1, 1, 0.9, 0.95]
    ]

    X = np.array(normal_data + anomaly_samples)

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.2,
        random_state=42
    )

    iso_forest.fit(X)
    joblib.dump(iso_forest, ANOMALY_MODEL_PATH)
    print(f"Anomaly detector model saved to: {ANOMALY_MODEL_PATH}")
    return iso_forest


if __name__ == "__main__":
    train_anomaly_detector()
