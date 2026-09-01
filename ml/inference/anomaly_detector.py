import os
import joblib
import numpy as np
from typing import Dict, Any

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
ANOMALY_MODEL_PATH = os.path.join(MODEL_DIR, "anomaly_detector.joblib")


class AnomalyDetectorService:
    """
    Unsupervised Anomaly Detector using Isolation Forest:
    Flags anomalous structural and behavioral profiles across email attributes.
    """
    _model = None

    @classmethod
    def load_model(cls):
        if cls._model is None:
            if os.path.exists(ANOMALY_MODEL_PATH):
                try:
                    cls._model = joblib.load(ANOMALY_MODEL_PATH)
                except Exception as e:
                    print(f"[Warning] Failed to load anomaly model: {e}")
                    cls._model = None
            else:
                from ml.training.train_anomaly import train_anomaly_detector
                cls._model = train_anomaly_detector()
        return cls._model

    @classmethod
    def evaluate(
        cls,
        text_len: int = 0,
        url_count: int = 0,
        attachment_count: int = 0,
        recipient_count: int = 1,
        relay_count: int = 2,
        urgency_score: float = 0.0,
        financial_score: float = 0.0
    ) -> Dict[str, Any]:
        model = cls.load_model()
        features = np.array([[
            text_len,
            url_count,
            attachment_count,
            recipient_count,
            relay_count,
            urgency_score,
            financial_score
        ]])

        if model is None:
            # Fallback heuristic
            is_anomaly = (urgency_score > 0.8 and financial_score > 0.8) or (url_count > 5) or (attachment_count > 2)
            score = 0.85 if is_anomaly else 0.20
        else:
            try:
                # isolation forest decision_function: lower is more abnormal (negative is anomaly)
                raw_score = model.decision_function(features)[0]
                prediction = model.predict(features)[0]  # -1 for anomaly, 1 for normal
                is_anomaly = bool(prediction == -1)

                # Normalize raw_score to 0.0 - 1.0 where 1.0 is most anomalous
                score = round(float(np.clip(0.5 - raw_score, 0.0, 1.0)), 2)
            except Exception:
                is_anomaly = (urgency_score > 0.8 and financial_score > 0.8)
                score = 0.75 if is_anomaly else 0.25

        explanations = []
        if urgency_score > 0.7:
            explanations.append("elevated urgency language")
        if financial_score > 0.7:
            explanations.append("unusual wire transfer instructions")
        if url_count > 3:
            explanations.append("high density of external hyperlinks")
        if attachment_count > 1:
            explanations.append("multiple file attachments")

        if is_anomaly and explanations:
            reason = f"Unusual email profile detected ({', '.join(explanations)})."
        elif is_anomaly:
            reason = "Statistical anomaly detected in structural transmission attributes."
        else:
            reason = "Email profile conforms to standard communication baselines."

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": score,
            "explanation": reason
        }
