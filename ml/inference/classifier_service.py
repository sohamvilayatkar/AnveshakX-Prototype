import os
import json
from typing import Dict, Any, Optional, List
import joblib

from ml.preprocessing.text_cleaner import TextCleaner
from ml.explainability.feature_importance import FeatureImportanceExplainer

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PIPELINE_PATH = os.path.join(MODEL_DIR, "email_classifier_pipeline.joblib")
MODEL_METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


class EmailClassifierService:
    """
    Inference Service for Primary Threat Classifier:
    Loads trained TF-IDF + Logistic Regression pipeline once and serves
    low-latency calibrated predictions with XAI feature importance.
    """
    _pipeline = None
    _metadata = None

    @classmethod
    def load_model(cls):
        if cls._pipeline is None:
            if os.path.exists(MODEL_PIPELINE_PATH):
                try:
                    cls._pipeline = joblib.load(MODEL_PIPELINE_PATH)
                    if os.path.exists(MODEL_METADATA_PATH):
                        with open(MODEL_METADATA_PATH, "r", encoding="utf-8") as f:
                            cls._metadata = json.load(f)
                    else:
                        cls._metadata = {
                            "model_name": "anveshakx-email-classifier",
                            "model_version": "v2.0",
                            "classes": list(cls._pipeline.named_steps["clf"].classes_)
                        }
                except Exception as e:
                    print(f"[Warning] Failed to load ML model from {MODEL_PIPELINE_PATH}: {e}")
                    cls._pipeline = None
            else:
                # If model hasn't been trained yet, train it on the fly
                from ml.training.train_classifier import train_classifier
                cls._pipeline, cls._metadata = train_classifier()

        return cls._pipeline, cls._metadata

    @classmethod
    def predict(
        cls,
        subject: str = "",
        body_text: str = "",
        body_html: str = ""
    ) -> Dict[str, Any]:
        pipeline, metadata = cls.load_model()
        cleaned_text = TextCleaner.extract_clean_text(subject, body_text, body_html)

        if not pipeline or not cleaned_text.strip():
            # Demo-safe fallback if text is empty
            return {
                "model_name": "anveshakx-email-classifier",
                "model_version": "v2.0",
                "classification": "legitimate",
                "confidence": 0.50,
                "probabilities": {
                    "legitimate": 0.50,
                    "phishing": 0.15,
                    "bec": 0.15,
                    "credential_theft": 0.10,
                    "financial_fraud": 0.10
                },
                "linguistic_signals": [],
                "status": "baseline_fallback"
            }

        try:
            probs = pipeline.predict_proba([cleaned_text])[0]
            classes = list(pipeline.named_steps["clf"].classes_)

            prob_dict = {cls_name: round(float(prob), 4) for cls_name, prob in zip(classes, probs)}
            best_class_idx = int(probs.argmax())
            predicted_class = classes[best_class_idx]
            raw_prob = float(probs[best_class_idx])

            # Multi-class calibrated confidence (accounting for 5-class baseline of 0.20)
            if raw_prob >= 0.40:
                calibrated_conf = round(min(0.95, 0.65 + (raw_prob - 0.40) * 0.60), 2)
            else:
                calibrated_conf = round(raw_prob, 2)

            # Extract XAI feature contributions
            linguistic_signals = FeatureImportanceExplainer.explain_prediction(
                pipeline, cleaned_text, predicted_class, top_k=6
            )

            # Map internal class names to clean UI classifications
            display_map = {
                "bec": "BUSINESS_EMAIL_COMPROMISE",
                "phishing": "CREDENTIAL_PHISHING",
                "credential_theft": "CREDENTIAL_THEFT",
                "financial_fraud": "FINANCIAL_WIRE_FRAUD",
                "legitimate": "LEGITIMATE_COMMUNICATION"
            }

            return {
                "model_name": metadata.get("model_name", "anveshakx-email-classifier"),
                "model_version": metadata.get("model_version", "v2.0"),
                "classification": display_map.get(predicted_class, predicted_class.upper()),
                "raw_class": predicted_class,
                "confidence": calibrated_conf,
                "probabilities": prob_dict,
                "linguistic_signals": linguistic_signals,
                "status": "active"
            }
        except Exception as e:
            print(f"[Error] ML inference error: {e}")
            return {
                "model_name": "anveshakx-email-classifier",
                "model_version": "v2.0",
                "classification": "UNCLASSIFIED",
                "confidence": 0.50,
                "probabilities": {},
                "linguistic_signals": [],
                "status": "inference_error"
            }
