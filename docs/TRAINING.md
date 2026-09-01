# AnveshakX ML Training & Evaluation Guide

This guide details how to prepare datasets, train the multi-class classifier and anomaly detector, and run model evaluation.

---

## 1. Dataset Preparation

The training pipeline loads datasets from `ml/datasets/synthetic_email_corpus.json` supporting JSON, CSV, and Parquet formats.

Expected structure:
```json
[
  {
    "subject": "Email Subject Line",
    "body": "Raw email body content...",
    "label": "bec"
  }
]
```

Supported classes:
- `legitimate`
- `phishing`
- `bec`
- `credential_theft`
- `financial_fraud`

---

## 2. Training the Threat Classifier

Run the training pipeline from the project root:

```bash
python -m ml.training.train_classifier
```

Outputs generated:
- Model Pipeline: `ml/models/email_classifier_pipeline.joblib`
- Model Metadata: `ml/models/model_metadata.json`

---

## 3. Training the Anomaly Detector

Train the unsupervised Isolation Forest structural model:

```bash
python -m ml.training.train_anomaly
```

Output generated:
- Anomaly Model: `ml/models/anomaly_detector.joblib`

---

## 4. Evaluating Model Performance

Run the comprehensive evaluation script:

```bash
python -m ml.evaluation.evaluate
```

This outputs:
- Overall Accuracy
- Precision, Recall, and F1-score per class
- Macro and Weighted Averages
- Complete Confusion Matrix
