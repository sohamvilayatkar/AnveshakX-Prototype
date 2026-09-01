from typing import List, Dict, Any, Tuple
import numpy as np


class FeatureImportanceExplainer:
    """
    Explainable AI (XAI) for Linear Models:
    Extracts the highest-impact linguistic features and n-grams driving the ML classification
    for a given input email.
    """

    @classmethod
    def explain_prediction(
        cls,
        pipeline: Any,
        cleaned_text: str,
        predicted_class: str,
        top_k: int = 6
    ) -> List[Dict[str, Any]]:
        try:
            tfidf = pipeline.named_steps["tfidf"]
            clf = pipeline.named_steps["clf"]

            feature_names = np.array(tfidf.get_feature_names_out())
            tfidf_vec = tfidf.transform([cleaned_text])

            # Get class index
            class_idx = list(clf.classes_).index(predicted_class)
            coefficients = clf.coef_[class_idx]

            # Multiply TF-IDF weights by model coefficients for this class
            dense_vec = tfidf_vec.toarray()[0]
            scores = dense_vec * coefficients

            # Find non-zero positive contributors
            active_indices = np.where(dense_vec > 0)[0]
            if len(active_indices) == 0:
                return []

            # Sort by highest positive contribution
            sorted_indices = active_indices[np.argsort(scores[active_indices])[::-1]]

            explanations = []
            for idx in sorted_indices[:top_k]:
                word = feature_names[idx]
                contrib = float(scores[idx])
                if contrib > 0.001:
                    explanations.append({
                        "token": word,
                        "weight": round(contrib, 3),
                        "description": f"Linguistic indicator '{word}' heavily influenced {predicted_class.upper()} classification."
                    })

            return explanations
        except Exception:
            return []
