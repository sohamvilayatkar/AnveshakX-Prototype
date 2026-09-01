from typing import List, Dict, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from ml.preprocessing.text_cleaner import TextCleaner

# Known Threat Campaign Signatures for correlation
KNOWN_CAMPAIGN_SIGNATURES = [
    {
        "campaign_id": "CAMP-2026-BEC-EXEC",
        "campaign_name": "Executive Acquisition Wire Fraud Cluster",
        "reference_text": "confidential executive board acquisition meeting wire transfer closing payment beneficiary bank account instructions",
        "target_industries": ["Enterprise Finance", "Banking", "Corporate Treasury"],
        "shared_traits": ["Urgent Wire Request", "CEO Impersonation Pretext", "Confidentiality Restriction"]
    },
    {
        "campaign_id": "CAMP-2026-PHISH-BANK",
        "campaign_name": "Banking Suspension Credential Harvester",
        "reference_text": "unauthorized login attempts online banking suspended verify credentials security questions account deactivation",
        "target_industries": ["Retail Banking", "Financial Services"],
        "shared_traits": ["Lookalike Bank Portal", "24-Hour Suspension Threat", "Credential Harvesting Form"]
    },
    {
        "campaign_id": "CAMP-2026-M365-MALWARE",
        "campaign_name": "Microsoft 365 Overdue Invoice Dropper",
        "reference_text": "microsoft 365 licensing renewal overdue invoice action required past due balance attached document invoice scan",
        "target_industries": ["Corporate IT", "Accounting"],
        "shared_traits": ["Double Extension Payload", "M365 Impersonation", "Service Termination Pretext"]
    }
]


class CampaignSimilarityMatcher:
    """
    Campaign & Historical Case Similarity Matcher:
    Computes TF-IDF cosine semantic similarity against known threat campaigns
    and past cases, explaining common infrastructure and linguistic traits.
    """

    @classmethod
    def match_campaigns(
        cls,
        subject: str = "",
        body_text: str = "",
        body_html: str = "",
        past_cases: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        clean_target = TextCleaner.extract_clean_text(subject, body_text, body_html)
        if not clean_target:
            return []

        corpus = [clean_target]
        campaign_meta = []

        # Add known campaign signatures
        for camp in KNOWN_CAMPAIGN_SIGNATURES:
            corpus.append(TextCleaner._clean_raw_text(camp["reference_text"]))
            campaign_meta.append({
                "type": "KNOWN_CAMPAIGN",
                "id": camp["campaign_id"],
                "name": camp["campaign_name"],
                "shared_traits": camp["shared_traits"]
            })

        # Add past cases if available
        if past_cases:
            for c in past_cases:
                c_text = f"{c.get('subject', '')} {c.get('body_text_preview', '')}"
                cleaned_c = TextCleaner._clean_raw_text(c_text)
                if cleaned_c:
                    corpus.append(cleaned_c)
                    campaign_meta.append({
                        "type": "PAST_CASE",
                        "id": c.get("case_id", "CASE-PREV"),
                        "name": f"Investigation {c.get('case_id')}",
                        "shared_traits": ["Similar Email Structure", f"Class: {c.get('classification', 'Threat')}"]
                    })

        try:
            vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
            tfidf_mat = vectorizer.fit_transform(corpus)
            similarities = cosine_similarity(tfidf_mat[0:1], tfidf_mat[1:])[0]

            matches = []
            for meta, sim in zip(campaign_meta, similarities):
                sim_score = round(float(sim), 2)
                # Keep matches with meaningful semantic overlap (>= 0.15)
                if sim_score >= 0.15:
                    matches.append({
                        "campaign_id": meta["id"],
                        "campaign_name": meta["name"],
                        "type": meta["type"],
                        "similarity_score": sim_score,
                        "similarity_percent": int(round(sim_score * 100)),
                        "shared_traits": meta["shared_traits"]
                    })

            # Sort by highest similarity
            matches.sort(key=lambda x: x["similarity_score"], reverse=True)
            return matches[:4]
        except Exception:
            return []
