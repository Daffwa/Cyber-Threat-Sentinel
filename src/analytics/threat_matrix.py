"""Multi-Dimensional Deterministic Cyber Threat Scoring Matrix.

Combines BK-Tree Levenshtein similarity, Shannon Entropy, TLD risk profiles,
and lexical security triggers to output calibrated threat scores in sub-milliseconds.
"""

import time
from typing import Dict, Any, Optional
from src.analytics.entropy_engine import extract_lexical_features
from src.analytics.bktree_matcher import BKTree, match_brand_impersonation

HIGH_RISK_TLDS = {
    "xyz": 1.2, "top": 1.3, "online": 1.0, "site": 1.0, "icu": 1.4,
    "cc": 1.1, "buzz": 1.3, "click": 1.2, "club": 0.8, "vip": 1.2
}

SUSPICIOUS_KEYWORDS = [
    # Indonesian Phishing Keywords
    "login", "masuk", "verifikasi", "otp", "rekening", "blokir", "pulsa", "kuota",
    "hadiah", "undian", "bantuan", "klaim", "pinjol", "bansos", "dana-kaget",
    # Global Phishing Keywords
    "secure", "verify", "account", "update", "portal", "auth", "support", "billing",
    "wallet", "claim", "airdrop", "recover", "security", "sign-in"
]


class ThreatMatrixEngine:
    """Sub-millisecond mathematical threat evaluator (Pure Big Data)."""

    def __init__(self):
        self.bktree = BKTree()

    def evaluate(self, domain: str, issuer_ca: str = "Unknown") -> Dict[str, Any]:
        """Evaluate domain threat posture deterministically."""
        start_time = time.time()
        lexical = extract_lexical_features(domain)
        brand_match = match_brand_impersonation(domain, self.bktree)

        clean_sld = lexical["sld"].lower()
        tld = lexical["tld"].lower()

        # 1. Base Score calculation
        score = 0.0
        threat_type = "BENIGN"
        confidence = 0.99
        matched_brand = brand_match["matched_brand"] if brand_match else "NONE"

        # Check Suspicious Keywords
        keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in clean_sld]

        # 2. Scenario Evaluation: Brand Impersonation / Phishing
        if brand_match:
            is_sub = (brand_match["match_type"] == "SUBSTRING_IMPERSONATION")
            is_typo = (brand_match["match_type"] == "TYPOSQUATTING")

            if is_sub:
                score += 3.5
                threat_type = "BRAND_IMPERSONATION"
                confidence = 0.965
            elif is_typo:
                score += 3.0
                threat_type = "TYPOSQUATTING"
                confidence = 0.920

            # Combined with phishing keywords (e.g. bca-login-verify.com)
            if keyword_hits:
                score += min(1.5, len(keyword_hits) * 0.8)
                confidence = min(0.995, confidence + 0.03)

            # Combined with High-Risk TLD (e.g. .xyz, .top)
            if tld in HIGH_RISK_TLDS:
                score += HIGH_RISK_TLDS[tld]

            # CA Anomaly: Free CA issuing cert for sensitive financial brand
            ca_lower = issuer_ca.lower()
            if any(free_ca in ca_lower for free_ca in ["let's encrypt", "cpanel", "zerossl", "r3"]):
                score += 0.5

        # 3. Scenario Evaluation: DGA Malware / Botnet C2
        elif lexical["is_dga_suspect"]:
            score += 3.8
            threat_type = "DGA_MALWARE_C2"
            confidence = 0.940
            if tld in HIGH_RISK_TLDS:
                score += 0.8

        # 4. Scenario Evaluation: Suspicious Standalone Phishing Keywords
        elif len(keyword_hits) >= 2:
            score += 2.8
            threat_type = "SCAM_PHISHING"
            confidence = 0.875

        # Clamp score between 0.0 and 5.0
        final_score = min(5.0, round(score, 2))

        # 5. Determine Autonomous Action
        if final_score >= 3.5 and confidence >= 0.90:
            action = "AUTO_SINKHOLE"
        elif final_score >= 2.0:
            action = "FLAGGED_SOC"
        else:
            action = "BENIGN"

        latency_ms = (time.time() - start_time) * 1000

        return {
            "domain": domain,
            "target_brand": matched_brand,
            "threat_type": threat_type,
            "threat_score": final_score,
            "confidence": round(confidence, 4),
            "action_taken": action,
            "shannon_entropy": lexical["entropy"],
            "levenshtein_dist": brand_match["distance"] if brand_match else None,
            "keyword_hits": keyword_hits,
            "tld": tld,
            "issuer_ca": issuer_ca,
            "processing_latency_ms": round(latency_ms, 3)
        }
