"""Shannon Information Entropy & Lexical Analytics Engine.

Computes exact statistical entropy of domain names to detect Domain Generation
Algorithms (DGA) used by botnets, command-and-control (C2) servers, and malware.
"""

import math
from collections import Counter
from typing import Dict, Any


def calculate_shannon_entropy(domain_string: str) -> float:
    """Calculate Shannon Entropy in bits per character.

    Formula: H(X) = - sum( P(x_i) * log2( P(x_i) ) )
    - Legitimate brand domains: ~2.2 - 3.4 bits/char
    - DGA Malware / Botnet domains: > 3.8 - 4.8 bits/char
    """
    clean_domain = domain_string.split(".")[0].lower()
    if not clean_domain:
        return 0.0

    length = len(clean_domain)
    char_counts = Counter(clean_domain)

    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def extract_lexical_features(domain: str) -> Dict[str, Any]:
    """Extract lexical metrics: entropy, digit ratio, consecutive consonants, hyphen count."""
    parts = domain.lower().split(".")
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    tld = parts[-1] if len(parts) >= 2 else ""

    entropy = calculate_shannon_entropy(sld)

    digits = sum(c.isdigit() for c in sld)
    vowels = sum(c in "aeiou" for c in sld)
    hyphens = sld.count("-")
    length = len(sld)

    digit_ratio = digits / max(length, 1)
    vowel_ratio = vowels / max(length, 1)

    is_dga_suspect = (entropy > 3.8 and length >= 10) or (digit_ratio > 0.35 and length >= 8)

    return {
        "full_domain": domain,
        "sld": sld,
        "tld": tld,
        "subdomain": subdomain,
        "entropy": entropy,
        "length": length,
        "digit_ratio": round(digit_ratio, 3),
        "vowel_ratio": round(vowel_ratio, 3),
        "hyphen_count": hyphens,
        "is_dga_suspect": is_dga_suspect
    }
