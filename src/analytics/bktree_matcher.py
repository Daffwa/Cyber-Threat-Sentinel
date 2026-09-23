"""BK-Tree (Burkhard-Keller Tree) & Levenshtein Metric Tree Engine.

Enables sub-millisecond O(log N) fuzzy string matching across protected
Indonesian and global brand targets to detect typosquatting and brand impersonation.
"""

from typing import Dict, List, Optional, Tuple

PROTECTED_BRANDS = [
    # Indonesian Banks & Financial Institutions
    "bca", "klikbca", "mybca", "mandiri", "livin", "bri", "brimo", "bni", "cimb",
    "octomobile", "permata", "bsi", "danamon", "panin", "bankdki", "bankbjb",
    # Indonesian Fintech & E-Wallets
    "gopay", "ovo", "dana", "shopeepay", "linkaja", "kredivo", "akulaku", "spaylater",
    # Indonesian E-Commerce & Retail
    "tokopedia", "shopee", "bukalapak", "blibli", "lazada", "traveloka", "tiket",
    # Indonesian Telco & Crypto
    "telkomsel", "indosat", "myxl", "smartfren", "indodax", "tokocrypto", "pintu",
    # Global Targets
    "google", "microsoft", "paypal", "apple", "netflix", "binance", "coinbase", "facebook", "whatsapp"
]

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "vv": "w"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class BKNode:
    """Node in Burkhard-Keller Tree."""
    def __init__(self, word: str):
        self.word = word
        self.children: Dict[int, 'BKNode'] = {}


class BKTree:
    """Discrete metric tree based on triangle inequality d(x, z) <= d(x, y) + d(y, z)."""

    def __init__(self, words: List[str] = PROTECTED_BRANDS):
        self.root: Optional[BKNode] = None
        for word in words:
            self.add(word)

    def add(self, word: str):
        if not self.root:
            self.root = BKNode(word)
            return

        curr = self.root
        while True:
            dist = levenshtein_distance(word, curr.word)
            if dist == 0:
                return  # Duplicate word
            if dist in curr.children:
                curr = curr.children[dist]
            else:
                curr.children[dist] = BKNode(word)
                break

    def search(self, query: str, max_distance: int = 2) -> List[Tuple[str, int]]:
        """Query words within max_distance in O(log N) operations."""
        if not self.root:
            return []

        results = []
        candidates = [self.root]

        while candidates:
            node = candidates.pop()
            dist = levenshtein_distance(query, node.word)

            if dist <= max_distance:
                results.append((node.word, dist))

            # Triangle inequality pruning
            low = dist - max_distance
            high = dist + max_distance

            for d, child in node.children.items():
                if low <= d <= high:
                    candidates.append(child)

        return sorted(results, key=lambda x: x[1])


def normalize_homoglyphs(text: str) -> str:
    """Convert common visual phishing homoglyphs (e.g. sh0pee -> shopee)."""
    normalized = text.lower()
    for char, replacement in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(char, replacement)
    return normalized


def match_brand_impersonation(domain: str, bktree: BKTree) -> Optional[Dict[str, Any]]:
    """Detect brand targeting using sub-string, homoglyph, and BK-Tree search."""
    clean_domain = domain.lower().split(".")[0]
    norm_domain = normalize_homoglyphs(clean_domain)

    # 1. Direct Substring Check (e.g., 'klikbca-update', 'login-mandiri-secure')
    for brand in PROTECTED_BRANDS:
        if brand in clean_domain or brand in norm_domain:
            dist = 0 if clean_domain == brand else 1
            return {
                "matched_brand": brand,
                "match_type": "SUBSTRING_IMPERSONATION" if dist > 0 else "EXACT",
                "distance": dist,
                "similarity_ratio": 1.0 if dist == 0 else 0.85
            }

    # 2. Sub-words token check (hyphenated e.g. bca-auth)
    tokens = clean_domain.replace("_", "-").split("-")
    for token in tokens:
        if len(token) >= 3:
            hits = bktree.search(token, max_distance=1)
            if hits:
                brand, dist = hits[0]
                return {
                    "matched_brand": brand,
                    "match_type": "TYPOSQUATTING",
                    "distance": dist,
                    "similarity_ratio": round(1.0 - (dist / max(len(brand), 1)), 2)
                }

    # 3. Overall SLD Levenshtein Search (edit distance <= 2)
    if len(clean_domain) >= 4:
        hits = bktree.search(clean_domain, max_distance=2)
        if hits:
            brand, dist = hits[0]
            # Avoid short-string false positive (e.g. 'cat' vs 'bca')
            if len(brand) >= 4 or dist <= 1:
                return {
                    "matched_brand": brand,
                    "match_type": "TYPOSQUATTING",
                    "distance": dist,
                    "similarity_ratio": round(1.0 - (dist / max(len(brand), 1)), 2)
                }

    return None
