"""
features.py
------------
Extracts lexical / structural / brand-similarity features from a URL.
No live network calls are required (fast, offline, real-time capable).

v2: expanded from the original ~20 features to ~38, adding typosquatting
distance, punycode/homoglyph detection, suspicious file extensions,
redirect-parameter detection, character-composition anomalies, and more.
"""

import re
import math
from urllib.parse import urlparse, unquote

# ----------------------------------------------------------------------
# Reference lists
# ----------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "update",
    "confirm", "banking", "signin", "sign-in", "password", "pay",
    "paypal", "billing", "suspend", "unlock", "alert", "security",
    "wallet", "click", "urgent", "free", "bonus", "gift", "recover",
    "authenticate", "reset", "invoice", "refund",
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "club", "work", "click", "link", "gq", "tk", "ml",
    "cf", "ga", "buzz", "monster", "loan", "men", "date", "review",
    "win", "bid", "download", "stream", "icu", "cam", "rest", "quest",
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc",
]

BRAND_DOMAINS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "netflix.com", "chase.com",
    "wellsfargo.com", "irs.gov", "outlook.com", "linkedin.com",
    "whatsapp.com", "coinbase.com", "bankofamerica.com", "dhl.com",
    "usps.com", "fedex.com", "ebay.com", "adobe.com", "dropbox.com",
]
BRAND_NAMES = sorted({d.split(".")[0] for d in BRAND_DOMAINS})

SUSPICIOUS_FILE_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".zip", ".apk", ".jar", ".vbs", ".msi", ".cmd",
]

REDIRECT_PARAM_NAMES = ["redirect", "url", "next", "continue", "dest",
                         "destination", "target", "return", "returnurl", "goto"]

HOMOGLYPH_CHARS = set("аеорсухАВЕКМНОРСТХ")  # common Cyrillic look-alikes


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _count_digits(s: str) -> int:
    return sum(c.isdigit() for c in s)


def _has_ip_address(host: str) -> bool:
    ipv4 = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ipv4, host.split(":")[0]))


def _min_brand_distance(domain: str):
    """Returns (closest_brand, edit_distance) — small distance to a known
    brand while NOT being that brand's real domain = typosquatting signal."""
    best_brand, best_dist = None, 99
    for brand_domain in BRAND_DOMAINS:
        d = _levenshtein(domain, brand_domain)
        if d < best_dist:
            best_dist, best_brand = d, brand_domain
    return best_brand, best_dist


def _case_switches(s: str) -> int:
    """Counts lower->upper or upper->lower transitions (URLs with random
    capitalization are unusual and often auto-generated)."""
    switches = 0
    for a, b in zip(s, s[1:]):
        if a.isalpha() and b.isalpha() and a.islower() != b.islower():
            switches += 1
    return switches


def extract_features(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    full_lower = url.lower()
    decoded_url = unquote(url)

    labels = host.split(".") if host else []
    tld = labels[-1] if len(labels) >= 2 else ""
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    subdomain_count = len(subdomain_labels)

    closest_brand, brand_edit_distance = _min_brand_distance(domain)
    is_typosquat = int(0 < brand_edit_distance <= 3 and domain != closest_brand)

    features = {
        # --- basic length / structure ---
        "url_length": len(url),
        "hostname_length": len(host),
        "domain_length": len(domain),
        "tld_length": len(tld),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": _count_digits(url),
        "num_params": query.count("&") + (1 if query else 0),
        "num_subdomains": subdomain_count,
        "num_special_chars": len(re.findall(r"[~!$%^*()+=\[\]{}|;:'\",<>?]", url)),

        # --- hosting / obfuscation red flags ---
        "has_ip_address": int(_has_ip_address(host)),
        "has_at_symbol": int("@" in url),
        "has_https": int(parsed.scheme == "https"),
        "has_port": int(bool(re.search(r":\d+$", parsed.netloc))),
        "is_shortened": int(any(s in host for s in SHORTENER_DOMAINS)),
        "has_punycode": int("xn--" in host),
        "has_homoglyph": int(any(c in HOMOGLYPH_CHARS for c in url)),
        "has_encoded_chars": int("%" in url),
        "url_decoded_differs": int(decoded_url != url),
        "double_slash_redirect": int("//" in path),
        "https_ip_conflict": int(parsed.scheme == "https" and _has_ip_address(host)),

        # --- content / semantic signals ---
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "keyword_count": sum(1 for k in SUSPICIOUS_KEYWORDS if k in full_lower),
        "brand_mentioned": int(any(b in full_lower for b in BRAND_NAMES)),
        "brand_impersonation": int(
            any(b in full_lower for b in BRAND_NAMES) and domain not in BRAND_DOMAINS
        ),
        "is_typosquat": is_typosquat,
        "brand_edit_distance": brand_edit_distance if brand_edit_distance <= 10 else 10,
        "has_redirect_param": int(
            any(p in query.lower() for p in REDIRECT_PARAM_NAMES)
        ),
        "suspicious_file_extension": int(
            any(path.lower().endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS)
        ),

        # --- statistical / anomaly signals ---
        "host_entropy": round(_shannon_entropy(host), 3),
        "digit_letter_ratio": round(
            _count_digits(host) / max(len(host) - _count_digits(host), 1), 3
        ),
        "case_switch_count": _case_switches(url),
        "hyphen_in_domain": int("-" in domain),
        "consecutive_digit_run": max(
            (len(m) for m in re.findall(r"\d+", host)), default=0
        ),
        "www_not_at_start": int(
            "www" in full_lower and not full_lower.replace("http://", "").replace("https://", "").startswith("www")
        ),
        "long_subdomain_chain": int(subdomain_count >= 3),
    }
    return features


def explain_features(feat: dict, url: str) -> list:
    reasons = []
    if feat["has_ip_address"]:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if feat["suspicious_tld"]:
        reasons.append("Uses an untrusted / high-abuse top-level domain (TLD)")
    if feat["num_hyphens"] >= 3:
        reasons.append("Excessive hyphens in the URL")
    if feat["keyword_count"] >= 2:
        reasons.append("Contains multiple login/verification-related keywords")
    elif feat["keyword_count"] == 1:
        reasons.append("Contains a login/verification-related keyword")
    if feat["is_typosquat"]:
        reasons.append(f"Domain looks like a typosquat of a known brand (edit distance {feat['brand_edit_distance']})")
    if feat["brand_impersonation"]:
        reasons.append("Mentions a well-known brand outside the real domain (brand impersonation)")
    if feat["has_punycode"]:
        reasons.append("Domain uses punycode (xn--), often used to spoof look-alike characters")
    if feat["has_homoglyph"]:
        reasons.append("Contains look-alike (homoglyph) characters that mimic Latin letters")
    if feat["has_at_symbol"]:
        reasons.append("Contains '@' symbol, which can hide the real destination")
    if feat["is_shortened"]:
        reasons.append("Uses a URL shortening service, hiding the real destination")
    if feat["has_redirect_param"]:
        reasons.append("Contains a redirect-style parameter (e.g. url=, redirect=) that can forward to another site")
    if feat["suspicious_file_extension"]:
        reasons.append("Links directly to an executable/archive file — possible malware delivery")
    if not feat["has_https"]:
        reasons.append("Does not use HTTPS")
    if feat["https_ip_conflict"]:
        reasons.append("Uses HTTPS with a raw IP address, an unusual combination")
    if feat["num_subdomains"] >= 3:
        reasons.append("Unusually large number of subdomains")
    if feat["host_entropy"] >= 3.8:
        reasons.append("Domain name looks randomly generated (high entropy)")
    if feat["url_length"] >= 75:
        reasons.append("Unusually long URL")
    if feat["double_slash_redirect"]:
        reasons.append("Contains a suspicious '//' redirect pattern in the path")
    if feat["case_switch_count"] >= 4:
        reasons.append("Unusual mixed-case pattern in the URL")
    if feat["url_decoded_differs"] and feat["has_encoded_chars"]:
        reasons.append("URL contains encoded characters that reveal a different destination when decoded")
    if not reasons:
        reasons.append("No major red flags detected in URL structure")
    return reasons
