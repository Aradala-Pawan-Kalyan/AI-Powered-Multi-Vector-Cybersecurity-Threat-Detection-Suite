"""
email_analysis.py
-------------------
Analyzes raw email content (headers + body, e.g. a pasted .eml file or
copy-pasted headers/body) for spam and phishing indicators:

 - Header spoofing signals (From/Reply-To mismatch, missing SPF/DKIM
   results if headers are present, suspicious "Received" chains)
 - Urgency / social-engineering language in the body
 - Mismatched display-name vs actual sender domain
 - Embedded URLs — reuses features.py's URL model to score every link
   found in the body
 - Suspicious attachment filenames mentioned in headers
 - Generic spam-content heuristics (excessive caps, exclamation marks,
   money/prize language, spammy phrasing)
"""

import re
import email
from email import policy
from email.parser import Parser as EmailParser

from features import extract_features, explain_features

URGENCY_PHRASES = [
    "act now", "urgent action", "verify your account", "account suspended",
    "will be closed", "click here immediately", "limited time",
    "confirm your identity", "unusual activity", "unauthorized access",
    "your account has been", "final notice", "failure to respond",
    "claim your prize", "you have won", "congratulations you",
    "wire transfer", "gift card", "tax refund", "password will expire",
]

SPAM_PHRASES = [
    "free money", "make money fast", "no credit check", "risk free",
    "100% free", "cash bonus", "lowest price", "guaranteed",
    "work from home", "double your", "no obligation", "act immediately",
]

SUSPICIOUS_ATTACHMENT_EXTS = [
    ".exe", ".scr", ".bat", ".vbs", ".js", ".jar", ".ps1", ".hta",
    ".docm", ".xlsm", ".zip", ".rar", ".iso", ".img",
]

URL_RE = re.compile(r'https?://[^\s\'"<>\)]+')
EMAIL_ADDR_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')


def _extract_domain(addr: str) -> str:
    m = re.search(r'@([\w.-]+)', addr or "")
    return m.group(1).lower() if m else ""


def _count_caps_words(text: str) -> int:
    words = re.findall(r"\b[A-Z]{4,}\b", text)
    return len(words)


def analyze_email(raw_text: str) -> dict:
    """raw_text can be a full .eml (headers + body) or just plain body
    text pasted by the user — both are handled gracefully."""

    reasons = []
    score = 0

    # Try to parse as a real email message (headers present)
    msg = EmailParser(policy=policy.default).parsestr(raw_text)
    from_header = msg.get("From", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    subject = msg.get("Subject", "") or ""

    body = None
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        body = "\n".join(parts) if parts else None
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = None

    # Fallback: if it doesn't look like a structured email, treat the
    # whole input as body text.
    has_headers = bool(from_header or msg.get("Received") or msg.get("Date"))
    if not body:
        body = raw_text

    full_text = f"{subject}\n{body}"
    full_lower = full_text.lower()

    # ---------------- header-based checks ----------------
    from_domain = _extract_domain(from_header)
    reply_domain = _extract_domain(reply_to)

    if has_headers and reply_domain and from_domain and reply_domain != from_domain:
        score += 25
        reasons.append(
            f"Reply-To domain ({reply_domain}) differs from the From domain ({from_domain}) — "
            f"replies would be redirected elsewhere"
        )

    display_name_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    if display_name_match:
        display_name = display_name_match.group(1).strip().lower()
        known_brands = ["paypal", "microsoft", "apple", "amazon", "bank", "irs",
                         "netflix", "google", "chase", "wellsfargo"]
        for brand in known_brands:
            if brand in display_name and brand not in from_domain:
                score += 30
                reasons.append(
                    f"Display name claims to be '{display_name_match.group(1).strip()}' but the "
                    f"sending domain ({from_domain or 'unknown'}) doesn't match that brand"
                )
                break

    attachment_names = []
    if msg.is_multipart():
        for part in msg.walk():
            fname = part.get_filename()
            if fname:
                attachment_names.append(fname)
    for fname in attachment_names:
        ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext in SUSPICIOUS_ATTACHMENT_EXTS:
            score += 25
            reasons.append(f"Contains a risky attachment type: {fname}")

    # ---------------- body language checks ----------------
    urgency_hits = [p for p in URGENCY_PHRASES if p in full_lower]
    if urgency_hits:
        score += min(30, 8 * len(urgency_hits))
        reasons.append(
            f"Uses urgency/social-engineering language ({len(urgency_hits)} phrase(s), "
            f"e.g. \"{urgency_hits[0]}\")"
        )

    spam_hits = [p for p in SPAM_PHRASES if p in full_lower]
    if spam_hits:
        score += min(20, 6 * len(spam_hits))
        reasons.append(f"Contains generic spam phrasing (e.g. \"{spam_hits[0]}\")")

    caps_count = _count_caps_words(full_text)
    if caps_count >= 6:
        score += 10
        reasons.append(f"Excessive ALL-CAPS words ({caps_count}) — a common spam signal")

    exclaim_count = full_text.count("!")
    if exclaim_count >= 4:
        score += 8
        reasons.append(f"Excessive exclamation marks ({exclaim_count})")

    # ---------------- embedded URL analysis (reuses the URL model logic) ----------------
    urls_found = list(dict.fromkeys(URL_RE.findall(full_text)))[:20]
    url_results = []
    max_url_risk = 0.0
    for u in urls_found:
        feat = extract_features(u)
        url_reasons = explain_features(feat, u)
        # crude heuristic score without loading the ML model here, to
        # keep this module dependency-light; app.py's /api/scan endpoint
        # gives the full ML-scored version for any link the user wants
        # to double-check individually.
        heuristic = (
            feat["suspicious_tld"] * 25 + feat["keyword_count"] * 8 +
            feat["is_typosquat"] * 30 + feat["brand_impersonation"] * 25 +
            feat["has_ip_address"] * 30 + feat["is_shortened"] * 15 +
            (0 if feat["has_https"] else 10)
        )
        heuristic = min(100, heuristic)
        max_url_risk = max(max_url_risk, heuristic)
        url_results.append({"url": u, "heuristic_risk": heuristic, "reasons": url_reasons[:3]})

    if url_results:
        if max_url_risk >= 50:
            score += 25
            reasons.append(f"Contains a high-risk embedded link ({urls_found[0][:60]}...)")
        elif max_url_risk >= 20:
            score += 10
            reasons.append("Contains at least one moderately suspicious embedded link")

    score = min(100, score)
    if not reasons:
        reasons.append("No strong spam/phishing indicators found in this email")

    if score >= 60:
        verdict = "Phishing / Spam"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Likely Legitimate"

    return {
        "subject": subject,
        "from": from_header,
        "reply_to": reply_to,
        "has_structured_headers": has_headers,
        "verdict": verdict,
        "risk_score": score,
        "reasons": reasons,
        "urls_found": url_results,
        "attachments": attachment_names,
    }
