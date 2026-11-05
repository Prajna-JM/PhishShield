
"""Conservative, offline URL and text warning checks.
No URL is visited or opened.
"""

import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_TERMS = {
    "verify", "login", "secure", "account", "update", "password",
    "wallet", "banking", "claim", "reward", "kyc", "payment"
}

URGENT_TERMS = {
    "urgent", "immediately", "now", "today", "blocked", "suspended",
    "expire", "final warning", "act now"
}

SENSITIVE_TERMS = {
    "otp", "pin", "password", "bank details", "card number",
    "cvv", "account details"
}


def contains_term(text, term):
    """Match complete words or phrases, avoiding accidental substring matches."""
    pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"
    return bool(re.search(pattern, text, re.IGNORECASE))


def extract_urls(text: str):
    """Extract URLs without visiting them."""
    found = re.findall(
        r"""(?i)(?:https?://|www\.)[^\s<>"']+""",
        text or ""
    )

    return [
        url.rstrip(".,!?;:)]}")
        for url in found
    ]


def analyze_url(raw_url: str):
    raw_url = (raw_url or "").strip()

    candidate = (
        raw_url
        if re.match(r"(?i)^https?://", raw_url)
        else "http://" + raw_url
    )

    parsed = urlparse(candidate)
    host = parsed.hostname or ""

    reasons = []
    score = 0

    if not host:
        return {
            "url": raw_url,
            "domain": None,
            "score": 25,
            "reasons": ["URL could not be parsed reliably"]
        }

    if len(raw_url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("Uses an IP address instead of a normal domain")
    except ValueError:
        pass

    if parsed.scheme != "https":
        score += 10
        reasons.append("Does not use HTTPS (not proof of phishing)")

    if "@" in parsed.netloc:
        score += 20
        reasons.append("Contains an @ symbol in the network location")

    if len(host.split(".")) >= 5:
        score += 10
        reasons.append("Contains many subdomain levels")

    if "xn--" in host.lower():
        score += 20
        reasons.append("Contains a punycode hostname")

    found = sorted(
        term for term in SUSPICIOUS_TERMS
        if contains_term(raw_url.lower(), term)
    )

    if found:
        score += min(20, 5 * len(found))
        reasons.append(
            "Contains potentially deceptive terms: " + ", ".join(found)
        )

    return {
        "url": raw_url,
        "domain": host,
        "score": min(score, 100),
        "reasons": reasons
    }


def text_warnings(text: str):
    lowered = (text or "").lower()
    warnings = []

    # 1. Urgent or threatening wording
    urgency = sorted(
        term for term in URGENT_TERMS
        if contains_term(lowered, term)
    )

    if urgency:
        warnings.append(
            "Urgent or threatening wording: " + ", ".join(urgency)
        )

    # 2. Sensitive information references
    sensitive = sorted(
        term for term in SENSITIVE_TERMS
        if contains_term(lowered, term)
    )

    if sensitive:
        warnings.append(
            "Mentions sensitive credentials or financial information: "
            + ", ".join(sensitive)
        )

    # 3. Detect actual requests to reveal credentials
    credential_request_patterns = [
        r"\bshare\b.{0,30}\botp\b",
        r"\b(?:send|provide|enter|submit|reveal)\b.{0,30}\botp\b",
        r"\b(?:share|send|provide|enter|submit|reveal)\b.{0,30}\bpin\b",
        r"\b(?:share|send|provide|enter|submit|reveal)\b.{0,30}\bpassword\b",
        r"\b(?:enter|submit|provide)\b.{0,30}\b(?:cvv|card number|bank details)\b",
    ]

    credential_requested = any(
        re.search(pattern, lowered)
        for pattern in credential_request_patterns
    )

    if credential_requested:
        warnings.append(
            "Requests sensitive credentials or authentication information"
        )

    # 4. Distinguish normal OTP safety advice
    if contains_term(lowered, "otp") and not credential_requested:
        if re.search(
            r"\b(?:do not|don't|never|never ever)\s+"
            r"(?:share|tell|reveal|disclose)\b.{0,30}\botp\b",
            lowered
        ):
            warnings.append(
                "Contains an OTP safety reminder; never share OTPs"
            )
        else:
            warnings.append(
                "Contains an OTP reference; never share OTPs with anyone"
            )

    # 5. Suspicious link instructions
    if (
        contains_term(lowered, "click here")
        or contains_term(lowered, "click the link")
    ):
        warnings.append("Encourages the recipient to click a link")

    # 6. Prize or reward bait
    if any(
        contains_term(lowered, term)
        for term in ("winner", "lottery", "free prize", "claim your reward")
    ):
        warnings.append("Uses prize or reward bait")

    return warnings
