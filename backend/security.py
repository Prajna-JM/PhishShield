"""Conservative, offline URL and text warning checks. No URL is visited."""
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

def extract_urls(text: str):
    # Trim common trailing punctuation. Do not fetch or resolve these URLs.
    found = re.findall(r'(?i)(?:https?://|www\.)[^\s<>"\']+', text or "")
    return [u.rstrip(".,!?;:)]}") for u in found]

def analyze_url(raw_url: str):
    raw_url = (raw_url or "").strip()
    candidate = raw_url if re.match(r"(?i)^https?://", raw_url) else "http://" + raw_url
    parsed = urlparse(candidate)
    host = parsed.hostname or ""
    reasons, score = [], 0

    if not host:
        return {"url": raw_url, "domain": None, "score": 25,
                "reasons": ["URL could not be parsed reliably"]}

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
    found = sorted(term for term in SUSPICIOUS_TERMS if term in raw_url.lower())
    if found:
        score += min(20, 5 * len(found))
        reasons.append("Contains potentially deceptive terms: " + ", ".join(found))
    return {"url": raw_url, "domain": host, "score": min(score, 100), "reasons": reasons}

def text_warnings(text: str):
    lowered = (text or "").lower()
    warnings = []
    urgency = sorted(term for term in URGENT_TERMS if term in lowered)
    sensitive = sorted(term for term in SENSITIVE_TERMS if term in lowered)
    if urgency:
        warnings.append("Urgent or threatening wording: " + ", ".join(urgency))
    if sensitive:
        warnings.append("Mentions sensitive credentials or financial information: " + ", ".join(sensitive))
    if "click here" in lowered or "click the link" in lowered:
        warnings.append("Encourages the recipient to click a link")
    if any(term in lowered for term in ("winner", "lottery", "free prize", "claim your reward")):
        warnings.append("Uses prize or reward bait")
    return warnings
