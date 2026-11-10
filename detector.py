import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = {
    "urgent": 1,
    "verify your account": 2,
    "account suspended": 2,
    "click here": 1,
    "password": 1,
    "immediately": 1,
    "24 hours": 1,
    "confirm your identity": 2,
    "update your payment": 2,
    "security alert": 1,
    "permanent suspension": 2,
    "limited time": 1,
    "unusual activity": 1,
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
}

def is_official_domain(domain, official_domain):
    return domain == official_domain or domain.endswith("." + official_domain)

def extract_urls(text):
    matches = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+", text or "")
    return [url.rstrip(".,;:!?)]}") for url in matches]

def analyze_email(sender, subject, body):
    findings = []
    score = 0
    email_text = f"{subject} {body}".lower()

    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in email_text:
            score += points
            findings.append(f"Suspicious phrase detected: {keyword}")

    sender = (sender or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        score += 2
        findings.append("Sender address appears to be invalid")
    else:
        sender_domain = sender.rsplit("@", 1)[1].rstrip(".")
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in sender_domain and not is_official_domain(sender_domain, official_domain):
                score += 3
                findings.append(f"Possible impersonation of {brand}")

    urls = extract_urls(body)
    for url in urls:
        normalized = url if "://" in url else "http://" + url
        parsed = urlparse(normalized)
        domain = (parsed.hostname or "").lower()

        if parsed.scheme.lower() == "http":
            score += 1
            findings.append(f"Unencrypted HTTP link: {url}")
        if "@" in parsed.netloc:
            score += 2
            findings.append(f"URL contains an @ symbol: {url}")

        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in domain and not is_official_domain(domain, official_domain):
                score += 3
                findings.append(f"Possible fake {brand} link: {url}")

    if score >= 7:
        risk_level, classification = "HIGH RISK", "Potential Phishing Email"
    elif score >= 3:
        risk_level, classification = "MEDIUM RISK", "Suspicious Email"
    else:
        risk_level, classification = "LOW RISK", "No Strong Phishing Indicators Detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "result": classification,
        "findings": findings,
        "urls": urls,
    }
