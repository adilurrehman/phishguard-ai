from urllib.parse import urlparse
from app.threat_keywords import SUSPICIOUS_KEYWORDS


def generate_reasons(url):
    reasons = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # LONG URL
    if len(url) > 75:
        reasons.append("URL is unusually long")

    # NO HTTPS
    if parsed.scheme != "https":
        reasons.append("Connection is not secure (HTTPS missing)")

    # MANY HYPHENS
    if url.count('-') > 3:
        reasons.append("Excessive hyphens detected")

    # @ SYMBOL
    if '@' in url:
        reasons.append("@ symbol detected")

    # SHORTENER
    shorteners = [
        'bit.ly',
        'tinyurl',
        'goo.gl',
        't.co',
        'ow.ly',
        'tiny.cc',
    ]

    if any(s in domain for s in shorteners):
        reasons.append("Shortened URL detected")

    # SUSPICIOUS KEYWORDS
    lower_url = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lower_url:
            reasons.append(f"Suspicious keyword: {keyword}")

    return reasons
