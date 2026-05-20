from urllib.parse import urlparse

SUSPICIOUS_TLDS = [
    ".tk",
    ".xyz",
    ".top",
    ".click",
    ".gq",
]


def analyze_tld(url):
    """
    Check whether a URL uses a TLD that is statistically abused more often.

    Returns:
        tuple: (is_suspicious, risk_score, reason)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").lower()

        if ":" in domain:
            domain = domain.split(":")[0]

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return (
                    True,
                    15,
                    f"Suspicious TLD detected: {tld} (commonly abused in phishing)",
                )

        return False, 0, "TLD appears normal"

    except Exception as e:
        return False, 0, f"TLD check error: {str(e)}"


def get_tld_penalty(url):
    """
    Return a risk multiplier based on TLD reputation.
    """
    is_suspicious, risk_score, reason = analyze_tld(url)

    if is_suspicious:
        return 1.15, reason

    return 1.0, reason