from urllib.parse import urlparse

REPUTATION_DOMAINS = [
    "google.com",
    "kaggle.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "stackoverflow.com",
    "oracle.com",
    "wikipedia.org",
    "python.org",
    "amazon.com",
]


def analyze_domain_reputation(url):
    """
    Apply a small reputation bonus for well-established domains.

    This is intentionally minor signal only. It should reduce risk a little,
    not override other phishing indicators.

    Returns:
        tuple: (has_reputation_signal, bonus_score, reason)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").lower()

        if ":" in domain:
            domain = domain.split(":")[0]

        for reputation_domain in REPUTATION_DOMAINS:
            if domain.endswith(reputation_domain):
                return True, 20, f"Established domain recognized: {reputation_domain}"

        return False, 0, "No reputation bonus applied"

    except Exception as e:
        return False, 0, f"Domain reputation check error: {str(e)}"