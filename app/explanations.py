def generate_reasons(url):

    reasons = []

    if len(url) > 75:
        reasons.append("URL is unusually long")

    if url.count('-') > 3:
        reasons.append("Excessive hyphens detected")

    if "https" not in url:
        reasons.append("No HTTPS encryption")

    if "@" in url:
        reasons.append("@ symbol detected")

    if "bit.ly" in url:
        reasons.append("Shortened URL detected")

    return reasons
