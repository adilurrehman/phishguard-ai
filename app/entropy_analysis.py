import math
from collections import Counter
from urllib.parse import urlparse

def shannon_entropy(data):
    """
    Calculate Shannon entropy of a string.
    Measures randomness/disorder in the data.
    
    - Low entropy (< 3.0): Legitimate domains with real words
    - Medium entropy (3.0-4.0): Mixed words and characters
    - High entropy (> 4.0): Random/obfuscated domains (SUSPICIOUS)
    
    Args:
        data: String to analyze
    
    Returns:
        float: Shannon entropy value
    """
    if not data or len(data) == 0:
        return 0.0
    
    counter = Counter(data.lower())
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_domain_entropy(url):
    """
    Analyze domain entropy to detect random/obfuscated domains.
    
    Returns:
        tuple: (entropy_value, is_suspicious, risk_score, reason)
    """
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").lower()
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Remove TLD (last part after dot)
        domain_parts = domain.split(".")
        if len(domain_parts) > 1:
            domain_name = ".".join(domain_parts[:-1])  # Everything except TLD
        else:
            domain_name = domain
        
        # Calculate entropy
        entropy = shannon_entropy(domain_name)
        
        # Risk assessment based on entropy thresholds
        if entropy > 4.2:
            return entropy, True, 35, f"Very high entropy ({entropy:.2f}) - Domain name looks random/obfuscated"
        elif entropy > 4.0:
            return entropy, True, 25, f"High entropy ({entropy:.2f}) - Domain name appears randomized"
        elif entropy > 3.5:
            return entropy, True, 15, f"Medium-high entropy ({entropy:.2f}) - Domain name is somewhat random"
        else:
            return entropy, False, 0, f"Normal entropy ({entropy:.2f}) - Domain name appears legitimate"
    
    except Exception as e:
        return 0.0, False, 0, f"Entropy check error: {str(e)}"


def get_entropy_penalty(url):
    """
    Get risk multiplier based on domain entropy.
    
    Returns:
        tuple: (risk_multiplier, reason)
    """
    entropy, is_suspicious, risk_score, reason = analyze_domain_entropy(url)
    
    if is_suspicious:
        if entropy > 4.2:
            return 2.0, reason  # Critical randomness
        elif entropy > 4.0:
            return 1.5, reason  # High randomness
        elif entropy > 3.5:
            return 1.2, reason  # Medium randomness
    
    return 1.0, ""


# Common legitimate domain patterns (for reference)
LEGITIMATE_WORDS = [
    "google", "amazon", "microsoft", "apple", "facebook",
    "github", "stackoverflow", "reddit", "twitter", "instagram",
    "youtube", "linkedin", "netflix", "spotify", "dropbox",
    "slack", "discord", "telegram", "whatsapp", "paypal",
    "stripe", "shopify", "wordpress", "medium", "dev",
    "io", "cloud", "api", "app", "web", "mail", "secure"
]

def entropy_with_word_bonus(url):
    """
    Calculate entropy with bonus for containing known legitimate words.
    This reduces false positives for domains like "my-github-portfolio.com"
    
    Returns:
        tuple: (adjusted_entropy, contains_legitimate_words)
    """
    entropy, is_suspicious, risk_score, reason = analyze_domain_entropy(url)
    
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").lower()
    
    contains_legitimate = any(word in domain for word in LEGITIMATE_WORDS)
    
    if contains_legitimate and entropy > 3.5:
        # Reduce entropy penalty if legitimate words are present
        adjusted_entropy = entropy * 0.85  # 15% reduction
        return adjusted_entropy, contains_legitimate
    
    return entropy, contains_legitimate
