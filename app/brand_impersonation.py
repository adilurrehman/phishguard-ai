from urllib.parse import urlparse

# List of major brands frequently impersonated in phishing attacks
KNOWN_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "twitter",
    "linkedin",
    "github",
    "slack",
    "dropbox",
    "adobe",
    "spotify",
    "whatsapp",
    "telegram",
    "discord",
    "reddit",
    "ebay",
    "visa",
    "mastercard",
    "stripe",
    "payoneer",
    "wise",
    "cryptocurrency",
    "bitcoin",
    "ethereum",
    "bank",
    "banking",
    "secure",
    "verify",
    "login",
    "account",
    "password"
]

def detect_brand_impersonation(url):
    """
    Detect if a domain is impersonating a known brand.
    
    Returns:
        tuple: (is_impersonation, risk_score, reasons)
        - is_impersonation: True if brand impersonation detected
        - risk_score: Risk score increase (0-100)
        - reasons: List of reasons for the detection
    """
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "").lower()
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Get the base domain (before TLD)
        domain_parts = domain.split(".")
        domain_name = domain_parts[0] if domain_parts else ""
        
        reasons = []
        total_risk = 0
        found_impersonation = False
        
        # Check each known brand
        for brand in KNOWN_BRANDS:
            brand_lower = brand.lower()
            
            # Check if brand appears in domain
            if brand_lower in domain:
                # The legitimate domain would be brand.com, brand.co.uk, etc.
                legitimate_domains = [
                    f"{brand}.com",
                    f"{brand}.co.uk",
                    f"{brand}.org",
                    f"{brand}.net",
                    f"{brand}.io",
                ]
                
                # Check if it's NOT the legitimate domain
                is_legitimate = any(domain.endswith(leg_domain) for leg_domain in legitimate_domains)
                
                if not is_legitimate:
                    # This is brand impersonation
                    found_impersonation = True
                    
                    # Calculate risk based on how obvious the impersonation is
                    if brand_lower == domain_name:
                        # Brand is the main domain name (e.g., paypal-login.xyz)
                        risk = 50
                        reasons.append(f"CRITICAL: Brand '{brand}' used as primary domain name on suspicious TLD")
                    elif domain.startswith(brand_lower):
                        # Brand appears at start (e.g., paypalsecure.com)
                        risk = 45
                        reasons.append(f"HIGH: Brand '{brand}' appears at start of domain name")
                    else:
                        # Brand appears somewhere in domain (e.g., secure-paypal-login.com)
                        risk = 40
                        reasons.append(f"MEDIUM: Brand '{brand}' appears in domain '{domain}'")
                    
                    total_risk = max(total_risk, risk)
        
        return found_impersonation, total_risk, reasons
    
    except Exception as e:
        return False, 0, [f"Brand check error: {str(e)}"]


def get_brand_risk_level(url):
    """
    Get the risk level and multiplier for brand impersonation.
    
    Returns:
        tuple: (risk_multiplier, reasons_list)
    """
    is_impersonation, risk_score, reasons = detect_brand_impersonation(url)
    
    if is_impersonation:
        if risk_score >= 50:
            return 2.8, reasons  # Critical impersonation
        elif risk_score >= 45:
            return 2.3, reasons  # High impersonation
        else:
            return 1.6, reasons  # Medium impersonation
    
    return 1.0, []
