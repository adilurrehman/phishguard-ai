import whois
from datetime import datetime, timedelta
from urllib.parse import urlparse

def check_domain_age(url):
    """
    Check the age of a domain.
    
    Returns:
        tuple: (is_suspicious, days_old, reason)
        - is_suspicious: True if domain is very new (suspicious)
        - days_old: Age of domain in days (None if lookup fails)
        - reason: Human-readable explanation
    """
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        
        # Remove any port number if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Perform WHOIS lookup
        whois_data = whois.whois(domain)
        
        # Get creation date
        creation_date = whois_data.creation_date
        
        # Handle case where creation_date might be a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Ensure we have a datetime object
        if not isinstance(creation_date, datetime):
            return False, None, "Could not determine domain age"
        
        # Calculate domain age in days
        now = datetime.now()
        if creation_date.tzinfo is not None:
            now = datetime.now(creation_date.tzinfo)
        
        days_old = (now - creation_date).days
        
        # RISK THRESHOLDS
        # Domains less than 30 days old are very suspicious
        if days_old < 30:
            return True, days_old, f"Domain is extremely new ({days_old} days old) - HIGH RISK"
        
        # Domains between 30-60 days are moderately suspicious
        elif days_old < 60:
            return True, days_old, f"Domain is very new ({days_old} days old) - MEDIUM RISK"
        
        # Domains older than 60 days are generally safe
        else:
            return False, days_old, f"Domain is established ({days_old} days old)"
    
    except Exception as e:
        # If WHOIS lookup fails, we can't determine age
        # Return None to indicate unknown, system should continue with ML model
        return False, None, f"Domain age check unavailable: {str(e)}"

def get_domain_age_penalty(url):
    """
    Get a risk score adjustment based on domain age.
    
    Returns:
        tuple: (risk_adjustment, reason)
        - risk_adjustment: Multiplier to apply to base risk score (1.0 = no change)
        - reason: Explanation of the adjustment
    """
    is_suspicious, days_old, reason = check_domain_age(url)
    
    if is_suspicious and days_old is not None:
        if days_old < 30:
            return 2.5, f"Domain extremely new ({days_old} days): HIGH RISK"
        elif days_old < 60:
            return 1.8, f"Domain very new ({days_old} days): MEDIUM RISK"
    
    return 1.0, "Domain age normal"
