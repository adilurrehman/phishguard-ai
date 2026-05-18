import re
from urllib.parse import urlparse

def extract_live_features(url):

    parsed = urlparse(url)

    features = {}

    # Length of URL
    features['length_url'] = len(url)

    # Count dots
    features['qty_dot_url'] = url.count('.')

    # Count hyphens
    features['qty_hyphen_url'] = url.count('-')

    # Count underscores
    features['qty_underline_url'] = url.count('_')

    # Count slashes
    features['qty_slash_url'] = url.count('/')

    # Count question marks
    features['qty_questionmark_url'] = url.count('?')

    # Count equals
    features['qty_equal_url'] = url.count('=')

    # Count @ symbols
    features['qty_at_url'] = url.count('@')

    # Count %
    features['qty_percent_url'] = url.count('%')

    # Check if domain uses IP
    domain = parsed.netloc

    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'

    features['domain_in_ip'] = 1 if re.match(ip_pattern, domain) else 0

    # Redirect count
    features['qty_redirects'] = url.count('//') - 1

    # HTTPS check
    features['tls_ssl_certificate'] = 1 if parsed.scheme == 'https' else 0

    # URL shortener check
    shortening_services = [
        'bit.ly',
        'tinyurl',
        'goo.gl',
        't.co'
    ]

    features['url_shortened'] = 1 if any(
        shortener in domain
        for shortener in shortening_services
    ) else 0

    # Email in URL
    features['email_in_url'] = 1 if "@" in url else 0

    return list(features.values())
