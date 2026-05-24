import math
import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

from app.brand_impersonation import detect_brand_impersonation
from app.domain_age_check import check_domain_age
from app.domain_reputation import analyze_domain_reputation
from app.entropy_analysis import analyze_domain_entropy
from app.threat_keywords import SUSPICIOUS_KEYWORDS
from app.tld_analysis import analyze_tld


LEGACY_FEATURE_COLUMNS = [
    'length_url',
    'qty_dot_url',
    'qty_hyphen_url',
    'qty_underline_url',
    'qty_slash_url',
    'qty_questionmark_url',
    'qty_equal_url',
    'qty_at_url',
    'qty_percent_url',
    'domain_in_ip',
    'qty_redirects',
    'tls_ssl_certificate',
    'url_shortened',
    'email_in_url',
]


FEATURE_COLUMNS = LEGACY_FEATURE_COLUMNS + [
    'domain_length',
    'qty_dot_domain',
    'qty_hyphen_domain',
    'qty_vowels_domain',
    'subdomain_count',
    'subdomain_length',
    'subdomain_keyword_hit',
    'path_length',
    'path_depth',
    'query_length',
    'query_count',
    'domain_age_days',
    'domain_age_risk',
    'entropy_domain',
    'entropy_risk',
    'brand_impersonation_risk',
    'brand_impersonation_hit',
    'has_suspicious_tld',
    'tld_risk',
    'domain_reputation_bonus',
    'domain_reputation_hit',
    'redirect_chain_count',
    'https_missing',
    'suspicious_keyword_count',
    'suspicious_keyword_hit',
    'has_ip_domain',
]


SHORTENER_DOMAINS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'lnkd.in', 's.id'
}


def _parsed_url(url):
    return urlparse(url if '://' in url else f'http://{url}')


def _hostname(url):
    parsed = _parsed_url(url)
    return (parsed.hostname or '').lower()


def _path_depth(path):
    parts = [part for part in path.split('/') if part]
    return len(parts)


def _count_vowels(text):
    return sum(1 for char in text.lower() if char in 'aeiou')


def _get_domain_parts(hostname):
    parts = [part for part in hostname.split('.') if part]
    if len(parts) <= 2:
        return '', hostname, ''

    subdomain = '.'.join(parts[:-2])
    domain = parts[-2]
    tld = parts[-1]
    return subdomain, f'{domain}.{tld}', tld


def _entropy(text):
    if not text:
        return 0.0

    counter = Counter(text.lower())
    entropy = 0.0
    length = len(text)
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _legacy_feature_dict(url):
    parsed = _parsed_url(url)
    hostname = _hostname(url)

    ip_pattern = r'^\d{1,3}(?:\.\d{1,3}){3}$'

    return {
        'length_url': len(url),
        'qty_dot_url': url.count('.'),
        'qty_hyphen_url': url.count('-'),
        'qty_underline_url': url.count('_'),
        'qty_slash_url': url.count('/'),
        'qty_questionmark_url': url.count('?'),
        'qty_equal_url': url.count('='),
        'qty_at_url': url.count('@'),
        'qty_percent_url': url.count('%'),
        'domain_in_ip': 1 if re.fullmatch(ip_pattern, hostname) else 0,
        'qty_redirects': max(0, len(re.findall(r'https?://', url)) - 1),
        'tls_ssl_certificate': 1 if parsed.scheme == 'https' else 0,
        'url_shortened': 1 if hostname in SHORTENER_DOMAINS else 0,
        'email_in_url': 1 if '@' in url else 0,
    }


def extract_feature_dict(url):
    parsed = _parsed_url(url)
    hostname = _hostname(url)
    subdomain, registrable_domain, _ = _get_domain_parts(hostname)
    domain_name = registrable_domain.rsplit('.', 1)[0] if '.' in registrable_domain else registrable_domain
    path = parsed.path or ''
    query = parsed.query or ''

    legacy = _legacy_feature_dict(url)

    age_is_suspicious, domain_age_days, _age_reason = check_domain_age(url)
    domain_age_days = domain_age_days if domain_age_days is not None else 0
    domain_age_risk = 35 if age_is_suspicious and domain_age_days < 30 else 20 if age_is_suspicious else 0

    entropy_value, entropy_is_suspicious, entropy_risk, _entropy_reason = analyze_domain_entropy(url)
    impersonation_hit, impersonation_risk, _impersonation_reasons = detect_brand_impersonation(url)
    tld_is_suspicious, tld_risk, _tld_reason = analyze_tld(url)
    reputation_hit, reputation_bonus, _reputation_reason = analyze_domain_reputation(url)

    suspicious_keyword_count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in url.lower())
    suspicious_keyword_hit = 1 if suspicious_keyword_count > 0 else 0

    subdomain_keywords = ('login', 'secure', 'verify', 'account', 'update', 'bank', 'payment', 'confirm', 'support')
    subdomain_keyword_hit = 1 if any(keyword in subdomain for keyword in subdomain_keywords) else 0

    return {
        **legacy,
        'domain_length': len(domain_name),
        'qty_dot_domain': hostname.count('.'),
        'qty_hyphen_domain': hostname.count('-'),
        'qty_vowels_domain': _count_vowels(domain_name),
        'subdomain_count': max(0, len([part for part in hostname.split('.') if part]) - 2),
        'subdomain_length': len(subdomain),
        'subdomain_keyword_hit': subdomain_keyword_hit,
        'path_length': len(path),
        'path_depth': _path_depth(path),
        'query_length': len(query),
        'query_count': len(parse_qs(query)),
        'domain_age_days': domain_age_days,
        'domain_age_risk': domain_age_risk,
        'entropy_domain': round(float(entropy_value), 4),
        'entropy_risk': entropy_risk if entropy_is_suspicious else 0,
        'brand_impersonation_risk': impersonation_risk if impersonation_hit else 0,
        'brand_impersonation_hit': 1 if impersonation_hit else 0,
        'has_suspicious_tld': 1 if tld_is_suspicious else 0,
        'tld_risk': tld_risk,
        'domain_reputation_bonus': reputation_bonus if reputation_hit else 0,
        'domain_reputation_hit': 1 if reputation_hit else 0,
        'redirect_chain_count': max(0, url.count('://') - 1),
        'https_missing': 1 if parsed.scheme != 'https' else 0,
        'suspicious_keyword_count': suspicious_keyword_count,
        'suspicious_keyword_hit': suspicious_keyword_hit,
        'has_ip_domain': legacy['domain_in_ip'],
    }


def extract_live_features(url):
    """Backward-compatible legacy vector used by older code paths."""
    features = extract_feature_dict(url)
    return [features[column] for column in LEGACY_FEATURE_COLUMNS]


def extract_feature_vector(url, feature_names=None):
    feature_names = feature_names or FEATURE_COLUMNS
    features = extract_feature_dict(url)
    return [features.get(name, 0) for name in feature_names]
