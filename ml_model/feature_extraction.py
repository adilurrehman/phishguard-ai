import re
from urllib.parse import urlparse

FEATURE_COLUMNS = [
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
    'email_in_url'
]

SHORTENER_DOMAINS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'lnkd.in', 's.id'
}


def _parsed_url(url):
    return urlparse(url if '://' in url else f'http://{url}')


def _hostname(url):
    parsed = _parsed_url(url)
    return parsed.hostname or ''


def _is_ipv4(hostname):
    return bool(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', hostname))

def extract_features(url):
    parsed = _parsed_url(url)
    hostname = _hostname(url)

    features = {
        'length_url': len(url),
        'qty_dot_url': url.count('.'),
        'qty_hyphen_url': url.count('-'),
        'qty_underline_url': url.count('_'),
        'qty_slash_url': url.count('/'),
        'qty_questionmark_url': url.count('?'),
        'qty_equal_url': url.count('='),
        'qty_at_url': url.count('@'),
        'qty_percent_url': url.count('%'),
        'domain_in_ip': 1 if _is_ipv4(hostname) else 0,
        'qty_redirects': max(0, len(re.findall(r'https?://', url)) - 1),
        'tls_ssl_certificate': 1 if parsed.scheme == 'https' else 0,
        'url_shortened': 1 if hostname.lower() in SHORTENER_DOMAINS else 0,
        'email_in_url': 1 if '@' in url else 0,
    }

    return features