from pathlib import Path
from urllib.parse import urlparse

import joblib

from model.live_features import LEGACY_FEATURE_COLUMNS, extract_feature_vector
from app.domain_age_check import check_domain_age
from app.brand_impersonation import detect_brand_impersonation
from app.entropy_analysis import analyze_domain_entropy
from app.domain_reputation import analyze_domain_reputation
from app.explanations import generate_reasons
from app.tld_analysis import analyze_tld
from app.safety_tips import get_safety_tips

BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_PATH = BASE_DIR / 'model' / 'phishing_model.pkl'

model = joblib.load(MODEL_PATH)

# Small curated list used to reduce risk for well-known trusted providers
TRUSTED_DOMAINS = [
    'google.com',
    'github.com',
    'microsoft.com',
    'amazon.com',
    'apple.com',
    'paypal.com',
    'facebook.com',
    'linkedin.com',
    'kaggle.com',
]


def _add_signal(score_total, reasons, score, reason):
    if score > 0:
        score_total = min(score_total + score, 100)
        reasons.append(reason)

    return score_total, reasons


def _apply_reason_weight(heuristic_score, heuristic_reasons, reason):
    r = reason.lower()

    if 'unusually long' in r or 'long url' in r:
        return _add_signal(heuristic_score, heuristic_reasons, 8, reason)

    if 'hyphen' in r:
        return _add_signal(heuristic_score, heuristic_reasons, 6, reason)

    if 'https' in r and ('missing' in r or 'not secure' in r or 'no https' in r):
        return _add_signal(heuristic_score, heuristic_reasons, 12, reason)

    if '@' in reason:
        return _add_signal(heuristic_score, heuristic_reasons, 20, reason)

    if 'shorten' in r:
        return _add_signal(heuristic_score, heuristic_reasons, 15, reason)

    if r.startswith('suspicious keyword:'):
        return _add_signal(heuristic_score, heuristic_reasons, 7, reason)

    return heuristic_score, heuristic_reasons


def analyze_url(url):
    """
    Centralized URL analysis pipeline.

    Returns a single analysis object with:
    - prediction
    - risk_score
    - reasons
    - safety_tips
    """
    heuristic_score = 0.0
    heuristic_reasons = []

    # Base explanation signals and mapped heuristic weights
    for reason in generate_reasons(url):
        heuristic_score, heuristic_reasons = _apply_reason_weight(
            heuristic_score,
            heuristic_reasons,
            reason,
        )

    # Domain age signal
    _, days_old, age_reason = check_domain_age(url)
    if days_old is not None:
        if days_old < 30:
            heuristic_score, heuristic_reasons = _add_signal(
                heuristic_score,
                heuristic_reasons,
                35,
                f"{age_reason} - strong phishing signal",
            )
        elif days_old < 60:
            heuristic_score, heuristic_reasons = _add_signal(
                heuristic_score,
                heuristic_reasons,
                20,
                f"{age_reason} - moderate phishing signal",
            )
        else:
            heuristic_reasons.append(age_reason)

    # Brand impersonation signal
    is_impersonation, impersonation_risk, impersonation_reasons = detect_brand_impersonation(url)
    if is_impersonation:
        heuristic_score, heuristic_reasons = _add_signal(
            heuristic_score,
            heuristic_reasons,
            min(max(impersonation_risk, 25), 40),
            'Possible brand impersonation detected',
        )
        heuristic_reasons.extend(impersonation_reasons)

    # Entropy signal
    _, entropy_is_suspicious, entropy_risk, entropy_reason = analyze_domain_entropy(url)
    if entropy_is_suspicious:
        heuristic_score, heuristic_reasons = _add_signal(
            heuristic_score,
            heuristic_reasons,
            entropy_risk,
            entropy_reason,
        )

    # TLD signal
    tld_is_suspicious, tld_risk, tld_reason = analyze_tld(url)
    if tld_is_suspicious:
        heuristic_score, heuristic_reasons = _add_signal(
            heuristic_score,
            heuristic_reasons,
            tld_risk,
            tld_reason,
        )

    # Domain reputation signal
    reputation_signal, reputation_bonus, reputation_reason = analyze_domain_reputation(url)
    if reputation_signal:
        heuristic_score -= reputation_bonus
        heuristic_reasons.append(f"Reputation bonus applied: {reputation_reason}")

    # ML scoring
    model_feature_names = list(getattr(model, 'feature_names_in_', []))
    if not model_feature_names:
        model_feature_names = LEGACY_FEATURE_COLUMNS

    features = extract_feature_vector(url, model_feature_names)
    model_input = [features]
    model_class = int(model.predict(model_input)[0])
    probability = model.predict_proba(model_input)[0]

    try:
        model_phishing_prob = float(probability[1])
    except Exception:
        model_phishing_prob = float(max(probability))

    # Hybrid final risk score
    domain = urlparse(url).netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]

    risk_score = 0.0

    # MODEL CONTRIBUTION
    risk_score += model_phishing_prob * 40

    # URL LENGTH
    if len(url) > 75:
        risk_score += 10

    # NO HTTPS
    if 'https' not in url.lower():
        risk_score += 15

    # @ SYMBOL
    if '@' in url:
        risk_score += 20

    # HYPHENS
    if url.count('-') > 3:
        risk_score += 15

    # Additional explainable heuristic contribution
    risk_score += float(heuristic_score) * 0.45

    # TRUSTED DOMAIN REDUCTION
    if any(trusted in domain for trusted in TRUSTED_DOMAINS):
        risk_score -= 50
        heuristic_reasons.append('Trusted domain reduction applied')

    final_risk_score = max(0, min(100, round(risk_score, 2)))

    if final_risk_score < 30:
        label = 'SAFE'
    elif final_risk_score < 60:
        label = 'SUSPICIOUS'
    else:
        label = 'PHISHING'

    reasons = [
        f"ML phishing probability: {model_phishing_prob:.3f}",
        f"ML contribution (x40): {model_phishing_prob * 40:.2f}",
        f"Heuristic signals contribution (scaled): {heuristic_score * 0.45:.2f}",
        f"Final risk score: {final_risk_score:.2f}",
        f"ML model class prediction: {'PHISHING' if model_class == 1 else 'LEGITIMATE'}",
    ]
    reasons.extend(heuristic_reasons)

    safety_tips = get_safety_tips(final_risk_score)

    return {
        'prediction': label,
        'risk_score': final_risk_score,
        'reasons': reasons,
        'safety_tips': safety_tips,
    }
