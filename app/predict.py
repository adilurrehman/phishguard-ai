import joblib
from ml_model.live_features import extract_live_features
from app.domain_age_check import check_domain_age, get_domain_age_penalty
from app.brand_impersonation import detect_brand_impersonation, get_brand_risk_level

model = joblib.load('ml_model/phishing_model.pkl')

def predict_url(url):
    """
    Predict if a URL is phishing using a layered approach:
    Layer 1: Domain Age Check (NEW domains = HIGH RISK)
    Layer 2: Brand Impersonation Detection (TYPOSQUATTING)
    Layer 3: ML Model (Feature-based detection)
    """
    
    # LAYER 1: DOMAIN AGE CHECK (Critical)
    is_suspicious_age, days_old, age_reason = check_domain_age(url)
    
    if is_suspicious_age and days_old is not None:
        # Domain is too new - extremely suspicious
        if days_old < 30:
            return "PHISHING", 95, [
                f"Domain is extremely new ({days_old} days old) - CRITICAL RISK",
                "Newly registered domains are primary phishing indicators",
                "Legitimate services use established domains"
            ]
        elif days_old < 60:
            return "PHISHING", 85, [
                f"Domain is very new ({days_old} days old) - HIGH RISK",
                "Domains younger than 60 days have high phishing probability",
                "Established services maintain domains for years"
            ]
    
    # LAYER 2: BRAND IMPERSONATION DETECTION (Typosquatting)
    is_impersonation, impersonation_risk, impersonation_reasons = detect_brand_impersonation(url)
    
    if is_impersonation and impersonation_risk >= 45:
        # Critical brand impersonation detected
        return "PHISHING", 92, impersonation_reasons + [
            "Brand impersonation is a primary phishing tactic",
            "Attackers use known brands to build false trust"
        ]
    
    # LAYER 3: ML MODEL (Feature-based)
    features = extract_live_features(url)
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0]
    risk_score = float(round(max(probability) * 100, 2))
    
    # Apply domain age penalty if available
    age_penalty, penalty_reason = get_domain_age_penalty(url)
    if age_penalty > 1.0:
        risk_score = min(risk_score * age_penalty, 100)
    
    # Apply brand impersonation penalty if available
    brand_penalty, brand_reasons = get_brand_risk_level(url)
    if brand_penalty > 1.0:
        risk_score = min(risk_score * brand_penalty, 100)
    
    if prediction == 1:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"
    
    # Generate reasons based on all layers
    reasons = [f"ML Model Confidence: {max(probability)*100:.1f}%"]
    if age_penalty > 1.0:
        reasons.extend([penalty_reason])
    if brand_penalty > 1.0:
        reasons.extend(brand_reasons)
    
    return label, risk_score, reasons