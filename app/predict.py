import joblib
from ml_model.live_features import extract_live_features

model = joblib.load('ml_model/phishing_model.pkl')

def predict_url(url):

    features = extract_live_features(url)

    prediction = model.predict([features])[0]

    probability = model.predict_proba([features])[0]

    risk_score = float(round(max(probability) * 100, 2))

    if prediction == 1:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    return label, risk_score