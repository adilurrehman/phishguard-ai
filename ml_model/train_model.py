import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load dataset
data = pd.read_csv('../dataset/phishing.csv')

# Selected features
features = [
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

# Inputs
X = data[features]

# Target
y = data['phishing']

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Model
model = RandomForestClassifier()

# Train
model.fit(X_train, y_train)

# Test
predictions = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, predictions)

print("Accuracy:", accuracy)

# Save
joblib.dump(model, 'phishing_model.pkl')