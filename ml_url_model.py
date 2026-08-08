import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Training data
data = {
    "url": [
        "https://google.com",
        "https://github.com",
        "https://amazon.in",
        "https://sbi-login-verify.top",
        "http://paypal-secure-update.xyz",
        "http://free-bonus-click.top"
    ],
    "label": [0, 0, 0, 1, 1, 1]
}

df = pd.DataFrame(data)

def extract_features(url):
    url = url.lower()
    return [
        len(url),
        url.count('.'),
        int('https' in url),
        int(any(k in url for k in ['login', 'verify', 'secure', 'bank', 'otp'])),
        int(any(t in url for t in ['.xyz', '.top', '.tk', '.ml']))
    ]

X = df['url'].apply(extract_features).tolist()
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "url_phishing_model.pkl")

print("URL ML Model Saved!")