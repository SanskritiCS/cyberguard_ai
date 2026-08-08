import joblib

model = joblib.load("url_phishing_model.pkl")

def extract_features(url):
    url = url.lower()
    return [[
        len(url),
        url.count('.'),
        int('https' in url),
        int(any(k in url for k in ['login','verify','secure','bank','otp'])),
        int(any(t in url for t in ['.xyz','.top','.tk','.ml']))
    ]]

def predict_url(url):
    features = extract_features(url)

    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0][1]

    return {
        "ml_prediction": "phishing" if prediction == 1 else "safe",
        "confidence": round(float(probability) * 100, 2)
    }