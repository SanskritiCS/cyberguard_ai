import joblib

# Load trained ML model
model = joblib.load("email_model.pkl")
vectorizer = joblib.load("email_vectorizer.pkl")

def predict_email(text):
    X = vectorizer.transform([text])

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1]

    return {
        "ml_prediction": "phishing" if prediction == 1 else "safe",
        "confidence": round(float(probability) * 100, 2)
    }