import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

data = {
    "text": [
        "verify your bank account immediately",
        "your account is suspended click now",
        "meeting tomorrow at 10 am",
        "project report attached",
        "claim your free reward now",
        "invoice attached for your purchase"
    ],
    "label": [1, 1, 0, 0, 1, 0]
}

df = pd.DataFrame(data)

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(df['text'])
y = df['label']

model = LogisticRegression()
model.fit(X, y)

joblib.dump(model, "email_model.pkl")
joblib.dump(vectorizer, "email_vectorizer.pkl")

print("Email ML Model Saved!")