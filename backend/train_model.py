"""
Train and save the PhishShield text classifier.
The included CSV is a tiny demonstration dataset only. Replace it with a
larger, correctly labelled dataset before reporting performance.
"""
from pathlib import Path
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "messages.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA).dropna(subset=["text", "label"])
df["text"] = df["text"].astype(str).str.strip()
df["label"] = df["label"].astype(str).str.strip().str.lower()
df = df[df["label"].isin(["phishing", "legitimate"])]
df = df[df["text"] != ""].drop_duplicates(subset=["text"])

if df["label"].nunique() != 2 or df["label"].value_counts().min() < 2:
    raise SystemExit("Need at least two examples of each class in messages.csv.")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.25, random_state=42, stratify=df["label"]
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True, ngram_range=(1, 2), max_features=30000,
        strip_accents="unicode", sublinear_tf=True
    )),
    ("classifier", LogisticRegression(
        max_iter=1500, class_weight="balanced", random_state=42
    ))
])
model.fit(X_train, y_train)
pred = model.predict(X_test)

print("Evaluation on the held-out split (small demo data; not production evidence):")
print(classification_report(y_test, pred, zero_division=0))
print("Confusion matrix [legitimate, phishing]:")
print(confusion_matrix(y_test, pred, labels=["legitimate", "phishing"]))

joblib.dump(model, MODEL_DIR / "text_model.joblib")
(MODEL_DIR / "metadata.json").write_text(json.dumps({
    "classes": list(model.classes_),
    "training_rows": int(len(X_train)),
    "test_rows": int(len(X_test)),
    "warning": "Demo dataset only. Replace with a larger verified dataset."
}, indent=2), encoding="utf-8")
print(f"Saved model to {MODEL_DIR / 'text_model.joblib'}")
