"""Train the Phishing Hunter v2 URL model.

    python training/train_url_model.py

Pipeline
--------
* Dataset: training/phishing_site_urls.csv (549k labelled URLs, good/bad)
* Clean-up: URLs normalised and de-duplicated *before* splitting, so the
  same URL can never appear in both train and test (the v1 pipeline did not
  do this, which inflates scores)
* Features: URLFeaturizer (char 1-5 grams + word 1-2 grams + 25 lexical features)
* Augmentation: ~560 curated legitimate app pages of popular sites (train split only)
* Model: L2 logistic regression (liblinear). It is fast, calibrated, and every
  prediction can be explained by its per-feature contributions
* Outputs (drop-in compatible with the existing detector):
    models/phishing_classifier.pkl   - classifier (predict / predict_proba, 1 = phishing)
    models/tfidf_vectorizer.pkl      - fitted URLFeaturizer (.transform([url]))
    models/evaluation_results.json   - held-out metrics + top indicative features
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)
from url_features import URLFeaturizer, normalize_url  # noqa: E402

DATA_CANDIDATES = [os.path.join(ROOT, "training", "phishing_site_urls.csv"),
                   os.path.join(ROOT, "phishing_site_urls.csv"),
                   os.path.join(ROOT, "data", "phishing_site_urls.csv")]
MODELS = os.path.join(ROOT, "models")

# Real-world sanity URLs with full schemes, as the extension sends them.
# Their paths are deliberately NOT in the augmentation set below.
SANITY = {
    "https://www.google.com/": 0,
    "https://github.com/login/oauth/authorize?client_id=abc123": 0,
    "https://www.wikipedia.org/": 0,
    "https://mail.google.com/mail/u/1/#sent": 0,
    "https://outlook.live.com/mail/0/": 0,
    "https://www.linkedin.com/checkpoint/lg/sign-in": 0,
    "https://www.amazon.in/gp/cart/view.html": 0,
    "https://stackoverflow.com/questions": 0,
    "https://www.kongu.ac.in/": 0,
    "https://docs.python.org/3/library/": 0,
    "http://paypal-secure-login.verify-account.tk/webscr?cmd=_login": 1,
    "http://192.168.4.20/bank/login.php": 1,
    "http://appleid.apple.com.verify-session.xyz/signin": 1,
    "http://secure-update-account.netflix.billing-support.ml/": 1,
    "http://github.com.login-session.top/verify": 1,
    "http://mail-google.com-security.xyz/mail/u/0/": 1,
}

# Dataset bias fix: the "good" URLs in the Kaggle set are mostly content pages,
# so ordinary login / inbox / account pages of popular sites look "phishy" to
# a model trained on it alone. A small curated set of legitimate app pages is
# added to the TRAINING split only (the test split is untouched).
AUGMENT_PATHS = ["", "login", "signin", "account", "settings", "home", "dashboard",
                 "mail/u/0/#inbox", "search?q=python+tutorial", "help", "profile",
                 "notifications", "account/security", "auth/login?next=%2F"]
AUGMENT_HOSTS = ["www.google.com", "accounts.google.com", "mail.google.com",
                 "drive.google.com", "github.com", "gitlab.com", "www.linkedin.com",
                 "login.live.com", "outlook.live.com", "login.microsoftonline.com",
                 "www.facebook.com", "www.instagram.com", "twitter.com", "x.com",
                 "www.amazon.in", "www.amazon.com", "www.flipkart.com", "www.netflix.com",
                 "open.spotify.com", "www.paypal.com", "appleid.apple.com", "www.icloud.com",
                 "www.dropbox.com", "slack.com", "zoom.us", "www.reddit.com",
                 "stackoverflow.com", "www.kaggle.com", "www.coursera.org", "onlinesbi.sbi",
                 "netbanking.hdfcbank.com", "www.irctc.co.in", "paytm.com", "web.whatsapp.com",
                 "discord.com", "www.notion.so", "www.canva.com", "chat.openai.com",
                 "claude.ai", "www.udemy.com"]


def augmentation_urls():
    return [f"{h}/{p}" for h in AUGMENT_HOSTS for p in AUGMENT_PATHS]


def main():
    path = next((p for p in DATA_CANDIDATES if os.path.exists(p)), None)
    if not path:
        sys.exit("Dataset phishing_site_urls.csv not found (expected in training/)")
    t0 = time.time()
    df = pd.read_csv(path).dropna()
    raw_rows = len(df)
    df["norm"] = df["URL"].map(normalize_url)
    df = df.drop_duplicates("norm")
    y = (df["Label"].str.lower() == "bad").astype(int).values
    print(f"{raw_rows:,} rows -> {len(df):,} unique URLs "
          f"({y.mean():.1%} phishing) from {os.path.relpath(path, ROOT)}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["URL"].values, y, test_size=0.2, random_state=42, stratify=y)

    aug = [u for u in augmentation_urls() if normalize_url(u) not in set(df["norm"])]
    X_train = np.concatenate([X_train, np.asarray(aug, dtype=object)])
    y_train = np.concatenate([y_train, np.zeros(len(aug), dtype=int)])
    print(f"  + {len(aug)} curated legitimate URLs added to the training split")

    print("Fitting featurizer...")
    featurizer = URLFeaturizer().fit(X_train)
    A, B = featurizer.transform(X_train), featurizer.transform(X_test)
    print(f"  {A.shape[1]:,} features")

    print("Training logistic regression...")
    model = LogisticRegression(C=10.0, solver="liblinear", max_iter=300)
    model.fit(A, y_train)

    proba = model.predict_proba(B)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall": round(float(recall_score(y_test, pred)), 4),
        "f1": round(float(f1_score(y_test, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }
    sanity_pred = model.predict_proba(featurizer.transform(list(SANITY)))[:, 1]
    sanity = [{"url": u, "expected": "phishing" if lab else "legitimate",
               "phishing_probability": round(float(p), 3),
               "correct": bool((p >= 0.5) == bool(lab))}
              for (u, lab), p in zip(SANITY.items(), sanity_pred)]

    names = np.asarray(featurizer.feature_names())
    coef = model.coef_[0]
    order = np.argsort(coef)
    top_phish = [{"feature": str(names[i]), "weight": round(float(coef[i]), 3)}
                 for i in order[::-1][:20]]
    top_legit = [{"feature": str(names[i]), "weight": round(float(coef[i]), 3)}
                 for i in order[:20]]

    os.makedirs(MODELS, exist_ok=True)
    joblib.dump(model, os.path.join(MODELS, "phishing_classifier.pkl"), compress=3)
    joblib.dump(featurizer, os.path.join(MODELS, "tfidf_vectorizer.pkl"), compress=3)

    results = {
        **metrics,
        "model_type": "LogisticRegression",
        "model_version": "2.0",
        "features": "URLFeaturizer: char 1-5 grams + word 1-2 grams + 25 lexical features",
        "n_features": int(A.shape[1]),
        "sklearn_version": sklearn.__version__,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": {"raw_rows": raw_rows, "unique_urls": int(len(df)),
                    "train_rows": int(len(X_train)), "test_rows": int(len(X_test)),
                    "augmented_legitimate_urls": len(aug),
                    "split": "stratified 80/20 after de-duplication, seed 42"},
        "sanity_checks": sanity,
        "top_phishing_indicators": top_phish,
        "top_legitimate_indicators": top_legit,
        "compatible": True,
        "train_seconds": round(time.time() - t0, 1),
    }
    with open(os.path.join(MODELS, "evaluation_results.json"), "w") as fh:
        json.dump(results, fh, indent=2)

    print(json.dumps(metrics, indent=2))
    print(f"Sanity checks: {sum(s['correct'] for s in sanity)}/{len(sanity)} correct")
    for s in sanity:
        print(f"  {'OK ' if s['correct'] else 'BAD'} {s['phishing_probability']:.3f}  {s['url']}")


if __name__ == "__main__":
    main()
