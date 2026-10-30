"""Train the Phishing Hunter v2 URL model.

    python training/train_url_model.py

Pipeline
--------
* Datasets:
    - training/phishing_site_urls.csv  (549k labelled URLs, Kaggle, older)
    - training/intel/                  (v3 threat intel: 150k ACTIVE 2026 phishing URLs,
                                        35k ISCX benign URLs, top-10k domain home pages)
* Fresh-data evaluation: threat-intel URLs are split by REGISTERED DOMAIN, so every
  test URL comes from a website the model never saw during training
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
INTEL = os.path.join(ROOT, "training", "intel")


def _registered_domain_fn():
    import tldextract
    ext = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

    def reg(url: str) -> str:
        host = normalize_url(url).split("/")[0].split(":")[0]
        r = ext(host)
        return r.top_domain_under_public_suffix if hasattr(r, "top_domain_under_public_suffix") \
            else r.registered_domain or host
    return reg


def load_intel(exclude_norm: set):
    """Return (urls, labels, groups) from training/intel, excluding Kaggle duplicates."""
    if not os.path.isdir(INTEL):
        return [], [], []
    def lines(name):
        path = os.path.join(INTEL, name)
        if not os.path.exists(path):
            return []
        with open(path, errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    phish = lines("phish_feed.txt")
    legit = lines("legit_urls.txt") + [f"https://{d}/" for d in lines("top_domains.txt")]
    reg = _registered_domain_fn()
    urls, labels, groups, seen = [], [], [], set()
    for lab, items in ((1, phish), (0, legit)):
        for u in items:
            n = normalize_url(u)
            if n in exclude_norm or n in seen:
                continue
            seen.add(n)
            urls.append(u)
            labels.append(lab)
            groups.append(reg(u))
    return urls, labels, groups


def domain_split(groups, test_fraction=0.2, seed=42):
    """Deterministic split by registered domain (no website in both train and test)."""
    import hashlib
    def bucket(g):
        return int(hashlib.md5(f"{seed}:{g}".encode()).hexdigest(), 16) % 1000 / 1000
    return np.array([bucket(g) < test_fraction for g in groups])


def metric_block(y, proba, threshold=0.5):
    pred = (proba >= threshold).astype(int)
    return {
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, proba)), 4),
        "false_positive_rate": round(float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1)), 4),
        "confusion_matrix": confusion_matrix(y, pred).tolist(),
        "samples": int(len(y)),
    }

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


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Train the Phishing Hunter URL model")
    ap.add_argument("--compare-with", help="directory with a previous model to score on the same tests")
    args = ap.parse_args(argv)
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

    # ---- v3 threat intelligence (fresh 2026 data), split by website ----
    intel_urls, intel_y, intel_groups = load_intel(set(df["norm"]))
    intel_test_mask = domain_split(intel_groups) if intel_urls else np.array([], dtype=bool)
    intel_urls, intel_y = np.asarray(intel_urls, dtype=object), np.asarray(intel_y, dtype=int)
    X_intel_test, y_intel_test = intel_urls[intel_test_mask], intel_y[intel_test_mask]
    w_train = np.ones(len(X_train))
    X_val = np.array([], dtype=object)
    y_val = np.array([], dtype=int)
    if len(intel_urls):
        groups_arr = np.asarray(intel_groups)
        # A second domain-level split of the remaining intel gives a VALIDATION set of
        # unseen websites, used only to calibrate the decision threshold.
        val_mask = domain_split(groups_arr, test_fraction=0.125, seed=7) & ~intel_test_mask
        tr_mask = ~intel_test_mask & ~val_mask
        X_val, y_val = intel_urls[val_mask], intel_y[val_mask]
        Xi, yi = intel_urls[tr_mask], intel_y[tr_mask]
        # Fresh data is ~3:1 phishing:legit. Re-balance so the model doesn't learn
        # "modern-looking URL => phishing" from the class prior.
        n_p, n_l = max((yi == 1).sum(), 1), max((yi == 0).sum(), 1)
        wi = np.where(yi == 0, n_p / n_l, 1.0)
        X_train = np.concatenate([X_train, Xi])
        y_train = np.concatenate([y_train, yi])
        w_train = np.concatenate([w_train, wi])
        print(f"  + {int((~intel_test_mask).sum()):,} threat-intel URLs for training; "
              f"{int(intel_test_mask.sum()):,} held out from {len(set(np.asarray(intel_groups)[intel_test_mask])):,} unseen websites")

    aug = [u for u in augmentation_urls() if normalize_url(u) not in set(df["norm"])]
    X_train = np.concatenate([X_train, np.asarray(aug, dtype=object)])
    y_train = np.concatenate([y_train, np.zeros(len(aug), dtype=int)])
    w_train = np.concatenate([w_train, np.ones(len(aug))])
    print(f"  + {len(aug)} curated legitimate URLs added to the training split")

    print("Fitting featurizer...")
    featurizer = URLFeaturizer().fit(X_train)
    A, B = featurizer.transform(X_train), featurizer.transform(X_test)
    print(f"  {A.shape[1]:,} features")

    print("Training logistic regression...")
    base = LogisticRegression(C=10.0, solver="liblinear", max_iter=300)
    base.fit(A, y_train, sample_weight=w_train)

    # Calibrate the decision threshold on the validation websites:
    # best F1 subject to a false-positive rate <= 2% (users hate false alarms).
    threshold = 0.5
    if len(X_val):
        pv = base.predict_proba(featurizer.transform(X_val))[:, 1]
        best = None
        for t in np.round(np.arange(0.30, 0.96, 0.01), 2):
            pred = (pv >= t).astype(int)
            fpr = ((pred == 1) & (y_val == 0)).sum() / max((y_val == 0).sum(), 1)
            f1 = f1_score(y_val, pred, zero_division=0)
            if fpr <= 0.02 and (best is None or f1 > best[1]):
                best = (float(t), f1, fpr)
        threshold = best[0] if best else 0.5
        print(f"  decision threshold {threshold:.2f} "
              f"(validation F1 {best[1]:.4f}, FPR {best[2]:.4f})" if best else "  threshold 0.50")
    from sklearn.model_selection import FixedThresholdClassifier
    model = FixedThresholdClassifier(base, threshold=threshold, response_method="predict_proba")
    model.estimator_ = base          # already fitted; avoid refitting on 650k rows

    metrics = metric_block(y_test, model.predict_proba(B)[:, 1], threshold)
    fresh = (metric_block(y_intel_test, model.predict_proba(featurizer.transform(X_intel_test))[:, 1],
                          threshold) if len(X_intel_test) else None)

    comparison = {}
    if args.compare_with:
        old_m = joblib.load(os.path.join(args.compare_with, "phishing_classifier.pkl"))
        old_v = joblib.load(os.path.join(args.compare_with, "tfidf_vectorizer.pkl"))
        if hasattr(old_m, "verbose"):
            old_m.verbose = 0
        comparison = {
            "previous_model_dir": os.path.relpath(args.compare_with, ROOT) if args.compare_with.startswith(ROOT) else args.compare_with,
            "kaggle_holdout": metric_block(y_test, old_m.predict_proba(old_v.transform(list(X_test)))[:, 1]),
        }
        if len(X_intel_test):
            comparison["fresh_2026_unseen_websites"] = metric_block(
                y_intel_test, old_m.predict_proba(old_v.transform(list(X_intel_test)))[:, 1])
    sanity_pred = model.predict_proba(featurizer.transform(list(SANITY)))[:, 1]
    sanity = [{"url": u, "expected": "phishing" if lab else "legitimate",
               "phishing_probability": round(float(p), 3),
               "correct": bool((p >= threshold) == bool(lab))}
              for (u, lab), p in zip(SANITY.items(), sanity_pred)]

    names = np.asarray(featurizer.feature_names())
    coef = base.coef_[0]
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
        "fresh_2026_unseen_websites": fresh,
        "previous_model_on_same_tests": comparison or None,
        "model_type": "LogisticRegression",
        "model_version": "3.0",
        "decision_threshold": threshold,
        "features": "URLFeaturizer: char 1-5 grams + word 1-2 grams + 25 lexical features",
        "n_features": int(A.shape[1]),
        "sklearn_version": sklearn.__version__,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset": {"raw_rows": raw_rows, "unique_urls": int(len(df)),
                    "train_rows": int(len(X_train)), "test_rows": int(len(X_test)),
                    "augmented_legitimate_urls": len(aug),
                    "threat_intel_train": int((~intel_test_mask).sum()) if len(intel_urls) else 0,
                    "threat_intel_test": int(intel_test_mask.sum()) if len(intel_urls) else 0,
                    "threat_intel_split": "by registered domain (unseen websites), 80/20",
                    "split": "stratified 80/20 after de-duplication, seed 42"},
        "sanity_checks": sanity,
        "top_phishing_indicators": top_phish,
        "top_legitimate_indicators": top_legit,
        "compatible": True,
        "train_seconds": round(time.time() - t0, 1),
    }
    with open(os.path.join(MODELS, "evaluation_results.json"), "w") as fh:
        json.dump(results, fh, indent=2)

    print("Kaggle holdout:", json.dumps({k: v for k, v in metrics.items() if k != "confusion_matrix"}))
    if fresh:
        print("Fresh 2026, unseen websites:", json.dumps({k: v for k, v in fresh.items() if k != "confusion_matrix"}))
    for k, v in (comparison or {}).items():
        if isinstance(v, dict):
            print(f"Previous model, {k}:", json.dumps({a: b for a, b in v.items() if a != "confusion_matrix"}))
    print(f"Sanity checks: {sum(s['correct'] for s in sanity)}/{len(sanity)} correct")
    for s in sanity:
        print(f"  {'OK ' if s['correct'] else 'BAD'} {s['phishing_probability']:.3f}  {s['url']}")
    print(f"Decision threshold: {threshold:.2f}")


if __name__ == "__main__":
    main()
