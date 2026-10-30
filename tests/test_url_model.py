"""Tests for the v2 URL model, explainability and featurizer."""
import json
import os
import sys

import joblib
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from url_features import LEXICAL_FEATURES, explain, lexical_vector, normalize_url, unwrap  # noqa: E402


@pytest.fixture(scope="module")
def model():
    m = joblib.load(os.path.join(ROOT, "models", "phishing_classifier.pkl"))
    v = joblib.load(os.path.join(ROOT, "models", "tfidf_vectorizer.pkl"))
    return m, v


def phish_prob(model, url):
    m, v = model
    return float(m.predict_proba(v.transform([url]))[0, 1])


def is_phish(model, url):
    m, v = model
    return bool(m.predict(v.transform([url]))[0] == 1)


def test_normalize_strips_scheme_and_lowercases_host():
    assert normalize_url("HTTPS://WWW.Example.COM/Path?A=B") == "www.example.com/Path?A=B"
    assert normalize_url("example.com") == "example.com"


def test_lexical_vector_shape_and_signals():
    vec = dict(zip(LEXICAL_FEATURES, lexical_vector("http://192.168.0.1:8080/login.php")))
    assert len(vec) == len(LEXICAL_FEATURES)
    assert vec["has_ip_host"] == 1.0 and vec["has_port"] == 1.0 and vec["exe_or_php"] == 1.0
    assert vec["reputable_domain"] == 0.0
    assert dict(zip(LEXICAL_FEATURES, lexical_vector("https://mail.google.com/")))["reputable_domain"] == 1.0


@pytest.mark.parametrize("url", [
    "https://www.google.com/",
    "https://github.com/login/oauth/authorize?client_id=x",
    "https://mail.google.com/mail/u/2/#starred",
    "https://www.wikipedia.org/",
    "https://docs.python.org/3/tutorial/",
])
def test_legitimate_urls(model, url):
    assert not is_phish(model, url)


@pytest.mark.parametrize("url", [
    "http://paypal-secure-login.verify-account.tk/webscr?cmd=_login",
    "http://192.168.4.20/bank/login.php",
    "http://appleid.apple.com.verify-session.xyz/signin",
    "http://github.com.login-session.top/verify",
])
def test_phishing_urls(model, url):
    assert is_phish(model, url)


def test_scheme_does_not_change_verdict(model):
    """v1 bug: adding https:// changed the prediction. v2 normalises it away."""
    for u in ["www.google.com/", "paypal-secure-login.verify-account.tk/webscr"]:
        assert abs(phish_prob(model, u) - phish_prob(model, "https://" + u)) < 1e-6


def test_threshold_is_calibrated(model):
    m, _ = model
    _, thr = unwrap(m)
    assert 0.3 <= thr <= 0.95


def test_explanation_is_exact_for_linear_model(model):
    import math
    m, v = model
    e = explain("http://appleid.apple.com.verify-session.xyz/signin", m, v, top=10**6)
    logit = e["bias"] + sum(c["contribution"] for c in e["toward_phishing"] + e["toward_legitimate"])
    assert abs(1 / (1 + math.exp(-logit)) - e["phishing_probability"]) < 0.01
    assert e["prediction"] == "phishing"


def test_evaluation_results_recorded():
    with open(os.path.join(ROOT, "models", "evaluation_results.json")) as fh:
        r = json.load(fh)
    assert r["model_version"] == "3.0"
    assert r["roc_auc"] > 0.99
    fresh = r["fresh_2026_unseen_websites"]
    assert fresh["roc_auc"] > 0.98 and fresh["false_positive_rate"] < 0.05
    assert all(s["correct"] for s in r["sanity_checks"])
