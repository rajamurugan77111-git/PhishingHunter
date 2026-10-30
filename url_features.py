"""URL featurisation for the Phishing Hunter v2 URL model.

The fitted URLFeaturizer is pickled as models/tfidf_vectorizer.pkl and keeps the
same interface the detector already uses (``vectorizer.transform([url])``),
so it is a drop-in replacement for the v1 TF-IDF vectorizer.

Three complementary views of each URL are stacked into one sparse matrix:

1. Character n-grams (1-5)  - obfuscation such as "paypa1", "-secure-", "%40"
2. Word / token n-grams     - brand + action words: "paypal webscr", "verify account"
3. 25 lexical features      - length, digit ratio, IP host, risky TLD, entropy, ...

URLs are normalised first (scheme stripped, lower-cased host) so that what
the browser extension sends ("https://www.site.com/") looks like the training
data ("www.site.com/"). The v1 model skipped this step, which made it flag
well-known sites such as google.com.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable, List

import numpy as np
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEX = re.compile(r"%[0-9a-fA-F]{2}")

SUSPICIOUS_WORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "webscr", "cmd=", "ebayisapi",
    "wallet", "unlock", "suspend", "billing", "invoice", "free", "bonus", "lucky", "gift",
)
BRANDS = ("paypal", "apple", "microsoft", "office365", "outlook", "amazon", "netflix",
          "facebook", "instagram", "google", "chase", "wellsfargo", "bankofamerica",
          "dropbox", "docusign", "adobe", "ebay", "whatsapp", "binance", "coinbase")
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "zip", "mov", "click", "country",
              "work", "support", "rest", "fit", "loan", "men", "date", "racing", "review",
              "kim", "cricket", "science", "party", "link", "info", "ru", "cn"}
# Popular, well-established registered domains. Used ONLY as a learned feature
# ("host belongs to a reputable domain"), never as a hard allowlist: the model
# learns its weight from data, which also contains phishing hosted on some of
# these platforms (e.g. sites.google.com, docs.google.com forms).
TOP_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "google.co.in", "facebook.com", "instagram.com",
    "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "microsoftonline.com", "bing.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "flipkart.com", "netflix.com", "spotify.com", "github.com",
    "gitlab.com", "stackoverflow.com", "reddit.com", "wikipedia.org", "yahoo.com",
    "zoom.us", "slack.com", "dropbox.com", "adobe.com", "paypal.com", "ebay.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "onlinesbi.sbi", "paytm.com", "phonepe.com", "razorpay.com",
    "irctc.co.in", "gov.in", "nic.in", "python.org", "pypi.org", "npmjs.com", "mozilla.org",
    "w3schools.com", "geeksforgeeks.org", "coursera.org", "udemy.com", "edx.org",
    "khanacademy.org", "nptel.ac.in", "kaggle.com", "medium.com", "quora.com",
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com", "thehindu.com",
    "timesofindia.indiatimes.com", "ndtv.com", "openai.com", "anthropic.com", "claude.ai",
    "notion.so", "canva.com", "figma.com", "atlassian.com", "salesforce.com", "oracle.com",
    "ibm.com", "cisco.com", "intel.com", "nvidia.com", "samsung.com", "hp.com", "dell.com",
    "cloudflare.com", "aws.amazon.com", "azure.com", "heroku.com", "vercel.com",
    "docker.com", "twitch.tv", "discord.com", "telegram.org", "pinterest.com", "tumblr.com",
    "imdb.com", "booking.com", "airbnb.com", "uber.com", "swiggy.com", "zomato.com",
}

SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
              "adf.ly", "bitly.com", "cutt.ly", "rebrand.ly", "shorte.st"}

LEXICAL_FEATURES = [
    "url_length", "host_length", "path_length", "n_dots_host", "n_hyphens_host",
    "n_digits_ratio", "n_special", "n_at", "n_slashes", "n_query_params",
    "n_percent_encoded", "has_ip_host", "has_port", "has_punycode", "is_shortener",
    "risky_tld", "n_subdomains", "host_entropy", "suspicious_words", "brand_in_path",
    "brand_in_subdomain", "double_slash_in_path", "exe_or_php", "tilde",
    "reputable_domain",
]


def normalize_url(url: str) -> str:
    """Strip scheme and lower-case the host; keep path/query case."""
    url = (url or "").strip()
    url = _SCHEME.sub("", url)
    host, sep, rest = url.partition("/")
    return host.lower() + sep + rest


def _split(url: str):
    host, _, rest = url.partition("/")
    host = host.split("@")[-1]
    port = ""
    if ":" in host and not host.startswith("["):
        host, port = host.rsplit(":", 1)
    path, _, query = rest.partition("?")
    return host, port, "/" + path, query


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def lexical_vector(raw_url: str) -> List[float]:
    url = normalize_url(raw_url)
    host, port, path, query = _split(url)
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if labels else ""
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
    low = url.lower()
    digits = sum(ch.isdigit() for ch in url)
    return [
        len(url),
        len(host),
        len(path) + len(query),
        host.count("."),
        host.count("-"),
        digits / max(len(url), 1),
        sum(not ch.isalnum() for ch in url),
        url.count("@"),
        url.count("/"),
        query.count("=") + query.count("&"),
        len(_HEX.findall(url)),
        float(bool(_IPV4.match(host))),
        float(bool(port)),
        float("xn--" in host),
        float(host.replace("www.", "", 1) in SHORTENERS),
        float(tld in RISKY_TLDS),
        max(len(labels) - 2, 0),
        _entropy(host),
        sum(w in low for w in SUSPICIOUS_WORDS),
        float(any(b in (path + query).lower() for b in BRANDS)),
        float(any(b in subdomain for b in BRANDS)),
        float("//" in path),
        float(bool(re.search(r"\.(exe|scr|php|cgi)(\b|$)", path.lower()))),
        float("~" in url),
        float(_is_reputable(host)),
    ]


def _is_reputable(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in TOP_DOMAINS)


class URLFeaturizer(BaseEstimator, TransformerMixin):
    """Char n-grams + word n-grams + 25 lexical features, stacked (sparse)."""

    def __init__(self, char_max_features: int = 300_000, word_max_features: int = 150_000):
        self.char_max_features = char_max_features
        self.word_max_features = word_max_features

    def _build(self):
        self.char_ = TfidfVectorizer(analyzer="char", ngram_range=(1, 5), min_df=3,
                                     max_features=self.char_max_features, sublinear_tf=True,
                                     lowercase=False, dtype=np.float32)
        self.word_ = TfidfVectorizer(analyzer="word", token_pattern=r"[A-Za-z0-9]{2,}",
                                     ngram_range=(1, 2), min_df=2,
                                     max_features=self.word_max_features, sublinear_tf=True,
                                     dtype=np.float32)
        self.lex_scaler_ = MaxAbsScaler()

    def fit(self, urls: Iterable[str], y=None):
        urls = [normalize_url(u) for u in urls]
        self._build()
        self.char_.fit(urls)
        self.word_.fit(urls)
        self.lex_scaler_.fit(np.asarray([lexical_vector(u) for u in urls], dtype=np.float32))
        return self

    def transform(self, urls: Iterable[str]):
        urls = [normalize_url(u) for u in urls]
        lex = self.lex_scaler_.transform(
            np.asarray([lexical_vector(u) for u in urls], dtype=np.float32))
        return sparse.hstack([self.char_.transform(urls), self.word_.transform(urls),
                              sparse.csr_matrix(lex)], format="csr")

    def feature_names(self) -> List[str]:
        return ([f"char:{t}" for t in self.char_.get_feature_names_out()] +
                [f"word:{t}" for t in self.word_.get_feature_names_out()] +
                [f"lex:{n}" for n in LEXICAL_FEATURES])


def unwrap(model):
    """Return (inner_estimator, decision_threshold) for a possibly thresholded model."""
    from sklearn.model_selection import FixedThresholdClassifier
    if isinstance(model, FixedThresholdClassifier):
        return model.estimator_, float(model.threshold)
    return model, 0.5


def explain(url: str, model, featurizer: "URLFeaturizer", top: int = 8) -> dict:
    """Explain one prediction of the linear URL model.

    For logistic regression the log-odds are exactly sum(weight_i * value_i) + bias,
    so each feature's contribution is exact (not an approximation like LIME).
    """
    x = featurizer.transform([url]).tocsr()
    est, threshold = unwrap(model)
    coef = est.coef_[0]
    idx = x.indices
    contrib = x.data * coef[idx]
    names = featurizer.feature_names()
    order = np.argsort(contrib)
    proba = float(est.predict_proba(x)[0, 1])

    def fmt(i):
        return {"feature": names[idx[i]], "contribution": round(float(contrib[i]), 3)}

    return {
        "url": url,
        "normalized": normalize_url(url),
        "phishing_probability": round(proba, 4),
        "prediction": "phishing" if proba >= threshold else "legitimate",
        "decision_threshold": threshold,
        "bias": round(float(est.intercept_[0]), 3),
        "toward_phishing": [fmt(i) for i in order[::-1][:top] if contrib[i] > 0],
        "toward_legitimate": [fmt(i) for i in order[:top] if contrib[i] < 0],
        "lexical": dict(zip(LEXICAL_FEATURES, lexical_vector(url))),
    }
