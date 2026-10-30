# Phishing Hunter — AI-Powered Phishing Detection

![tests](https://github.com/<your-username>/PhishingHunter/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![chrome](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4)

A Chrome extension and Flask API that detect phishing websites and emails in real time. The
system combines a **multi-layer detection engine** with **explainable machine learning**:
URL classification, page-content analysis, behavioural monitoring and a DistilBERT email
classifier.

---

## What's new in v4: a threat-intel-trained, explainable URL model

The URL model is evaluated where it matters: on **currently active 2026 phishing**, from
**websites it has never seen** (split by registered domain). See
[docs/EVALUATION.md](docs/EVALUATION.md) for the full report.

| Model | Accuracy | Precision | Recall | ROC-AUC | False alarms on legit sites |
|---|---|---|---|---|---|
| v1 (original random forest) | 54.8% | 87.7% | 50.0% | 0.708 | 27.0% |
| v2 (better features) | 86.5% | 94.5% | 88.1% | 0.921 | 19.6% |
| **v4 (deployed)** | **93.3%** | **99.2%** | **92.4%** | **0.991** | **3.1%** |

*42,886 test URLs from 18,781 unseen websites. Phishing comes from the live
Phishing.Database feed (October 2026).*

### What changed and why

1. **The scheme bug is fixed.** v1 trained on URLs without `https://` but scored full URLs
   from the browser, so it flagged google.com as phishing. Every URL is now normalised the
   same way for training and for prediction.
2. **Richer features (450k).** Character 1-5 grams, word 1-2 grams and 25 lexical features:
   IP host, risky TLD, host entropy, brand in subdomain, punycode, shorteners, and a learned
   reputable-domain signal.
3. **Threat-intelligence training.** 151k currently active phishing URLs, plus modern
   legitimate URLs, are added to the 507k-URL Kaggle set.
   `python training/update_threat_intel.py` refreshes the feed.
4. **Honest evaluation.** URLs are de-duplicated before splitting, and fresh data is split by
   website, so no site appears in both training and test.
5. **Calibrated for real users.** Classes are re-balanced, and the decision threshold is
   tuned on a separate validation set of unseen websites to keep false alarms at or below 2%.
   On the test set it gives 3.1% false alarms at 99.2% precision.
6. **Explainable by construction.** For a linear model the log-odds are exactly
   Σ weightᵢ·valueᵢ + bias, so the popup's "Why?" box shows exact per-feature
   contributions rather than approximations.

<p align="center"><img src="docs/ai_explanation.png" width="360" alt="AI explanation in the popup"></p>

```bash
curl "http://localhost:5000/explain_url?url=http://appleid.apple.com.verify-session.xyz/signin"
```

```json
{
  "prediction": "phishing", "phishing_probability": 1.0,
  "toward_phishing":  [{"feature": "lex:suspicious_words", "contribution": 3.27},
                       {"feature": "lex:host_entropy", "contribution": 2.59},
                       {"feature": "lex:brand_in_subdomain", "contribution": 1.78}],
  "toward_legitimate": [{"feature": "lex:n_dots_host", "contribution": -0.85}]
}
```

---

## Features

### 🛡️ Website protection
- **6-layer detection engine**: basic validation and allowlist → feature analysis
  (WHOIS, SSL, domain) → content analysis → ML classification → ensemble decision → final
  verdict
- **Real-time notifications** while browsing, plus a manual scan from the popup
- **Content and behaviour analysis**: HTML source patterns, suspicious forms, redirects

### 📧 Email phishing detection
- **DistilBERT classifier** with 4 classes: Safe, Suspicious, Phishing, Malware
  (optional; see below)
- **Pattern engine** (always on): urgency, financial pressure, credential requests,
  suspicious links, sender-domain checks
- **Automatic compose detection** in Gmail, Outlook and Yahoo Mail

### 📊 User experience
- Modern popup UI with scan, email, history and settings tabs
- Detailed reports with recommendations
- A user-feedback loop for future retraining

---

## Architecture

```
┌──────────────┐   ┌────────────────┐   ┌────────────────────┐
│ Website /    │──►│ Content script │──►│ Background worker  │── notifications
│ Email page   │   │ (DOM, compose) │   │ (monitoring)       │
└──────────────┘   └────────────────┘   └─────────┬──────────┘
                                                  │ REST
┌──────────────┐                        ┌─────────▼──────────┐
│ Popup UI     │◄──────────────────────►│ Flask API          │
│ + AI "Why?"  │   /check_url           │ api_server.py      │
└──────────────┘   /explain_url         └─────────┬──────────┘
                                                  │
              ┌───────────────────────────────────┼───────────────────────────┐
              ▼                                   ▼                           ▼
   LayeredPhishingDetector            URL model v4 (url_features.py)   DistilBERT email model
   (detector/ package)                LogReg on 450k features          (optional, models/email)
```

---

## Installation

### 1. Backend

```bash
git clone https://github.com/<your-username>/PhishingHunter.git
cd PhishingHunter
python -m venv venv
# Windows: venv\Scripts\activate      macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python api_server.py
```

The API starts on `http://localhost:5000`. The URL model is included in the repo, so no
training is needed.

Or with Docker: `cp .env.example .env` (set `PH_API_KEY`), then `docker compose up -d --build`.

### Production security

| Setting | Purpose |
|---|---|
| `PH_API_KEY` | Required on every endpoint except `/health`. Paste the same key into the extension under **Settings → API server key** |
| `PH_ADMIN_KEY` | Separate key for the admin endpoints `/retrain_model` and `/learning_stats` |
| `PH_DEBUG=0` | The debug console stays off (default), because it allows remote code execution |

The server runs on **waitress**, a production WSGI server, and is rate-limited to 100
requests/min per client. Keys are compared in constant time.

### 2. Chrome extension

1. Open `chrome://extensions/` and turn on **Developer mode**.
2. Click **Load unpacked** and select the `chrome_extension/` folder.
3. Pin **Enhanced Phishing Hunter** to the toolbar.

### 3. (Optional) DistilBERT email model

The fine-tuned email model (`model.safetensors`, 268 MB) is **not stored in this repository**,
because GitHub rejects files larger than 100 MB. Without it, email analysis automatically falls
back to the pattern engine. To enable it:

1. Get `model.safetensors` from the project's
   [Releases](https://github.com/<your-username>/PhishingHunter/releases) page, or from the
   original project archive.
2. Put it in `models/email/`. The tokenizer and config files are already there.
3. Install the extra dependencies: `pip install -r requirements-email.txt`

---

## Retraining the URL model

```bash
python training/update_threat_intel.py   # optional: pull the latest active-phishing feed
python training/train_url_model.py       # about 15 min on a laptop
```

This re-creates `models/phishing_classifier.pkl`, `models/tfidf_vectorizer.pkl` and
`models/evaluation_results.json`, which holds the Kaggle-holdout and unseen-website metrics,
the calibrated threshold, sanity checks and top indicators. The data comes from
`training/phishing_site_urls.csv` (549k Kaggle URLs) and `training/intel/` (see its README for
sources and licences). The original v1 script is kept as `training/train.py` for reference.

---

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/check_url?url=<url>` | Quick multi-layer URL check |
| POST | `/analyze_detailed` | Comprehensive website analysis |
| POST | `/analyze_source` | HTML source analysis |
| GET/POST | `/explain_url` | Explain the ML verdict for a URL (exact feature contributions) |
| GET | `/model_info` | URL-model metrics, threshold and top indicators |
| POST | `/analyze_email` | Full email analysis (AI + patterns) |
| POST | `/check_email_quick` | Fast pattern-based email check |
| GET | `/health` | Server health |
| POST | `/feedback` | Submit user feedback |
| GET | `/learning_stats` | Feedback statistics |

---

## Testing

```bash
pip install pytest
pytest -v
```

The 25 tests cover API-key and admin-key enforcement, and URL normalisation, lexical features, legitimate and phishing URLs, the
scheme-invariance bug fix, threshold calibration, exact explanations, recorded fresh-data
metrics, and the API endpoints including the email fallback. They run on every push via
GitHub Actions.

---

## Project structure

```
PhishingHunter/
├── api_server.py              # Flask REST API
├── phishing_detector.py       # compatibility entry point (re-exports detector/)
├── detector/                  # 6-layer detection engine, one module per layer
│   ├── layer1_validation.py   #   allowlist + URL validation
│   ├── layer2_features.py     #   domain / WHOIS / SSL features
│   ├── layer3_content.py      #   page content + behaviour
│   ├── layer4_ml.py, ml_model.py  # ML classification + model loading
│   ├── decision.py            #   layers 5-6: ensemble + final verdict
│   ├── pipeline.py            #   LayeredPhishingDetector
│   └── url_heuristics.py      #   hand-crafted features + rule fallback
├── content_analyzer.py        # HTML/content analysis
├── url_features.py            # URL featurizer + exact explanations
├── email_phishing_ml/         # email detector helpers
├── chrome_extension/          # Manifest V3 extension (popup, background, content script,
│                              #   api_auth.js adds the API key to server requests)
├── models/                    # URL model (v4) + email tokenizer/config
├── training/
│   ├── train_url_model.py     # v4 training + fresh-data evaluation
│   ├── update_threat_intel.py # refresh the active-phishing feed
│   ├── train.py               # v1 pipeline (reference)
│   ├── intel/                 # threat intel: 150k active phishing + legit URLs
│   └── phishing_site_urls.csv # Kaggle dataset (549k URLs)
├── tests/                     # pytest suite
└── docs/
```

---

## Troubleshooting

- **The extension can't connect:** start `python api_server.py` and check that
  `http://localhost:5000/health` responds.
- **"ML model not found":** run `python training/train_url_model.py`.
- **Email AI not used:** the DistilBERT weights are missing. See step 3 of Installation;
  the pattern engine still works without them.

## License

MIT. See [LICENSE](LICENSE).

---

**Note:** this project is for educational and security purposes. Always be careful with
suspicious websites and emails, and never give personal information to unverified sources.
