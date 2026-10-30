# Phishing Hunter: URL model evaluation

All numbers are reproducible with `python training/train_url_model.py`, whose output is stored in
`models/evaluation_results.json`.

## 1. Fresh 2026 phishing on unseen websites (the realistic test)

Test set: 42,886 URLs from **websites (registered domains) that never appear in
training**. The phishing URLs come from the *currently active* Phishing.Database feed (October 2026).
The legitimate URLs are ISCX-URL-2016 benign links plus top-10k home pages. Every model is scored
on exactly the same URLs.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | False alarms on legit |
|---|---|---|---|---|---|---|
| v1 | 54.8% | 87.7% | 50.0% | 0.637 | 0.708 | 27.0% |
| v2 | 86.5% | 94.5% | 88.1% | 0.912 | 0.921 | 19.6% |
| v3 | 96.8% | 97.5% | 98.5% | 0.980 | 0.993 | 9.7% |
| v4 | 93.3% | 99.2% | 92.4% | 0.956 | 0.991 | 3.1% |

- **v1:** the original random forest. It misses half of today's phishing.
- **v2:** scheme normalisation + richer features (Kaggle data only).
- **v3:** + 151k threat-intel URLs.
- **v4 (deployed):** + class re-balancing + a decision threshold (**0.92**)
  calibrated on a separate *validation* set of unseen websites to keep false alarms at or below 2%.
  On test it gives 3.1% false alarms with
  99.2% precision.

v3 has higher recall; v4 trades a few points of recall for **3× fewer false alarms**. For a browser
extension that warns users in real time, false alarms are the costlier error, and the other
detection layers (content, WHOIS, behaviour) still back up the ML layer.

## 2. Kaggle holdout (older, in-distribution)

| Model | Accuracy | F1 | ROC-AUC | False alarms |
|---|---|---|---|---|
| v2 | 98.6% | 0.968 | 0.998 | 0.5% |
| v4 (deployed) | 97.1% | 0.931 | 0.997 | 0.08% |

v4's recall on the *old* Kaggle phishing is lower (87.3%) because of the
conservative threshold. ROC-AUC is unchanged, so the ranking quality is the same; only the
operating point moved.

## 3. Real-world sanity checks

16/16 correct, including
look-alikes such as `github.com.login-session.top` and legitimate login and inbox pages of
Google, GitHub, Outlook and LinkedIn.

## Limitations

- The legitimate side of the fresh test set is ISCX-2016 plus home pages. A crawl of modern,
  deep legitimate pages would make the false-alarm estimate stronger.
- The Phishing.Database feed is community-curated and may contain some mislabelled URLs.
- The DistilBERT email model's training data and metrics are not documented in this repository,
  so its accuracy is not claimed here. The pattern engine is the verified email path.
