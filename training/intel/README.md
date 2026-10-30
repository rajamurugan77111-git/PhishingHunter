# Threat-intelligence training data (v3)

| File | Source | Licence / note |
|---|---|---|
| `phish_feed.txt` | 150,000 URLs sampled from the **Phishing.Database** active-phishing feed (`phishing-links-ACTIVE.txt`, downloaded 30 Oct 2026) | https://github.com/mitchellkrogza/Phishing.Database (MIT) |
| `legit_urls.txt` | Benign URLs from the **ISCX-URL-2016** dataset (Canadian Institute for Cybersecurity), via the copy in [shreyagopal/Phishing-Website-Detection](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques) | research use |
| `top_domains.txt` | Top 10,000 domains, from [zer0h/top-1000000-domains](https://github.com/zer0h/top-1000000-domains) | home pages used as legitimate examples |

Refresh the phishing feed with `python training/update_threat_intel.py`, then retrain with
`python training/train_url_model.py`.
