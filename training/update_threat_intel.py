"""Refresh the phishing threat-intel feed used to train the URL model.

    python training/update_threat_intel.py            # download + sample 150k URLs
    python training/train_url_model.py                # retrain on the fresh feed

Source: Phishing.Database (https://github.com/mitchellkrogza/Phishing.Database),
a community-maintained list of currently ACTIVE phishing links (MIT licence).
Phishing changes quickly, so refreshing every few weeks keeps the model current.
"""
import argparse
import os
import random
import sys

import requests

FEED = ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
        "master/phishing-links-ACTIVE.txt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "intel", "phish_feed.txt")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sample", type=int, default=150_000, help="URLs to keep (default 150k)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    print(f"Downloading {FEED} ...")
    r = requests.get(FEED, timeout=300)
    r.raise_for_status()
    urls = sorted({u.strip() for u in r.text.splitlines() if u.strip() and not u.startswith("#")})
    print(f"  {len(urls):,} active phishing URLs")
    random.Random(args.seed).shuffle(urls)
    keep = urls[: args.sample]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write("\n".join(keep) + "\n")
    print(f"Saved {len(keep):,} URLs to {os.path.relpath(OUT)}. Now run: python training/train_url_model.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
