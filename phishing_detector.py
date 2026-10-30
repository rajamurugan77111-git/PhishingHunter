"""Phishing Hunter detection engine - compatibility entry point.

The implementation now lives in the `detector/` package (one module per layer).
This module re-exports everything so existing imports keep working:

    from phishing_detector import LayeredPhishingDetector, RiskLevel, extract_features
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detector import *  # noqa: F401,F403
from detector import LayeredPhishingDetector, RiskLevel  # noqa: F401
from detector.common import json, logger  # noqa: F401


def main() -> None:
    """
    Main function demonstrating the layered phishing detection system with GPU support.
    """
    print("🛡️  Layered Phishing Detection System v3.0 - GPU Accelerated")
    print("="*70)
    
    # Initialize the layered detector
    detector = LayeredPhishingDetector()
    
    # Check GPU status
    try:
        import xgboost as xgb
        gpu_count = 0
        try:
            # xgboost.gpu may not exist in all versions, so check for CUDA support
            gpu_count = xgb.rabit.get_num_processes() if hasattr(xgb, "rabit") else 0
        except Exception:
            pass
        if gpu_count > 0:
            print(f"🚀 GPU acceleration available: {gpu_count} device(s)")
        else:
            print("🔄 Running on CPU (no GPU detected for XGBoost)")
    except ImportError:
        print("🔄 XGBoost not installed or no GPU support detected")

    print()
    print("Enter a URL to analyze (or 'exit' to quit):")
    while True:
        url = input("URL: ").strip()
        if url.lower() == 'exit':
            print("Exiting.")
            break
        if not url:
            continue

        print("\nAnalyzing URL, please wait...\n")
        results = detector.analyze_url(url)
        final_result = results.get('final_result', {})
        verdict = final_result.get('final_verdict', 'ERROR')
        risk = final_result.get('risk_percentage', 50)
        confidence = final_result.get('confidence', 0.0)
        recommendations = final_result.get('recommendations', [])

        print(f"Verdict: {verdict}")
        print(f"Risk Score: {risk:.1f}%")
        print(f"Confidence: {confidence:.2f}")
        if recommendations:
            print("Recommendations:")
            for rec in recommendations:
                print(f" - {rec}")
        print("="*70)

if __name__ == "__main__":
    main()
