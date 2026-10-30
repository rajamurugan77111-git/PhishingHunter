"""Shared imports, availability flags, logger and base classes."""

import os
import sys
import re

# The v2 URL model pickles a URLFeaturizer from url_features.py (project root);
# make sure it is importable however this module is launched.
_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # project root
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
try:
    import url_features  # noqa: F401
except Exception:  # pragma: no cover - only needed for the v2 model
    pass
import urllib.parse
import tldextract
import socket
from datetime import datetime, timedelta

# Import whois implementations
IMPROVED_WHOIS_AVAILABLE = False
STANDARD_WHOIS_AVAILABLE = False
ImprovedWhois = None  # optional; used only when IMPROVED_WHOIS_AVAILABLE
whois = None          # optional; used only when STANDARD_WHOIS_AVAILABLE

# Try to import our improved WHOIS implementation first
try:
    from improved_whois import ImprovedWhois
    IMPROVED_WHOIS_AVAILABLE = True
except ImportError:
    pass

# Try to import standard whois as fallback
try:
    import whois
    STANDARD_WHOIS_AVAILABLE = True
except ImportError:
    pass
from typing import Dict, List, Any, Optional, Tuple
import joblib
import json
import logging
from enum import Enum

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('phishing_detector')


class RiskLevel(Enum):
    """Risk level enumeration for clear classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"


class DetectionLayer:
    """Base class for detection layers."""
    
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
        self.enabled = True
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL and return results."""
        raise NotImplementedError
