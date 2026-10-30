from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import time
import os
import sys
import importlib.util
import re
import urllib.parse
import ssl
import socket
from functools import wraps
import requests
import subprocess
try:
    import whois
except ImportError:
    whois = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import BeautifulSoup for HTML parsing
try:
    from bs4 import BeautifulSoup
    logger.info("BeautifulSoup4 imported successfully")
except ImportError:
    logger.error("BeautifulSoup4 is not installed. Please install it with: pip install beautifulsoup4")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
        from bs4 import BeautifulSoup
        logger.info("BeautifulSoup4 installed and imported successfully")
    except Exception as e:
        logger.error(f"Failed to install BeautifulSoup4: {e}")
        BeautifulSoup = None

# Try to import urllib3 and disable warnings
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    logger.warning("urllib3 not available - SSL warnings may appear")

# Ensure scikit-learn is installed before importing phishing_detector
try:
    import sklearn
    logger.info(f"scikit-learn version: {sklearn.__version__}")
except ImportError:
    logger.error("scikit-learn is not installed. Please install it with: pip install scikit-learn>=1.0.0")
    if input("Attempt to install scikit-learn now? (y/n): ").lower() == 'y':
        import subprocess
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "scikit-learn>=1.0.0"])
            logger.info("scikit-learn installed successfully. Continuing...")
        except Exception as e:
            logger.error(f"Failed to install scikit-learn: {e}")
            sys.exit(1)
    else:
        sys.exit(1)

# Now try to import from phishing_detector
try:
    from phishing_detector import LayeredPhishingDetector, RiskLevel, extract_features
except ImportError as e:
    logger.error(f"Error importing phishing detector: {e}")
    logger.error("This might be due to missing dependencies or incorrect paths")
    logger.error("Please ensure all dependencies are installed and try again")
    sys.exit(1)

# Try to import email analysis dependencies
try:
    import torch
    from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
    import numpy as np
    logger.info("Email analysis dependencies imported successfully")
    EMAIL_ANALYSIS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Email analysis dependencies not available: {e}")
    logger.warning("Email analysis will be limited to basic pattern matching")
    EMAIL_ANALYSIS_AVAILABLE = False

# Security Configuration
API_KEY = os.environ.get("PHISHING_API_KEY", "dev-phishing-detector-2025")
TRUSTED_ORIGINS = [
    "chrome-extension://*",  # Allow any Chrome extension (can be further restricted)
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5000",  # For testing
    "http://127.0.0.1:5000"
]

# Input validation function
def is_valid_url(url):
    """Validate URL format and basic security checks."""
    if not url or len(url) > 2000:  # Prevent extremely long URLs
        return False
    
    # Basic URL format validation
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    if not re.match(url_pattern, url):
        return False
    
    # Block local/private IPs for security
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if hostname:
            # Block localhost, private IPs
            if hostname in ['localhost', '127.0.0.1', '0.0.0.0'] or hostname.startswith('192.168.') or hostname.startswith('10.'):
                return False
    except:
        pass
    
    return True

# API Key authentication decorator
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # For development, allow requests without API key from localhost
        if request.remote_addr in ['127.0.0.1', 'localhost']:
            return f(*args, **kwargs)
        
        key = request.headers.get('X-API-KEY') or request.args.get('api_key')
        if key != API_KEY:
            logger.warning(f"Unauthorized API access attempt from {request.remote_addr}")
            return jsonify({'error': 'Unauthorized - Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

# Update CORS configuration to be more secure
app = Flask(__name__)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute", "1000 per hour"],
    storage_uri="memory://"
)

CORS(app, resources={
    r"/*": {
        "origins": TRUSTED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-KEY"],
        "supports_credentials": False  # Disable credentials for security
    }
})

# Initialize the detector globally with retry mechanism
detector = None
MAX_INIT_ATTEMPTS = 3

# Initialize email analysis model
email_model = None
email_tokenizer = None

def initialize_detector():
    """Initialize the layered phishing detector with retries."""
    global detector
    
    for attempt in range(1, MAX_INIT_ATTEMPTS + 1):
        try:
            logger.info(f"Initializing detector (attempt {attempt}/{MAX_INIT_ATTEMPTS})...")
            
            # Check if models exist before initializing
            models_dir = os.path.join(os.path.dirname(__file__), 'models')
            model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
            vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
            
            if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
                logger.warning("ML models not found - detector will run with limited functionality")
                logger.info("To enable full ML capabilities, run: python training/train_url_model.py")
            
            detector = LayeredPhishingDetector()
            logger.info("✅ Layered phishing detector initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize detector (attempt {attempt}): {e}")
            if attempt < MAX_INIT_ATTEMPTS:
                wait_time = 2 * attempt  # Exponential backoff
                logger.info(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
    
    logger.error(f"Failed to initialize detector after {MAX_INIT_ATTEMPTS} attempts")
    return False

def initialize_email_model():
    """Initialize the email phishing detection model."""
    global email_model, email_tokenizer
    
    if not EMAIL_ANALYSIS_AVAILABLE:
        logger.warning("Email analysis dependencies not available")
        return False
    
    try:
        logger.info("Initializing email phishing detection model...")
        
        # Path to email model
        email_model_dir = os.path.join(os.path.dirname(__file__), 'models', 'email')
        
        if not os.path.exists(email_model_dir):
            logger.warning("Email model directory not found")
            return False
        
        # Load tokenizer and model
        email_tokenizer = DistilBertTokenizer.from_pretrained(email_model_dir)
        email_model = DistilBertForSequenceClassification.from_pretrained(email_model_dir)
        
        # Set to evaluation mode
        email_model.eval()
        
        logger.info("✅ Email phishing detection model initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize email model: {e}")
        return False

# Initialize detector on startup
if not initialize_detector():
    logger.error("Failed to initialize detector - API will return errors")
    logger.warning("API server will start but detector-dependent endpoints will return errors")

# Initialize email model
if not initialize_email_model():
    logger.warning("Failed to initialize email model - email analysis will be limited")

# Suppress SSL warnings globally for phishing detection
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add request logging middleware
@app.before_request
def log_request_info():
    logger.info(f"Received {request.method} request to {request.path}")
    logger.info(f"Headers: {dict(request.headers)}")
    if request.args:
        logger.info(f"Query params: {dict(request.args)}")

@app.route('/check_url', methods=['GET', 'OPTIONS'])
def check_url_api():
    """
    Simple API endpoint for Chrome extension compatibility.
    Returns basic safe/unsafe status with reason.
    Enhanced with better timeout handling and performance optimization.
    """
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response, 204
        
    url = request.args.get('url')
    logger.info(f"Analyzing URL: {url}")
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Add request timing
    start_time = time.time()
    
    try:
        if detector is None:
            return jsonify({
                'safe': False, 
                'reason': 'Detection system unavailable - detector not initialized'
            }), 500
        
        # Quick URL validation to fail fast
        if len(url) > 2000:
            return jsonify({
                'safe': False,
                'reason': 'URL too long (>2000 characters) - likely malicious',
                'risk_percentage': 95,
                'confidence': 0.9,
                'verdict': 'CRITICAL'
            })
        
        # Simplified analysis without threading to avoid signal issues
        try:
            logger.info(f"Starting analysis for URL: {url[:100]}...")
            
            # Set a simple timeout using time-based approach
            analysis_start = time.time()
            analysis = detector.analyze_url(url)
            analysis_duration = time.time() - analysis_start
            
            # Check if analysis took too long
            if analysis_duration > 15:  # 15 second timeout
                logger.warning(f"Analysis took {analysis_duration:.2f}s (slow)")
            
        except Exception as analysis_error:
            logger.error(f"Analysis error: {analysis_error}")
            # For model-related errors, provide more specific guidance
            error_str = str(analysis_error).lower()
            if 'model' in error_str or 'classifier' in error_str:
                return jsonify({
                    'safe': False,
                    'reason': 'ML model unavailable - ensure models are trained and saved',
                    'risk_percentage': 50,
                    'confidence': 0.3,
                    'verdict': 'ERROR',
                    'error': True,
                    'processing_time': time.time() - start_time
                }), 500
            else:
                # Use basic rule-based analysis as fallback
                from phishing_detector import extract_features, rule_based_classification
                try:
                    features = extract_features(url)
                    basic_result = rule_based_classification(features)
                    
                    safe = basic_result['prediction'] == 'legitimate'
                    risk_percentage = (1 - basic_result['confidence']) * 100 if safe else basic_result['confidence'] * 100
                    
                    return jsonify({
                        'safe': safe,
                        'reason': f"Basic analysis: {basic_result['prediction']} (fallback mode)",
                        'risk_percentage': risk_percentage,
                        'confidence': basic_result['confidence'],
                        'verdict': 'MEDIUM' if not safe else 'LOW',
                        'fallback_mode': True,
                        'processing_time': time.time() - start_time
                    })
                except:
                    return jsonify({
                        'safe': False,
                        'reason': 'Analysis failed - treating as suspicious',
                        'risk_percentage': 60,
                        'confidence': 0.3,
                        'verdict': 'ERROR',
                        'error': True,
                        'processing_time': time.time() - start_time
                    }), 500
        
        final_result = analysis.get('final_result', {})
        
        # Extract verdict and risk info
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        risk_percentage = final_result.get('risk_percentage', 50)
        confidence = final_result.get('confidence', 0)
        
        # Get ML prediction for additional context
        ml_prediction = None
        ml_confidence = 0
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('layer') == 'ML Classification' and not layer_result.get('error'):
                ml_prediction = layer_result.get('ml_prediction')
                ml_scores = layer_result.get('confidence_scores', {})
                ml_confidence = ml_scores.get('phishing', 0)
                break
        
        # Check for legitimate brand sites (reduced false positives)
        is_legitimate_brand = check_legitimate_brand(url)
        
        # Count high-risk flags for later use
        high_risk_flags = 0
        specific_high_risk_indicators = []
        for layer_result in analysis.get('layer_results', []):
            if layer_result.get('error'):
                continue  # Skip error layers
            layer_risk = layer_result.get('risk_score', 0)
            if layer_risk > 50:  # Lower threshold
                high_risk_flags += 1
            
            # Collect specific high-risk indicators
            flags = layer_result.get('flags', [])
            for flag in flags:
                if any(term in flag.lower() for term in ['ip address', 'dns record', 'domain', 'shortened']):
                    specific_high_risk_indicators.append(flag)

        # NEW: Basic heuristics for non-whitelisted but legitimate sites
        # These will help prevent false positives on regular websites
        is_likely_legitimate = False
        
        # Check if the site has no serious red flags despite not being in our whitelist
        if risk_percentage < 35 and high_risk_flags == 0 and not specific_high_risk_indicators:
            is_likely_legitimate = True
        
        # Parse the domain and check some additional features
        try:
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # FIXED: Check domain structure - if it HAS suspicious patterns, it's NOT legitimate
            has_ip_address = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain))
            has_long_numbers = bool(re.search(r'[0-9]{5,}', domain))
            has_suspicious_keywords = bool(re.search(r'(secure|login|banking|account)\d+\.', domain))
            
            # Only mark as likely legitimate if domain looks normal AND has low risk
            if (not has_ip_address and not has_long_numbers and 
                not has_suspicious_keywords and len(domain) < 40 and 
                risk_percentage < 35):  # Added risk check
                is_likely_legitimate = True
                
            # CRITICAL: If domain uses IP address, it's definitely suspicious
            if has_ip_address:
                is_likely_legitimate = False  # Never treat IP addresses as likely legitimate
        except:
            pass
        
        # Check for suspicious tunnel/proxy services (ngrok, etc.)
        suspicious_services = [
            'ngrok.io', 'ngrok-free.app', 'localtunnel.me', 'serveo.net', 
            'pagekite.me', 'tunnelto.dev', 'localhost.run', 'tunnel.me'
        ]
        
        is_tunnel_service = False
        try:
            parsed_domain = urllib.parse.urlparse(url).netloc.lower()
            for service in suspicious_services:
                if service in parsed_domain:
                    is_tunnel_service = True
                    break
        except:
            pass
        
        # Enhanced classification logic with tunnel service detection
        if isinstance(verdict, RiskLevel):
            # SECURITY: Tunnel services are high risk for phishing
            if is_tunnel_service:
                # Tunnel services should be treated with extreme caution
                if risk_percentage > 25 or ml_prediction == 'phishing' or high_risk_flags >= 2:
                    safe = False
                    reason = f"HIGH RISK: Tunnel service detected ({risk_percentage:.0f}% risk) - commonly used for phishing"
                else:
                    safe = False  # Default to unsafe for tunnel services
                    reason = f"SUSPICIOUS: Tunnel service detected ({risk_percentage:.0f}% risk) - proceed with extreme caution"
            
            # PRIORITY: Legitimate brands get strong preference (non-tunnel services only)
            elif is_legitimate_brand:
                # Check if this is a payment gateway (needs special handling)
                is_payment_gateway = False
                try:
                    parsed_domain = urllib.parse.urlparse(url).netloc.lower()
                    payment_domains = ['billdesk.com', 'payu.in', 'razorpay.com', 'cashfree.com', 
                                     'paypal.com', 'stripe.com', 'ccavenue.com', 'instamojo.com']
                    for payment_domain in payment_domains:
                        if payment_domain in parsed_domain:
                            is_payment_gateway = True
                            break
                except:
                    pass
                
                # For known legitimate brands, we need VERY strong evidence of phishing
                if verdict in [RiskLevel.CRITICAL]:
                    safe = False
                    reason = f"CRITICAL ALERT: Legitimate brand site compromised ({risk_percentage:.0f}% risk)"
                elif verdict in [RiskLevel.HIGH] and ml_prediction == 'phishing' and ml_confidence > 0.90:
                    safe = False
                    reason = f"HIGH RISK: Legitimate brand site possibly compromised ({risk_percentage:.0f}% risk)"
                else:
                    # Trust the legitimate brand - it's safe
                    safe = True
                    if is_payment_gateway:
                        reason = f"Safe - Verified payment gateway ({risk_percentage:.0f}% risk from technical flags - normal for payment processors)"
                    else:
                        reason = f"Safe - Verified legitimate brand site ({risk_percentage:.0f}% risk - acceptable)"
                    if risk_percentage > 50:
                        if is_payment_gateway:
                            reason += " - Payment gateways often trigger security flags due to cross-domain forms"
                        else:
                            reason += " - Some security flags detected but overridden for known brand"
            
            # For non-whitelisted sites, use normal thresholds
            elif verdict in [RiskLevel.SAFE]:
                # Double-check with ML prediction - LOWER THRESHOLD
                if ml_prediction == 'phishing' and ml_confidence > 0.40 and not is_likely_legitimate:
                    safe = False
                    reason = f"ML detected phishing risk ({ml_confidence:.2f} confidence) despite low overall risk"
                else:
                    safe = True
                    reason = f"Safe ({risk_percentage:.0f}% risk, {confidence:.2f} confidence)"
            elif verdict in [RiskLevel.LOW]:
                # SECURITY FIX: Give more weight to ML predictions to catch typosquatting/fake sites
                if ml_prediction == 'phishing' and ml_confidence > 0.45:  # Lowered threshold from 0.60 to 0.45
                    safe = False
                    reason = f"Low overall risk but ML detected phishing ({ml_confidence:.2f} confidence) - likely typosquatting/fake site"
                else:
                    safe = True
                    reason = f"Low risk detected ({risk_percentage:.0f}% risk)"
                    if is_likely_legitimate and ml_prediction != 'phishing':
                        reason += " - appears legitimate"
            elif verdict in [RiskLevel.MEDIUM]:
                # SECURITY FIX: Be more strict with MEDIUM risk
                # Check for IP addresses or other severe indicators
                has_ip_in_domain = 'ip address' in ' '.join(specific_high_risk_indicators).lower()
                has_brand_impersonation = any('brand impersonation' in flag.lower() for flag in specific_high_risk_indicators)
                
                if has_ip_in_domain or has_brand_impersonation:
                    # IP addresses and brand impersonation should always be flagged
                    safe = False
                    reason = f"MEDIUM RISK with critical indicators ({risk_percentage:.0f}% risk) - likely phishing"
                elif is_likely_legitimate and not (has_ip_in_domain or has_brand_impersonation):
                    # Only for truly legitimate-looking sites without severe indicators
                    if ml_prediction == 'phishing' and ml_confidence > 0.75:
                        safe = False
                        reason = f"Medium risk from likely legitimate site - unusual behavior detected ({risk_percentage:.0f}% risk)"
                    else:
                        safe = True
                        reason = f"Medium risk but appears legitimate ({risk_percentage:.0f}%) - likely safe"
                else:
                    # Default: treat medium risk as unsafe unless ML strongly disagrees
                    if ml_prediction == 'phishing' or ml_confidence < 0.30:  # Stricter threshold
                        safe = False
                        reason = f"Suspicious ({risk_percentage:.0f}% risk, proceed with extreme caution)"
                    else:
                        safe = False  # Changed default to False for medium risk
                        reason = f"Medium risk detected ({risk_percentage:.0f}% risk) - exercise caution"
            elif verdict in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                # High risk sites are unsafe regardless
                safe = False
                reason = f"Dangerous ({risk_percentage:.0f}% risk, avoid this site)"
            else:
                safe = False
                reason = "Analysis error - treat as suspicious"
        else:
            safe = False
            reason = "Unknown verdict - treat as suspicious"
        
        # NEW: Much more lenient approach for low/medium risk sites
        # Only override if there are VERY strong indicators of actual phishing
        if high_risk_flags >= 4 and safe and not (is_legitimate_brand or is_likely_legitimate):  # Increased threshold from 3 to 4
            safe = False
            reason += f" | {high_risk_flags} layers detected high risk"
        
        # SECURITY FIX: Flag if there are ANY severe high-risk indicators (like IP addresses)
        severe_indicators = []
        for indicator in specific_high_risk_indicators:
            if any(severe_term in indicator.lower() for severe_term in ['ip address', 'critical phishing', 'brand impersonation', 'dns record', 'no dns']):
                severe_indicators.append(indicator)
        
        # Single severe indicator is enough to flag as unsafe (reduced from 2 to 1)
        if len(severe_indicators) >= 1 and safe and not is_legitimate_brand:
            safe = False
            reason = f"FLAGGED: Critical security indicators detected - {', '.join(severe_indicators[:2])}" # Override reason
        
        # SECURITY FIX: Be more selective with educational domain overrides
        try:
            parsed_domain = urllib.parse.urlparse(url).netloc.lower()
            
            # Only override for verified educational domains, not suspicious ones
            if parsed_domain.endswith('.edu') or parsed_domain.endswith('.ac.uk'):
                # US .edu and UK .ac.uk are generally trustworthy
                if verdict in [RiskLevel.HIGH, RiskLevel.CRITICAL] and ml_confidence > 0.85:
                    pass  # Keep as unsafe only for very high risk
                else:
                    safe = True
                    if 'Educational/institutional domain' not in reason:
                        reason += " - Educational/institutional domain override"
            elif parsed_domain.endswith('.ac.in') or parsed_domain.endswith('.edu.in'):
                # For Indian educational domains, only override if DNS resolves AND no severe indicators
                try:
                    import socket
                    socket.gethostbyname(parsed_domain)
                    
                    # Only override if no severe indicators and ML doesn't strongly suggest phishing
                    if len(severe_indicators) == 0 and (ml_confidence < 0.70 or ml_prediction != 'phishing'):
                        safe = True
                        reason += " - Verified educational domain"
                    # If there are severe indicators or high ML confidence, don't override
                except socket.gaierror:
                    # DNS failed - don't override, let normal logic apply
                    pass
        except:
            pass
        
        # Add fallback mode indicator if applicable
        if final_result.get('fallback_result'):
            reason += " | Limited analysis mode"
        
        # Add processing time info
        processing_time = time.time() - start_time
        
        response_data = {
            'safe': safe, 
            'reason': reason,
            'risk_percentage': risk_percentage,
            'confidence': confidence,
            'verdict': verdict.value if isinstance(verdict, RiskLevel) else str(verdict),
            'ml_prediction': ml_prediction,
            'ml_confidence': ml_confidence,
            'is_legitimate_brand': is_legitimate_brand,
            'is_likely_legitimate': is_likely_legitimate,
            'processing_time': processing_time,
            'server_time': time.time(),
            'fallback_mode': final_result.get('fallback_result', False)
        }
        
        logger.info(f"Analysis completed in {processing_time:.2f}s: {verdict}")
        response = jsonify(response_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return response
        
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"Analysis error for URL {url[:100]}: {e} (took {processing_time:.2f}s)")
        
        error_response = jsonify({
            'safe': False, 
            'reason': f'Analysis failed: {str(e)[:200]} - treating as suspicious',
            'risk_percentage': 60,
            'confidence': 0.3,
            'verdict': 'ERROR',
            'error': True,
            'processing_time': processing_time
        })
        error_response.headers.add('Access-Control-Allow-Origin', '*')
        error_response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        error_response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        return error_response, 500

@app.route('/analyze_detailed', methods=['POST'])
def analyze_detailed():
    """
    Detailed analysis endpoint that returns full layered analysis results.
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if detector is None:
            return jsonify({'error': 'Detector not initialized'}), 500
        
        # Get full analysis
        analysis = detector.analyze_url(url)
        
        # Process results for JSON serialization
        result = process_analysis_results(analysis)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Detailed analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_source', methods=['POST'])
def analyze_source_code():
    """
    Endpoint to analyze HTML source code sent from the extension.
    Uses content_analyzer module for deeper analysis.
    """
    try:
        data = request.get_json()
        
        url = data.get('url')
        html_content = data.get('source')
        
        if not url or not html_content:
            return jsonify({'error': 'URL and source code are required'}), 400
        
        try:
            from content_analyzer import ContentAnalyzer
            analyzer = ContentAnalyzer()
            analysis_result = analyzer.analyze_content(html_content, url)
            return jsonify(analysis_result)
        except ImportError:
            # Fallback to basic analysis if ContentAnalyzer not available
            risk_score = 0
            flags = []
            
            # Simple regex checks
            if re.search(r'eval\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}', html_content):
                flags.append("Obfuscated JavaScript detected")
                risk_score += 15
            
            if re.search(r'document\.cookie', html_content):
                flags.append("Cookie manipulation detected")
                risk_score += 10
            
            if len(re.findall(r'<input[^>]*type\s*=\s*["\']password["\']', html_content)) > 0:
                flags.append("Password field detected")
                risk_score += 5
                
                # Check if form submits to different domain
                form_actions = re.findall(r'<form[^>]*action\s*=\s*["\'](https?://[^"\']+)["\']', html_content)
                
                if form_actions:
                    try:
                        from urllib.parse import urlparse
                        current_domain = urlparse(url).netloc
                        for action in form_actions:
                            action_domain = urlparse(action).netloc
                            if action_domain != current_domain:
                                flags.append(f"Form submits to different domain: {action_domain}")
                                risk_score += 25
                    except:
                        pass
            # Check for external resources
            external_resources = re.findall(r'src\s*=\s*["\'](https?://[^"\']+)["\']', html_content)
            if external_resources:
                try:
                    from urllib.parse import urlparse
                    current_domain = urlparse(url).netloc
                    
                    for resource in external_resources:
                        resource_domain = urlparse(resource).netloc
                        if resource_domain != current_domain:
                            flags.append("Page loads resources from external domains")
                            risk_score += 5
                            break
                except:
                    pass
            
            return jsonify({
                'risk_score': min(risk_score, 100),
                'flags': flags,
                'basic_analysis': True
            })
            
    except Exception as e:
        logger.error(f"Source code analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Enhanced health check endpoint with more details."""
    health_data = {
        'status': 'healthy',
        'detector_loaded': detector is not None,
        'layers_count': len(detector.layers) if detector else 0,
        'timestamp': time.time(),
        'server_uptime': time.time() - server_start_time if 'server_start_time' in globals() else 0,
        'python_version': sys.version.split()[0],
        'dependencies': {},
        'cors': "enabled"
    }
    
    # Check key dependencies
    try:
        import sklearn
        health_data['dependencies']['sklearn'] = sklearn.__version__
    except ImportError:
        health_data['dependencies']['sklearn'] = 'missing'
    
    try:
        import flask
        health_data['dependencies']['flask'] = flask.__version__
    except ImportError:
        health_data['dependencies']['flask'] = 'missing'
    
    # Skip detector test for health check to make it faster
    if detector:
        health_data['detector_status'] = 'initialized'
    else:
        health_data['detector_status'] = 'not initialized'
        health_data['status'] = 'degraded'
    
    # Add debug info for CORS
    health_data['allowed_origins'] = '*'
    health_data['allowed_methods'] = ['GET', 'POST', 'OPTIONS']
    
    response = jsonify(health_data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    return response

_url_explainer = None


def _load_url_explainer():
    """Load the v2 URL model + featurizer once for the /explain_url endpoint."""
    global _url_explainer
    if _url_explainer is None:
        import joblib
        models_dir = os.path.join(os.path.dirname(__file__), 'models')
        _url_explainer = (joblib.load(os.path.join(models_dir, 'phishing_classifier.pkl')),
                          joblib.load(os.path.join(models_dir, 'tfidf_vectorizer.pkl')))
    return _url_explainer


@app.route('/explain_url', methods=['GET', 'POST'])
def explain_url():
    """Explainable AI: which parts of the URL pushed the ML verdict, and how much.

    GET  /explain_url?url=<url>     or     POST {"url": "<url>"}
    """
    url = request.args.get('url') if request.method == 'GET' else (request.get_json(silent=True) or {}).get('url')
    if not url or not isinstance(url, str) or len(url) > 4096:
        return jsonify({'error': "Provide a 'url' (max 4096 chars)"}), 400
    try:
        from url_features import explain
        model, featurizer = _load_url_explainer()
        if not hasattr(featurizer, 'feature_names'):
            return jsonify({'error': 'Explanations need the v2 URL model. Run: python training/train_url_model.py'}), 503
        return jsonify(explain(url, model, featurizer))
    except FileNotFoundError:
        return jsonify({'error': 'URL model not found. Run: python training/train_url_model.py'}), 503
    except Exception as e:
        logger.error(f"explain_url error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/model_info')
def model_info():
    """Metrics and top indicators of the deployed URL model."""
    path = os.path.join(os.path.dirname(__file__), 'models', 'evaluation_results.json')
    if not os.path.exists(path):
        return jsonify({'error': 'evaluation_results.json not found'}), 404
    import json as _json
    with open(path) as fh:
        return jsonify(_json.load(fh))


@app.route('/feedback', methods=['POST'])
def handle_user_feedback():
    """Handle user feedback for model improvement."""
    try:
        data = request.get_json()
        
        required_fields = ['url', 'user_response', 'timestamp']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Process feedback
        feedback_result = process_feedback(data)
        
        # Store feedback in database/file
        store_feedback(data)
        
        # Update model if applicable
        if feedback_result.get('update_model', False):
            schedule_model_update()
        
        return jsonify({
            'success': True,
            'message': 'Feedback received and processed',
            'feedback_id': feedback_result.get('feedback_id'),
            'model_updated': feedback_result.get('update_model', False)
        })
        
    except Exception as e:
        logger.error(f"Feedback handling error: {e}")
        return jsonify({'error': 'Failed to process feedback'}), 500

@app.route('/learning_stats', methods=['GET'])
def get_learning_stats():
    """Get statistics about the learning system."""
    try:
        stats = {
            'total_feedback': get_total_feedback_count(),
            'accuracy_improvement': get_accuracy_improvement(),
            'false_positive_rate': get_false_positive_rate(),
            'model_version': get_current_model_version(),
            'last_updated': get_last_model_update()
        }
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Learning stats error: {e}")
        return jsonify({'error': 'Failed to get learning stats'}), 500

@app.route('/retrain_model', methods=['POST'])
def retrain_model():
    """Trigger model retraining with accumulated feedback."""
    try:
        # Check if enough feedback is available
        feedback_count = get_total_feedback_count()
        if feedback_count < 50:  # Minimum threshold
            return jsonify({
                'error': 'Insufficient feedback data for retraining',
                'current_count': feedback_count,
                'minimum_required': 50
            }), 400
        
        # Start retraining process
        retrain_result = start_model_retraining()
        
        return jsonify({
            'success': True,
            'message': 'Model retraining initiated',
            'estimated_completion': retrain_result.get('estimated_completion'),
            'training_samples': retrain_result.get('training_samples')
        })
        
    except Exception as e:
        logger.error(f"Model retraining error: {e}")
        return jsonify({'error': 'Failed to start model retraining'}), 500

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    """
    Analyze email content for phishing detection.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email_content = data.get('content', '')
        email_subject = data.get('subject', '')
        sender_email = data.get('sender', '')
        
        if not email_content and not email_subject:
            return jsonify({'error': 'Email content or subject is required'}), 400
        
        logger.info(f"Analyzing email from {sender_email} with subject: {email_subject}")
        
        # Combine subject and content for analysis
        full_text = f"Subject: {email_subject}\n\n{email_content}"
        
        # Perform email analysis
        analysis_result = analyze_email_content(full_text, sender_email)
        
        return jsonify(analysis_result)
        
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_email_quick', methods=['POST'])
def check_email_quick():
    """
    Quick email check for immediate threat detection.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email_content = data.get('content', '')
        email_subject = data.get('subject', '')
        sender_email = data.get('sender', '')
        
        if not email_content and not email_subject:
            return jsonify({'error': 'Email content or subject is required'}), 400
        
        # Quick pattern-based analysis
        quick_result = quick_email_check(email_subject, email_content, sender_email)
        
        return jsonify(quick_result)
        
    except Exception as e:
        logger.error(f"Quick email check error: {e}")
        return jsonify({'error': str(e)}), 500

# Helper functions for feedback processing
def process_feedback(feedback_data):
    """Process user feedback and determine actions."""
    url = feedback_data['url']
    user_response = feedback_data['user_response']
    analysis_data = feedback_data.get('analysis_data', {})
    
    # Extract features from URL
    features = extract_features(url)
    
    # Create training sample
    training_sample = {
        'url': url,
        'features': features,
        'predicted_label': 1 if analysis_data.get('ml_prediction') == 'phishing' else 0,
        'actual_label': 1 if user_response == 'dangerous' else 0,
        'confidence': analysis_data.get('ml_confidence', 0.5),
        'timestamp': feedback_data['timestamp']
    }
    
    # Check if this feedback indicates model error
    predicted_phishing = analysis_data.get('ml_prediction') == 'phishing'
    user_says_phishing = user_response == 'dangerous'
    
    model_error = (predicted_phishing != user_says_phishing)
    
    # Store training sample
    feedback_id = store_training_sample(training_sample)
    
    # Determine if model update is needed
    update_model = should_update_model(model_error)
    
    return {
        'feedback_id': feedback_id,
        'model_error': model_error,
        'update_model': update_model,
        'training_sample': training_sample
    }

def store_feedback(feedback_data):
    """Store feedback data for analysis."""
    import json
    import os
    
    feedback_file = 'data/user_feedback.jsonl'
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(feedback_file), exist_ok=True)
    
    # Append feedback to file
    with open(feedback_file, 'a') as f:
        f.write(json.dumps(feedback_data) + '\n')

def store_training_sample(sample):
    """Store training sample for model improvement."""
    import json
    import os
    import uuid
    
    training_file = 'data/training_samples.jsonl'
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(training_file), exist_ok=True)
    
    # Add unique ID
    sample['id'] = str(uuid.uuid4())
    
    # Append to file
    with open(training_file, 'a') as f:
        f.write(json.dumps(sample) + '\n')
    
    return sample['id']

def get_total_feedback_count():
    """Get total number of feedback samples."""
    try:
        with open('data/user_feedback.jsonl', 'r') as f:
            return sum(1 for line in f)
    except FileNotFoundError:
        return 0

def should_update_model(model_error):
    """Determine if model should be updated based on error rate."""
    # Simple heuristic: update if error rate is high
    recent_errors = get_recent_error_count()
    recent_total = get_recent_feedback_count()
    
    if recent_total > 10:  # Minimum samples
        error_rate = recent_errors / recent_total
        return error_rate > 0.3  # Update if >30% error rate
    
    return False

def get_recent_error_count():
    """Get number of recent model errors."""
    # Implementation depends on your data storage
    return 0  # Placeholder

def get_recent_feedback_count():
    """Get number of recent feedback samples."""
    # Implementation depends on your data storage
    return 0  # Placeholder

def schedule_model_update():
    """Schedule model update process."""
    # This could trigger a background task
    logger.info("Model update scheduled based on user feedback")

def start_model_retraining():
    """Start the model retraining process."""
    # Implementation for retraining
    return {
        'estimated_completion': '30 minutes',
        'training_samples': get_total_feedback_count()
    }
# Additional utility functions
def get_accuracy_improvement():
    """Calculate accuracy improvement from feedback."""
    return 0.05  # Placeholder

def get_false_positive_rate():
    """Calculate false positive rate."""
    return 0.15  # Placeholder

def get_current_model_version():
    """Get current model version."""
    return "1.2.3"  # Placeholder

def get_last_model_update():
    """Get timestamp of last model update."""
    return "2025-07-18T09:00:00Z"  # Placeholder

# Add helper function to check legitimate brands
def check_legitimate_brand(url):
    """Check if URL belongs to a legitimate brand website - Enhanced version."""
    try:
        from urllib.parse import urlparse
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove 'www.' prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Expanded list of legitimate brand domains and their common subdomains
        legitimate_brands = {
            # Major tech companies
            'google.com': ['www', 'mail', 'drive', 'docs', 'calendar', 'photos', 'play', 'store'],
            'youtube.com': ['www', 'music', 'studio', 'tv', 'm'],
            'microsoft.com': ['www', 'account', 'login', 'office', 'outlook', 'teams'],
            'apple.com': ['www', 'support', 'id', 'developer', 'store'],
            'amazon.com': ['www', 'smile', 'pay', 'music', 'prime', 'aws'],
            
            # Social media
            'facebook.com': ['www', 'business', 'm', 'developers', 'about'],
            'instagram.com': ['www', 'about', 'help', 'business'],
            'twitter.com': ['www', 'mobile', 'api', 'help'],
            'linkedin.com': ['www', 'business', 'developer', 'help'],
            'whatsapp.com': ['www', 'web', 'business'],
            
            # Development platforms
            'github.com': ['www', 'gist', 'api', 'docs', 'help'],
            'stackoverflow.com': ['www', 'meta', 'chat'],
            'gitlab.com': ['www', 'about', 'docs'],
            
            # Media and entertainment
            'netflix.com': ['www', 'help', 'media'],
            'spotify.com': ['www', 'open', 'developer', 'artists'],
            'reddit.com': ['www', 'old', 'new'],
            
            # Professional tools
            'slack.com': ['www', 'api', 'status', 'help'],
            'zoom.us': ['www', 'support', 'marketplace'],
            'discord.com': ['www', 'support', 'blog'],
            
            # Educational and reference
            'wikipedia.org': ['www', 'en', 'commons', 'meta'],
            'w3schools.com': ['www', 'my', 'spaces', 'tryit'],  # Added W3Schools
            'mdn.mozilla.org': ['www', 'developer'],  # Mozilla Developer Network
            'codecademy.com': ['www', 'pro', 'learn'],
            'freecodecamp.org': ['www', 'www'],
            'coursera.org': ['www', 'about', 'learn'],
            'edx.org': ['www', 'courses', 'about'],
            'khanacademy.org': ['www', 'www'],
            'udemy.com': ['www', 'support', 'teach'],
            'w3.org': ['www', 'www'],  # W3C standards
            'mit.edu': ['www', 'web', 'admissions'],
            'stanford.edu': ['www', 'admissions', 'news'],
            'harvard.edu': ['www', 'college', 'news'],
            
            # Financial services
            'paypal.com': ['www', 'developer', 'checkout', 'business'],
            'chase.com': ['www', 'secure', 'www.secure'],
            'bankofamerica.com': ['www', 'secure'],
            
            # Indian Payment Gateways & Financial Services
            'billdesk.com': ['www', 'payments', 'pgi', 'secure', 'checkout'],
            'payu.in': ['www', 'secure', 'checkout', 'info'],
            'razorpay.com': ['www', 'api', 'dashboard', 'checkout'],
            'cashfree.com': ['www', 'payments', 'checkout'],
            'instamojo.com': ['www', 'api', 'blog'],
            'ccavenue.com': ['www', 'secure', 'checkout'],
            'citruspay.com': ['www', 'checkout', 'secure'],
            'atom.in': ['www', 'paynetz', 'secure'],
            'ebs.in': ['www', 'secure', 'checkout'],
            'freecharge.in': ['www', 'api'],
            'mobikwik.com': ['www', 'checkout', 'api'],
            'amazon.in': ['www', 'pay', 'checkout'],
            'phonepe.com': ['www', 'business', 'api'],
            'paytm.com': ['www', 'business', 'developer'],
            'gpay.google.com': ['www', 'api'],
            
            # News and media
            'bbc.com': ['www', 'news', 'sport', 'iplayer'],
            'cnn.com': ['www', 'edition', 'money'],
            'nytimes.com': ['www', 'cooking', 'games'],
            'reuters.com': ['www', 'graphics', 'graphics'],
            
            # Other major sites
            'ebay.com': ['www', 'pages', 'community'],
            'adobe.com': ['www', 'helpx', 'forums'],
            'dropbox.com': ['www', 'help', 'paper']
        }
        
        # Check for direct domain match
        if domain in legitimate_brands:
            return True
            
        # Check for subdomain of a legitimate brand
        for brand_domain, subdomains in legitimate_brands.items():
            if domain.endswith(f'.{brand_domain}'):
                subdomain = domain.replace(f'.{brand_domain}', '')
                # Check if it's a known subdomain or follows common patterns
                if (subdomain in subdomains or 
                    re.match(r'^(help|about|support|developer|api|business|login|account|secure|status|blog|news|docs|help|store|mail)$', subdomain)):
                    return True
                    
        # Additional checks for government, education domains
        # SECURITY FIX: Be more selective with educational domains
        if (domain.endswith('.gov') or domain.endswith('.edu') or 
            domain.endswith('.gov.uk') or domain.endswith('.ac.uk')):
            return True
            
        # For Indian educational domains, add additional validation
        if domain.endswith('.ac.in') or domain.endswith('.edu.in'):
            # Verify it's a real educational institution by checking DNS and known institutions
            try:
                import socket
                # Try to resolve the domain - if it fails, it's suspicious
                socket.gethostbyname(domain)
                
                # Additional check: known legitimate Indian educational institutions
                legitimate_indian_edu = [
                    'iit.ac.in', 'iisc.ac.in', 'nit.ac.in', 'iim.ac.in',
                    'du.ac.in', 'jnu.ac.in', 'bhu.ac.in', 'amu.ac.in'
                ]
                
                # Check if it's a subdomain of known legitimate institutions
                for edu_domain in legitimate_indian_edu:
                    if domain == edu_domain or domain.endswith('.' + edu_domain):
                        return True
                        
                # For other .ac.in domains, only trust if DNS resolves AND domain is not suspicious
                if not any(suspicious in domain for suspicious in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']):
                    return True  # Only if no numbers in domain name
                    
            except socket.gaierror:
                # DNS resolution failed - definitely suspicious
                logger.warning(f"Educational domain {domain} failed DNS resolution - treating as suspicious")
                return False
                
        # For .org and .net, be more selective (removed blanket approval)
        if domain.endswith('.org'):
            # Only trust well-known organizations
            trusted_orgs = [
                'wikipedia.org', 'mozilla.org', 'w3.org', 'apache.org',
                'python.org', 'nodejs.org', 'jquery.org', 'bootstrap.org'
            ]
            if domain in trusted_orgs or any(domain.endswith('.' + org) for org in trusted_orgs):
                return True

        # Check for common CDN and legitimate service domains
        legitimate_services = [
            'amazonaws.com', 'cloudfront.net', 'googleapis.com',
            'gstatic.com', 'bootstrapcdn.com', 'jquery.com',
            'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net'
        ]
        
        for service in legitimate_services:
            if domain == service or domain.endswith('.' + service):
                return True

        # NEW: Domain age as indicator of legitimacy - FIXED Implementation
        try:
            import whois
            from datetime import datetime
            logger.debug(f"Checking domain age for: {domain}")
            
            # Use proper whois library usage as shown in documentation
            w = whois.whois(domain)
            
            if w and hasattr(w, 'creation_date') and w.creation_date:
                creation_date = w.creation_date
                
                # Handle case where creation_date might be a list
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if isinstance(creation_date, datetime):
                    # Calculate domain age
                    domain_age_days = (datetime.now() - creation_date).days
                    logger.info(f"Domain {domain} is {domain_age_days} days old")
                    
                    if domain_age_days > 365:  # Domain older than 1 year
                        logger.info(f"Domain {domain} is older than 1 year ({domain_age_days} days), likely legitimate")
                        return True
                    elif domain_age_days < 180:  # Less than 6 months
                        logger.warning(f"Domain {domain} is very new ({domain_age_days} days), potentially suspicious")
                        return False
                else:
                    logger.debug(f"Invalid creation_date format for {domain}: {creation_date}")
            else:
                logger.debug(f"No creation_date found in WHOIS for {domain}")
        except Exception as whois_error:
            logger.debug(f"WHOIS lookup failed for {domain}: {whois_error}")
            
        return False
    except Exception as e:
        logger.error(f"Error checking legitimate brand: {e}")
        return False

def process_analysis_results(analysis):
    """Process analysis results for JSON serialization."""
    result = {
        'url': analysis['url'],
        'timestamp': analysis['timestamp'],
        'processing_time': analysis['processing_time'],
        'error': analysis.get('error')
    }
    
    # Process final result
    final_result = analysis.get('final_result', {})
    if final_result:
        verdict = final_result.get('final_verdict')
        result['final_result'] = {
            'verdict': verdict.value if isinstance(verdict, RiskLevel) else str(verdict),
            'risk_percentage': final_result.get('risk_percentage', 0),
            'confidence': final_result.get('confidence', 0),
            'recommendations': final_result.get('recommendations', []),
            'summary': final_result.get('summary', {}),
            'early_termination': final_result.get('early_termination', False)
        }
    
    # Process layer results (filter out hidden layers)
    result['layer_results'] = []
    for layer_result in analysis.get('layer_results', []):
        # Skip hidden layers from API response
        if layer_result.get('hidden', False):
            continue
            
        processed_layer = {
            'layer': layer_result.get('layer'),
            'risk_score': layer_result.get('risk_score', 0),
            'flags': layer_result.get('flags', []),
            'weight': layer_result.get('weight', 1.0)
        }
        
        # Add ML-specific info
        if 'ml_prediction' in layer_result:
            processed_layer['ml_prediction'] = layer_result['ml_prediction']
            processed_layer['confidence_scores'] = layer_result.get('confidence_scores', {})
            processed_layer['inference_time'] = layer_result.get('inference_time', 0)
            processed_layer['model_info'] = layer_result.get('model_info', {})
        
        # Add content analysis info
        if 'content_analysis' in layer_result:
            processed_layer['content_analysis'] = layer_result.get('content_analysis', {})  
            processed_layer['ssl_info'] = layer_result.get('ssl_info', {})
            processed_layer['form_analysis'] = layer_result.get('form_analysis', {})
            processed_layer['js_analysis'] = layer_result.get('js_analysis', {})
        
        result['layer_results'].append(processed_layer)
    
    # Process ensemble result
    ensemble_result = analysis.get('ensemble_result', {})
    if ensemble_result:
        result['ensemble_result'] = {
            'weighted_risk_score': ensemble_result.get('weighted_risk_score', 0),
            'consensus': ensemble_result.get('consensus'),
            'conflicts': ensemble_result.get('conflicts', []),
            'layer_scores': ensemble_result.get('layer_scores', {})
        }
    
    return result

def analyze_email_content(email_text, sender_email):
    """
    Comprehensive email analysis using ML model and pattern matching.
    """
    try:
        # Initialize result
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'risk_score': 0,
            'threats': [],
            'analysis_method': 'pattern_only',
            'recommendations': [],
            'sender_analysis': {},
            'content_analysis': {},
            'timestamp': time.time()
        }
        
        # Sender analysis
        sender_analysis = analyze_sender(sender_email)
        result['sender_analysis'] = sender_analysis
        
        # Content analysis
        content_analysis = analyze_email_text(email_text)
        result['content_analysis'] = content_analysis
        
        # ML model analysis if available
        if email_model is not None and email_tokenizer is not None:
            try:
                ml_result = analyze_email_with_ml(email_text)
                result['ml_analysis'] = ml_result
                result['analysis_method'] = 'ml_enhanced'
                
                # Use ML confidence if available
                if 'confidence' in ml_result:
                    result['confidence'] = ml_result['confidence']
            except Exception as e:
                logger.warning(f"ML analysis failed: {e}")
        
        # Pattern-based analysis
        # Extract subject from email_text if it contains "Subject:" prefix
        email_subject = ""
        if email_text.startswith("Subject:"):
            lines = email_text.split('\n')
            if lines:
                email_subject = lines[0].replace("Subject:", "").strip()
        
        pattern_result = analyze_email_patterns(email_text, email_subject)
        result['pattern_analysis'] = pattern_result
        
        # Combine all analysis results
        final_risk_score = calculate_email_risk_score(
            sender_analysis, content_analysis, 
            result.get('ml_analysis', {}), pattern_result
        )
        
        result['risk_score'] = final_risk_score
        result['is_phishing'] = final_risk_score >= 70
        
        # Generate recommendations
        result['recommendations'] = generate_email_recommendations(result)
        
        # Determine confidence if not set by ML
        if result['confidence'] == 0.0:
            result['confidence'] = min(0.95, final_risk_score / 100)
        
        logger.info(f"Email analysis completed: risk_score={final_risk_score}, is_phishing={result['is_phishing']}")
        
        # Convert to the format expected by the Chrome extension
        response = {
            'status': 'phishing' if result['is_phishing'] else 'safe',
            'risk_level': 'high' if final_risk_score >= 70 else 'medium' if final_risk_score >= 50 else 'low',
            'risk_score': final_risk_score,
            'reason': 'Multiple suspicious indicators detected' if result['is_phishing'] else 'No threats detected',
            'is_phishing': result['is_phishing'],
            'confidence': result['confidence'],
            'threats': result.get('threats', []),
            'analysis_method': result['analysis_method'],
            'recommendations': result['recommendations'],
            'sender_analysis': result['sender_analysis'],
            'content_analysis': result['content_analysis'],
            'ml_analysis': result.get('ml_analysis', {}),
            'pattern_analysis': result.get('pattern_analysis', {}),
            'timestamp': result['timestamp']
        }
        
        logger.info(f"Final response: {response}")
        return response
        
    except Exception as e:
        logger.error(f"Email analysis failed: {e}")
        return {
            'is_phishing': True,  # Default to suspicious on error
            'confidence': 0.5,
            'risk_score': 80,
            'threats': ['analysis_error'],
            'error': str(e),
            'timestamp': time.time()
        }

def quick_email_check(subject, content, sender):
    """
    Quick email check using pattern matching only.
    """
    try:
        risk_score = 0
        threats = []
        
        # Check subject line
        if subject:
            subject_lower = subject.lower()
            
            # Urgency indicators
            urgency_words = ['urgent', 'immediate', 'action required', 'account suspended', 'verify now', 'last warning']
            for word in urgency_words:
                if word in subject_lower:
                    risk_score += 15
                    threats.append(f'urgent_language: {word}')
            
            # Financial indicators
            financial_words = ['bank', 'paypal', 'credit card', 'payment', 'invoice', 'refund']
            for word in financial_words:
                if word in subject_lower:
                    risk_score += 10
                    threats.append(f'financial_language: {word}')
        
        # Check content
        if content:
            content_lower = content.lower()
            
            # Suspicious patterns
            if 'click here' in content_lower or 'click below' in content_lower:
                risk_score += 20
                threats.append('suspicious_links')
            
            if 'password' in content_lower or 'username' in content_lower:
                risk_score += 25
                threats.append('credential_request')
            
            if 'verify your account' in content_lower or 'confirm your identity' in content_lower:
                risk_score += 30
                threats.append('identity_verification')
        
        # Check sender
        if sender:
            sender_lower = sender.lower()
            
            # Suspicious sender patterns
            if 'noreply' in sender_lower or 'no-reply' in sender_lower:
                risk_score += 5
                threats.append('noreply_sender')
            
            if 'support' in sender_lower and '@' not in sender_lower:
                risk_score += 10
                threats.append('fake_support_sender')
        
        return {
            'is_phishing': risk_score >= 50,
            'risk_score': min(risk_score, 100),
            'threats': threats,
            'confidence': min(0.8, risk_score / 100),
            'analysis_method': 'quick_pattern',
            'timestamp': time.time()
        }
        
    except Exception as e:
        logger.error(f"Quick email check failed: {e}")
        return {
            'is_phishing': True,
            'risk_score': 80,
            'threats': ['check_error'],
            'confidence': 0.5,
            'timestamp': time.time()
        }

def analyze_sender(sender_email):
    """
    Analyze sender email for suspicious patterns.
    """
    try:
        if not sender_email:
            return {'risk': 'unknown', 'score': 50, 'flags': ['no_sender']}
        
        sender_lower = sender_email.lower()
        risk_score = 0
        flags = []
        
        # Check for suspicious patterns
        if 'noreply' in sender_lower:
            risk_score += 10
            flags.append('noreply_address')
        
        if 'support' in sender_lower and '@' not in sender_lower:
            risk_score += 15
            flags.append('fake_support')
        
        if 'admin' in sender_lower and '@' not in sender_lower:
            risk_score += 20
            flags.append('fake_admin')
        
        # Check domain
        if '@' in sender_lower:
            domain = sender_lower.split('@')[1]
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit.ly']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 30
                    flags.append(f'suspicious_tld: {tld}')
            
            # Check for IP addresses
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                risk_score += 40
                flags.append('ip_address_domain')
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk': risk_level,
            'score': risk_score,
            'flags': flags,
            'email': sender_email
        }
        
    except Exception as e:
        logger.error(f"Sender analysis failed: {e}")
        return {'risk': 'unknown', 'score': 50, 'flags': ['analysis_error']}

def analyze_email_text(email_text):
    """
    Analyze email text content for suspicious patterns.
    """
    try:
        if not email_text:
            return {'risk': 'unknown', 'score': 50, 'flags': ['no_content']}
        
        text_lower = email_text.lower()
        risk_score = 0
        flags = []
        
        # Urgency indicators
        urgency_patterns = [
            r'urgent|immediate|asap|right now|within.*hours|deadline',
            r'account.*suspended|account.*locked|verify.*now|confirm.*identity',
            r'last.*warning|final.*notice|action.*required|respond.*immediately'
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                risk_score += 15
                flags.append(f'urgency: {pattern}')
        
        # Financial pressure
        financial_patterns = [
            r'payment.*overdue|invoice.*unpaid|refund.*pending|credit.*card.*expired',
            r'bank.*account.*frozen|paypal.*limited|stripe.*suspended'
        ]
        
        for pattern in financial_patterns:
            if re.search(pattern, text_lower):
                risk_score += 20
                flags.append(f'financial_pressure: {pattern}')
        
        # Credential requests
        credential_patterns = [
            r'enter.*password|confirm.*username|verify.*email|update.*account',
            r'login.*credentials|account.*details|personal.*information'
        ]
        
        for pattern in credential_patterns:
            if re.search(pattern, text_lower):
                risk_score += 25
                flags.append(f'credential_request: {pattern}')
        
        # Suspicious links
        if 'click here' in text_lower or 'click below' in text_lower:
            risk_score += 20
            flags.append('suspicious_link_text')
        
        # Grammatical errors (basic check)
        common_errors = ['ur account', 'ur password', 'pls verify', 'thx']
        for error in common_errors:
            if error in text_lower:
                risk_score += 10
                flags.append(f'grammatical_error: {error}')
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk': risk_level,
            'score': risk_score,
            'flags': flags
        }
        
    except Exception as e:
        logger.error(f"Email text analysis failed: {e}")
        return {'risk': 'unknown', 'score': 50, 'flags': ['analysis_error']}

def analyze_email_with_ml(email_text):
    """
    Analyze email using the ML model.
    """
    try:
        if email_model is None or email_tokenizer is None:
            return {'error': 'ML model not available'}
        
        # Tokenize input
        inputs = email_tokenizer(
            email_text,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors="pt"
        )
        
        # Get prediction
        with torch.no_grad():
            outputs = email_model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            predicted_class = torch.argmax(probabilities, dim=1).item()
            confidence = probabilities[0][predicted_class].item()
            
            # Debug logging
            logger.info(f"Raw model output - Logits shape: {outputs.logits.shape}")
            logger.info(f"Raw probabilities shape: {probabilities.shape}")
            logger.info(f"Predicted class: {predicted_class}")
            logger.info(f"Confidence: {confidence:.4f}")
            logger.info(f"All raw probabilities: {probabilities[0].tolist()}")
        
        # Map class to label - use the actual model labels from config
        # The model uses generic labels, so we'll map them to meaningful categories
        class_labels = ['safe', 'suspicious', 'phishing', 'malware']
        predicted_label = class_labels[predicted_class] if predicted_class < len(class_labels) else 'unknown'
        
        # Get all probabilities for each class
        all_probabilities = {}
        for i, prob in enumerate(probabilities[0]):
            if i < len(class_labels):
                all_probabilities[class_labels[i]] = prob.item()
            else:
                all_probabilities[f'class_{i}'] = prob.item()
        
        return {
            'predicted_class': predicted_class,
            'predicted_label': predicted_label,
            'confidence': confidence,
            'probabilities': all_probabilities
        }
        
    except Exception as e:
        logger.error(f"ML email analysis failed: {e}")
        return {'error': str(e)}

def analyze_email_patterns(email_text, subject):
    """
    Analyze email for common phishing patterns.
    """
    try:
        patterns = []
        risk_score = 0
        
        # Check for common phishing indicators
        indicators = {
            'urgent_language': [r'urgent', r'immediate', r'asap', r'right now'],
            'financial_pressure': [r'payment.*overdue', r'account.*frozen', r'refund.*pending'],
            'credential_requests': [r'password', r'username', r'login', r'verify'],
            'suspicious_links': [r'click.*here', r'click.*below', r'verify.*link'],
            'grammatical_errors': [r'ur ', r'pls ', r'thx ', r'account.*suspended'],
            'brand_impersonation': [r'paypal', r'amazon', r'google', r'microsoft', r'apple']
        }
        
        full_text = f"{subject} {email_text}".lower()
        
        for category, regex_list in indicators.items():
            for regex in regex_list:
                matches = re.findall(regex, full_text, re.IGNORECASE)
                if matches:
                    patterns.append({
                        'category': category,
                        'pattern': regex,
                        'matches': len(matches),
                        'examples': matches[:3]  # Limit examples
                    })
                    
                    # Assign risk scores based on category
                    if category in ['urgent_language', 'financial_pressure']:
                        risk_score += 15
                    elif category in ['credential_requests', 'suspicious_links']:
                        risk_score += 20
                    elif category == 'grammatical_errors':
                        risk_score += 10
                    elif category == 'brand_impersonation':
                        risk_score += 25
        
        return {
            'patterns': patterns,
            'risk_score': min(risk_score, 100),
            'total_patterns': len(patterns)
        }
        
    except Exception as e:
        logger.error(f"Pattern analysis failed: {e}")
        return {'patterns': [], 'risk_score': 0, 'total_patterns': 0}

def calculate_email_risk_score(sender_analysis, content_analysis, ml_analysis, pattern_analysis):
    """
    Calculate final risk score based on all analysis components.
    """
    try:
        total_score = 0
        weights = {
            'sender': 0.25,
            'content': 0.30,
            'ml': 0.35,
            'patterns': 0.10
        }
        
        # Sender risk
        sender_score = sender_analysis.get('score', 0)
        total_score += sender_score * weights['sender']
        
        # Content risk
        content_score = content_analysis.get('score', 0)
        total_score += content_score * weights['content']
        
        # ML analysis risk
        if 'error' not in ml_analysis:
            ml_label = ml_analysis.get('predicted_label', 'safe')
            ml_confidence = ml_analysis.get('confidence', 0)
            
            if ml_label == 'phishing':
                ml_score = 90 + (ml_confidence * 10)
            elif ml_label == 'suspicious':
                ml_score = 60 + (ml_confidence * 20)
            elif ml_label == 'malware':
                ml_score = 95 + (ml_confidence * 5)
            else:
                ml_score = 20 + (ml_confidence * 10)
            
            total_score += ml_score * weights['ml']
        else:
            # Fallback to pattern analysis if ML fails
            pattern_score = pattern_analysis.get('risk_score', 0)
            total_score += pattern_score * weights['ml']
        
        # Pattern risk
        pattern_score = pattern_analysis.get('risk_score', 0)
        total_score += pattern_score * weights['patterns']
        
        # Cap at 100
        final_score = min(100, int(total_score))
        
        return final_score
        
    except Exception as e:
        logger.error(f"Risk score calculation failed: {e}")
        return 80  # Default to high risk on error

def generate_email_recommendations(analysis_result):
    """
    Generate recommendations based on email analysis.
    """
    recommendations = []
    
    try:
        risk_score = analysis_result.get('risk_score', 0)
        is_phishing = analysis_result.get('is_phishing', False)
        
        if is_phishing or risk_score >= 70:
            recommendations.extend([
                "Do not click any links in this email",
                "Do not reply to this email",
                "Do not provide any personal information",
                "Mark this email as spam/phishing",
                "Delete this email immediately"
            ])
        elif risk_score >= 50:
            recommendations.extend([
                "Exercise caution with this email",
                "Verify the sender's identity before responding",
                "Do not click suspicious links",
                "Contact the organization directly if unsure"
            ])
        else:
            recommendations.extend([
                "Email appears safe",
                "Continue with normal email practices",
                "Report if you notice anything suspicious"
            ])
        
        # Add specific recommendations based on threats
        threats = analysis_result.get('threats', [])
        if 'credential_request' in str(threats):
            recommendations.append("Never provide passwords via email")
        
        if 'financial_pressure' in str(threats):
            recommendations.append("Verify financial requests through official channels")
        
        if 'urgency' in str(threats):
            recommendations.append("Be suspicious of urgent requests")
        
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}")
        recommendations = ["Error generating recommendations - treat email with caution"]
    
    return recommendations

if __name__ == '__main__':
    # Track server start time
    server_start_time = time.time()
    
    print("🛡️  Phishing Detection API Server v2.0")
    print("="*50)
    print("✅ Starting Flask server with enhanced timeout handling...")
    
    # Report detector status
    if detector is not None:
        print("✅ Phishing detector initialized successfully")
        print(f"✅ Number of detection layers: {len(detector.layers)}")
    else:
        print("⚠️  Warning: Phishing detector not initialized")
        print("⚠️  API will run but analysis functions will return errors")
        print("💡 Fix by ensuring scikit-learn is installed and models are available")
    
    print("🌐 Chrome Extension endpoint: http://localhost:5000/check_url")
    print("🔍 Detailed analysis endpoint: http://localhost:5000/analyze_detailed")
    print("💚 Health check: http://localhost:5000/health")
    print("\n⚡ Performance optimizations:")
    print("   - 12s timeout for analysis requests")
    print("   - Fast failure for invalid URLs") 
    print("   - Enhanced error reporting")
    print("   - SSL warnings suppressed for phishing detection")
    
    try:
        # Update server configuration
        # Debug mode exposes the Werkzeug debugger (remote code execution if the
        # port is reachable), so it is opt-in via PH_DEBUG=1 for local development.
        debug = os.environ.get('PH_DEBUG', '0') == '1'
        app.run(
            host=os.environ.get('PH_HOST', '127.0.0.1'),
            port=int(os.environ.get('PH_PORT', '5000')),
            debug=debug,
            threaded=True,
            use_reloader=debug
        )
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("Trying alternative configuration...")
        try:
            # Fall back to a simpler configuration
            app.run(host=os.environ.get('PH_HOST', '127.0.0.1'), port=int(os.environ.get('PH_PORT', '5000')))
        except Exception as e2:
            print(f"❌ Failed to start server with alternative configuration: {e2}")
            sys.exit(1)