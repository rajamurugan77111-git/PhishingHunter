"""
Phishing URL Detection App - Layered Approach

This module implements a multi-layered detection system where URLs pass through
progressively sophisticated analysis layers for comprehensive phishing detection.
"""

import os
import sys
import re

# The v2 URL model pickles a URLFeaturizer from url_features.py (project root);
# make sure it is importable however this module is launched.
_HERE = os.path.dirname(os.path.abspath(__file__))
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
logger = logging.getLogger(__name__)

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

class Layer1_BasicValidation(DetectionLayer):
    """
    Layer 1: Basic URL Validation & Quick Checks
    - URL format validation
    - Basic malicious patterns
    - Quick blacklist checks
    - Legitimate domain whitelist
    """
    
    def __init__(self):
        super().__init__("Basic Validation", weight=0.8)
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple dashes
            r'(paypal|ebay|amazon|microsoft|apple|google).*[0-9]+\..*',  # Brand + numbers
            r'(secure|login|account|verify|update).*[0-9]+\.',  # Security terms + numbers
            r'(apple-id|paypal-|amazon-|microsoft-|google-|facebook-|twitter-).*\.',  # Brand impersonation with dashes
            r'(verification|confirm|secure).*\.(com|org|net)',  # Verification/security terms
        ]
        
        # Quick blacklist (only known malicious domains - no mock data)
        self.blacklisted_domains = {
            # Add actual known malicious domains here if needed
            # Note: This should be populated from a real threat intelligence feed
        }
        
        # Tunneling services detection
        self.tunneling_services = [
            # Ngrok patterns
            r'[a-f0-9-]+\.ngrok\.io',
            r'[a-f0-9-]+\.ngrok-free\.app',
            r'tunnel\.ngrok\.io',
            
            # LocalhostRun patterns  
            r'[a-f0-9-]+\.lhr\.life',
            r'[a-f0-9-]+\.localhostrun\.com',
            
            # Other tunneling services
            r'[a-f0-9-]+\.serveo\.net',
            r'[a-f0-9-]+\.pagekite\.me',
            r'[a-f0-9-]+\.tunnelto\.dev',
            r'[a-f0-9-]+\.bore\.pub',
            r'[a-f0-9-]+\.loca\.lt',
            r'[a-f0-9-]+\.zrok\.io',
            
            # Generic tunnel patterns
            r'tunnel\d*\.',
            r'localhost-\d+\.',
            r'\d+-\d+-\d+-\d+\.tunnel\.',
        ]
        
        # Legitimate domain whitelist (major trusted sites)
        self.legitimate_domains = {
            # Major tech companies
            'google.com', 'youtube.com', 'gmail.com', 'drive.google.com',
            'microsoft.com', 'outlook.com', 'office.com', 'live.com',
            'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com',
            'facebook.com', 'instagram.com', 'whatsapp.com',
            'twitter.com', 'linkedin.com', 'github.com',
            
            # Major websites
            'wikipedia.org', 'reddit.com', 'stackoverflow.com',
            'netflix.com', 'spotify.com', 'youtube.com',
            'ebay.com', 'paypal.com', 'adobe.com',
            
            # Educational and reference sites
            'w3schools.com', 'mdn.mozilla.org', 'codecademy.com', 'freecodecamp.org',
            'coursera.org', 'edx.org', 'khanacademy.org', 'udemy.com',
            
            # Major news sites
            'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com',
            
            # Government and educational
            'gov.uk', 'gov.in', 'nih.gov', 'cdc.gov',
            'mit.edu', 'stanford.edu', 'harvard.edu',
            
            # Banking (major ones)
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'citibank.com', 'hsbc.com'
        }
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform basic validation checks."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {},
            'passed': True
        }
        
        try:
            # 1. URL format validation
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                results['flags'].append("Invalid URL format")
                results['risk_score'] += 30
                results['passed'] = False
                return results
            
            # 2. Extract domain for checks
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # 3. Check legitimate domains first (whitelist)
            if domain in self.legitimate_domains:
                results['flags'].append("Recognized legitimate domain")
                results['risk_score'] = max(0, results['risk_score'] - 20)  # Reduce risk significantly
                results['details']['is_whitelisted'] = True
                results['details']['domain'] = domain
                return results
            
            # 4. Length check (extreme cases)
            if len(url) > 2000:
                results['flags'].append("Extremely long URL")
                results['risk_score'] += 20
            elif len(url) > 200:
                results['flags'].append("Very long URL")
                results['risk_score'] += 10
            
            # 5. Malicious pattern detection - ENHANCED for brand impersonation
            pattern_matches = 0
            brand_impersonation_detected = False
            
            for pattern in self.malicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    pattern_matches += 1
                    
                    # Check if this is brand impersonation (brand name + suspicious pattern)
                    if re.search(r'(paypal|ebay|amazon|microsoft|apple|google|facebook|twitter|instagram|linkedin|netflix|spotify|github|apple-id|paypal-|amazon-|microsoft-)', url, re.IGNORECASE):
                        brand_impersonation_detected = True
            
            if brand_impersonation_detected:
                results['flags'].append(f"CRITICAL: Brand impersonation detected - likely phishing")
                results['risk_score'] += 85  # Increased from 70 to 85 - this is extremely suspicious and should guarantee HIGH risk
            elif pattern_matches > 0:
                results['flags'].append(f"Suspicious patterns detected ({pattern_matches})")
                results['risk_score'] += min(pattern_matches * 30, 60)  # Increased from 25 to 30, cap from 45 to 60
            
            # 6. Check for tunneling services (WARNING, not blocking)
            tunneling_detected = False
            for tunnel_pattern in self.tunneling_services:
                if re.search(tunnel_pattern, domain, re.IGNORECASE):
                    tunneling_detected = True
                    results['flags'].append(f'TUNNELING SERVICE DETECTED: {domain}')
                    results['details']['tunneling_service'] = domain
                    results['risk_score'] += 30  # Significant risk but not blocking
                    break
            
            # 7. Quick blacklist check
            if domain in self.blacklisted_domains:
                results['flags'].append("Domain in blacklist")
                results['risk_score'] += 90  # Increased from 50 to 90 - blacklisted domains should be HIGH risk
                results['passed'] = False
            
            # 8. Protocol check
            if parsed.scheme not in ['http', 'https']:
                results['flags'].append("Unusual protocol")
                results['risk_score'] += 15
            
            # 9. Check for common legitimate patterns
            legitimate_patterns = [
                r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.(?:com|org|net|edu|gov)$',
                r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]*\.(?:co\.uk|com\.au|com\.ca)$'
            ]
            
            is_legitimate_pattern = any(re.match(pattern, domain) for pattern in legitimate_patterns)
            if is_legitimate_pattern:
                results['flags'].append("Domain follows legitimate naming pattern")
                results['risk_score'] = max(0, results['risk_score'] - 10)
            
            results['details'] = {
                'url_length': len(url),
                'domain': domain,
                'protocol': parsed.scheme,
                'pattern_matches': pattern_matches,
                'is_whitelisted': False,
                'follows_legitimate_pattern': is_legitimate_pattern,
                'tunneling_detected': tunneling_detected if 'tunneling_detected' in locals() else False
            }
            
        except Exception as e:
            results['flags'].append(f"Validation error: {str(e)}")
            results['risk_score'] = 40
            results['passed'] = False
        
        return results

class Layer2_FeatureAnalysis(DetectionLayer):
    """
    Layer 2: Feature Analysis
    - Domain-based features
    - URL structure analysis
    - WHOIS data analysis
    """
    
    def __init__(self):
        super().__init__("Feature Analysis", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL features."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {}
        }
        
        try:
            # Extract features
            features = extract_features(url)
            
            # Assess risk based on features
            risk_score = 0.0
            
            # 1. Check for IP address in URL - CRITICAL SECURITY RISK
            if features.get('has_ip_address', False):
                results['flags'].append("IP address used in URL - CRITICAL phishing indicator")
                risk_score += 80  # Increased from 60 to 80 - this should almost guarantee HIGH risk
            
            # 2. Check URL length
            if features.get('url_length') == 'Suspicious':
                results['flags'].append("Suspicious URL length")
                risk_score += 15
            elif features.get('url_length') == 'Phishing':
                results['flags'].append("Very long URL")
                risk_score += 30
            
            # 5. Check for shortened URL - HIGH RISK
            if features.get('is_shortened', False):
                results['flags'].append("URL shortening service detected - commonly used for phishing")
                risk_score += 35  # Increased from 25 to 35
            
            # 4. Check for double slash redirect
            if features.get('double_slash_redirect', False):
                results['flags'].append("Double slash redirect detected")
                risk_score += 10
            
            # 5. Check for dash in domain
            if features.get('has_dash_in_domain', False):
                results['flags'].append("Domain contains dashes")
                risk_score += 15
            
            # 6. Check subdomain level
            if features.get('subdomain_level') == 'Suspicious':
                results['flags'].append("Suspicious subdomain depth")
                risk_score += 20
            elif features.get('subdomain_level') == 'Phishing':
                results['flags'].append("Excessive subdomain levels")
                risk_score += 35
            
            # 7. Check for HTTPS in domain (not in protocol)
            if features.get('https_token_in_domain', False):
                results['flags'].append("HTTPS token in domain name")
                risk_score += 40
            
            # 8. Check domain age - MAJOR RISK FACTOR
            if features.get('domain_age') == 'Phishing':
                results['flags'].append("Domain registered less than 6 months ago - high phishing risk")
                risk_score += 25  # Reduced back from 35 to 25 - new domains can be legitimate
            
            # 9. Check domain expiry
            if features.get('domain_registration_length') == 'Phishing':
                results['flags'].append("Domain expires in less than 1 year")
                risk_score += 15
            
            # 10. Check DNS record - CRITICAL INFRASTRUCTURE ISSUE
            if not features.get('dns_record', True):
                results['flags'].append("No DNS record found - CRITICAL security issue")
                risk_score += 50  # Increased from 40 to 50 - missing DNS is very suspicious
            
            # Set final risk score (cap at 100)
            results['risk_score'] = min(100, risk_score)
            results['details'] = features
            
        except Exception as e:
            results['flags'].append(f"Feature analysis error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results

class Layer3_ContentAnalysis(DetectionLayer):
    """
    Layer 2+: Content Analysis
    - Examines HTML structure and content
    - Analyzes JavaScript patterns
    - Detects suspicious form behaviors
    - Checks for SSL certificate issues
    """
    
    def __init__(self):
        super().__init__("Content Analysis", weight=1.2)
        self.sensitive_terms = [
            'password', 'credit card', 'login', 'ssn', 'social security',
            'verify', 'bank', 'account', 'update', 'confirm', 'secure'
        ]
        self.js_suspicious_patterns = [
            'document.cookie', 'window.location', 'eval(', 'fromCharCode',
            'onsubmit', 'addEventListener("submit"', '.submit()', 'keylogger',
            'obfuscated', 'document.forms[0]'
        ]
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze page content and behavior."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'content_analysis': {},
            'ssl_info': {},
            'form_analysis': {},
            'js_analysis': {}
        }
        
        try:
            # Only proceed if URL is valid and accessible
            if not url.startswith(('http://', 'https://')):
                results['flags'].append("Skipping content analysis - invalid URL protocol")
                return results
            
            # Get page content
            content = self._fetch_page_content(url)
            if content:
                # Analyze HTML structure
                html_risk, html_flags, html_analysis = self._analyze_html(content, url)
                results['content_analysis'] = html_analysis
                results['flags'].extend(html_flags)
                results['risk_score'] += html_risk
                
                # Analyze JavaScript
                js_risk, js_flags, js_analysis = self._analyze_javascript(content, url)
                results['js_analysis'] = js_analysis
                results['flags'].extend(js_flags)
                results['risk_score'] += js_risk
                
                # Analyze forms
                form_risk, form_flags, form_analysis = self._analyze_forms(content, url)
                results['form_analysis'] = form_analysis
                results['flags'].extend(form_flags)
                results['risk_score'] += form_risk
            else:
                # If content fetch fails, perform URL-based analysis
                results['flags'].append("Failed to fetch page content - performing URL-based analysis")
                
                # URL-based content analysis
                url_risk, url_flags = self._analyze_url_structure(url)
                results['flags'].extend(url_flags)
                results['risk_score'] += url_risk
                
                # Set default analysis results
                results['content_analysis'] = {'analysis_type': 'url_based', 'content_available': False}
                results['js_analysis'] = {'analysis_type': 'url_based', 'content_available': False}
                results['form_analysis'] = {'analysis_type': 'url_based', 'content_available': False}
            
            # Check SSL certificate
            ssl_risk, ssl_flags, ssl_info = self._check_ssl(url)
            results['ssl_info'] = ssl_info
            results['flags'].extend(ssl_flags)
            results['risk_score'] += ssl_risk
            
            # Cap risk score
            results['risk_score'] = min(100, results['risk_score'])
            
        except Exception as e:
            results['flags'].append(f"Content analysis error: {str(e)}")
            results['risk_score'] = 0  # Don't penalize for analysis failures
            
        return results
    
    def _fetch_page_content(self, url: str) -> Optional[str]:
        """Fetch page content with timeout."""
        try:
            import requests
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml',
                'Accept-Language': 'en-US,en;q=0.9'
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            return response.text
        except Exception as e:
            logger.error(f"Failed to fetch content for {url}: {e}")
            return None
    
    def _analyze_html(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze HTML content for suspicious patterns."""
        risk_score = 0
        flags = []
        analysis = {
            'title_mismatch': False,
            'brand_mentions': [],
            'hidden_elements': 0,
            'iframe_count': 0,
            'external_resources': 0,
            'suspicious_elements': [],
            'favicon_mismatch': False,
            'login_form_present': False,
            'seo_issues': [],
            'html_quality': {}
        }
        
        # Check if this is a major legitimate site that we should be extra lenient with
        domain = urllib.parse.urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        
        major_legitimate_sites = {
            'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
            'wikipedia.org', 'netflix.com', 'spotify.com', 'paypal.com',
            'ebay.com', 'adobe.com', 'instagram.com', 'whatsapp.com'
        }
        
        is_major_legitimate = domain.lower() in major_legitimate_sites
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check page title
            title = soup.title.text if soup.title else ""
            analysis['page_title'] = title
            
            # Extract domain from URL for comparison
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            
            # Check for title mismatch with domain (but be lenient for educational sites)
            analysis['title_mismatch'] = main_domain.lower() not in title.lower()
            
            # Check if this is an educational/reference site that commonly has descriptive titles
            educational_domains = ['w3schools.com', 'stackoverflow.com', 'github.com', 'mdn.mozilla.org', 
                                 'codecademy.com', 'freecodecamp.org', 'coursera.org', 'edx.org', 'khanacademy.org']
            is_educational = any(edu_domain in domain.lower() for edu_domain in educational_domains)
            
            # Be extra lenient with major legitimate sites
            if analysis['title_mismatch'] and not is_educational and not is_major_legitimate:
                flags.append("Page title doesn't match domain")
                risk_score += 15
            elif analysis['title_mismatch'] and (is_educational or is_major_legitimate):
                flags.append("Known legitimate site with complex title (normal)")
                # Don't add risk score for educational or major legitimate sites
            
            # Check for brand mentions in content - be more intelligent about legitimate sites
            common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 
                             'google', 'chase', 'bank', 'netflix', 'instagram',
                             'linkedin', 'outlook', 'gmail', 'office365', 'bitcoin',
                             'wellsfargo', 'bankofamerica', 'citibank', 'dropbox']
            
            # Get full page text
            page_text = soup.get_text().lower()
            
            # Special handling for legitimate domains that naturally contain brand mentions
            is_google_property = domain.lower() in ['youtube.com', 'gmail.com', 'google.com', 'accounts.google.com']
            is_microsoft_property = domain.lower() in ['outlook.com', 'office.com', 'microsoft.com', 'live.com']
            is_legitimate_brand_site = is_google_property or is_microsoft_property
            
            brand_mentions_found = []
            for brand in common_brands:
                if brand.lower() in page_text and brand not in domain.lower():
                    # Skip Google/YouTube mentions on legitimate Google properties
                    if is_google_property and brand in ['google', 'youtube', 'gmail']:
                        continue
                    # Skip Microsoft mentions on legitimate Microsoft properties
                    if is_microsoft_property and brand in ['microsoft', 'outlook']:
                        continue
                    
                    brand_mentions_found.append(brand)
            
            analysis['brand_mentions'] = brand_mentions_found
            
            # Only penalize if we found suspicious brand mentions
            if brand_mentions_found and not is_major_legitimate:
                flags.append(f"References to {brand_mentions_found[0]} found, but not in domain")
                risk_score += 10
            
            # Count multiple brand mentions for additional context
            if len(brand_mentions_found) > 1 and not is_legitimate_brand_site:
                flags.append(f"Multiple ({len(brand_mentions_found)}) brand references not in domain name")
                risk_score += min(5 * (len(brand_mentions_found) - 1), 15)  # Cap at +15 points
            
            # ENHANCED: Comprehensive hidden element analysis for LAYER 3
            hidden_risk, hidden_flags, hidden_analysis = self._analyze_hidden_elements(soup, url)
            analysis['hidden_elements_analysis'] = hidden_analysis
            flags.extend(hidden_flags)
            risk_score += hidden_risk
            
            # Keep backward compatibility - set the basic hidden_elements count
            analysis['hidden_elements'] = hidden_analysis.get('total_hidden_elements', 0)
            
            # Check for iframes (can be used for clickjacking)
            iframes = soup.find_all('iframe')
            analysis['iframe_count'] = len(iframes)
            if analysis['iframe_count'] > 0:
                flags.append(f"Found {analysis['iframe_count']} iframes")
                risk_score += 5 * min(analysis['iframe_count'], 3)  # Cap at 15 points
                
                # NEW: Check for suspicious iframe sources
                suspicious_iframe = False
                for iframe in iframes:
                    src = iframe.get('src', '')
                    if src:
                        # Check if iframe source is from different domain
                        try:
                            iframe_domain = urllib.parse.urlparse(src).netloc
                            if iframe_domain and iframe_domain != domain:
                                suspicious_iframe = True
                                flags.append(f"Iframe from external domain: {iframe_domain}")
                                break
                        except:
                            pass
                
                if suspicious_iframe:
                    risk_score += 10
            
            # Check for external resources
            external_resources = 0
            resource_domains = set()
            parsed_domain = urllib.parse.urlparse(url).netloc
            for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith(('http://', 'https://')):
                    try:
                        resource_domain = urllib.parse.urlparse(src).netloc
                        if resource_domain and resource_domain != parsed_domain:
                            external_resources += 1
                            resource_domains.add(resource_domain)
                    except:
                        pass
            
            analysis['external_resources'] = external_resources
            analysis['resource_domains'] = list(resource_domains)
            
            # NEW: Check resource domain count - high count can be suspicious
            if len(resource_domains) > 10:  # Many external domains can be suspicious
                flags.append(f"High number of external domains: {len(resource_domains)}")
                risk_score += min(20, len(resource_domains))
            
            # Look for suspicious meta elements
            meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
            if meta_refresh:
                analysis['suspicious_elements'].append('meta-refresh')
                flags.append("Page uses meta refresh (possible redirect)")
                risk_score += 10
                
                # NEW: Check if meta refresh redirects to external domain
                content_attr = meta_refresh.get('content', '')
                if 'url=' in content_attr.lower():
                    redirect_url = content_attr.split('url=', 1)[1].strip()
                    try:
                        redirect_domain = urllib.parse.urlparse(redirect_url).netloc
                        if redirect_domain and redirect_domain != domain:
                            flags.append(f"Meta refresh redirects to external domain: {redirect_domain}")
                            risk_score += 15
                    except:
                        pass
            
            # NEW: Check favicon source domain
            favicon_mismatch = False
            favicon_tags = soup.find_all('link', rel=['icon', 'shortcut icon', 'apple-touch-icon'])
            
            for favicon in favicon_tags:
                href = favicon.get('href', '')
                if href and href.startswith(('http://', 'https://')):
                    try:
                        favicon_domain = urllib.parse.urlparse(href).netloc
                        if favicon_domain and favicon_domain != domain:
                            favicon_mismatch = True
                            flags.append(f"Favicon from different domain: {favicon_domain}")
                            break
                    except:
                        pass
            
            analysis['favicon_mismatch'] = favicon_mismatch
            if favicon_mismatch:
                risk_score += 10
            
            # NEW: Check login form presence
            login_forms = 0
            password_fields = 0
            
            # Find forms with password fields or login-related attributes
            for form in soup.find_all('form'):
                has_password = len(form.find_all('input', {'type': 'password'})) > 0
                form_id = form.get('id', '').lower()
                form_class = form.get('class', [])
                form_class = ' '.join(form_class).lower() if form_class else ''
                form_action = form.get('action', '').lower()
                
                login_indicators = ['login', 'signin', 'sign-in', 'logon', 'auth', 'credential']
                
                if (has_password or 
                    any(ind in form_id for ind in login_indicators) or
                    any(ind in form_class for ind in login_indicators) or
                    any(ind in form_action for ind in login_indicators)):
                    
                    login_forms += 1
                    password_fields += len(form.find_all('input', {'type': 'password'}))
            
            analysis['login_form_present'] = login_forms > 0
            analysis['login_forms_count'] = login_forms
            analysis['password_fields_count'] = password_fields
            
            if login_forms > 0:
                # For login forms, check if they submit to external domain
                external_action = False
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    if action.startswith(('http://', 'https://')):
                        try:
                            action_domain = urllib.parse.urlparse(action).netloc
                            if action_domain and action_domain != domain:
                                external_action = True
                                flags.append(f"Login form submits to external domain: {action_domain}")
                                break
                        except:
                            pass
                
                if external_action:
                    risk_score += 30
                elif password_fields > 0:
                    # Only flag login form as suspicious if not part of main domain (may be legitimate)
                    brand_in_domain = any(brand in domain.lower() for brand in analysis['brand_mentions'])
                    if brand_in_domain:
                        flags.append("Login form present with known brand in URL - potential phishing")
                        risk_score += 15
            
            # NEW: Check for poor HTML quality (often indicates phishing)
            html_quality = {
                'has_doctype': bool(soup.find('html').parent.name == '[document]' if soup.find('html') else False),
                'has_html_tag': bool(soup.find('html')),
                'has_head_tag': bool(soup.find('head')),
                'has_body_tag': bool(soup.find('body')),
                'has_broken_links': False,
                'element_count': len(soup.find_all()),
                'text_to_html_ratio': len(page_text) / max(1, len(content))
            }
            
            # Check for broken links
            broken_links = 0
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if href == '#' or href == '' or href == 'javascript:void(0)':
                    broken_links += 1
            
            html_quality['broken_links_count'] = broken_links
            html_quality['has_broken_links'] = broken_links > 5
            
            analysis['html_quality'] = html_quality
            
            # Score for poor HTML quality
            quality_issues = 0
            if not html_quality['has_doctype']:
                quality_issues += 1
            if not html_quality['has_head_tag'] or not html_quality['has_body_tag']:
                quality_issues += 1
            if html_quality['has_broken_links']:
                quality_issues += 1
            if html_quality['element_count'] < 10:  # Very simple page
                quality_issues += 1
            
            if quality_issues >= 2:
                flags.append(f"Poor HTML quality ({quality_issues} issues detected)")
                risk_score += quality_issues * 5  # 5 points per quality issue
            
            # NEW: Check for SEO elements consistency
            meta_description = soup.find('meta', {'name': 'description'})
            meta_keywords = soup.find('meta', {'name': 'keywords'})
            
            seo_issues = []
            
            # Check if meta description includes domain name
            if meta_description:
                meta_desc_content = meta_description.get('content', '').lower()
                if main_domain.lower() not in meta_desc_content:
                    seo_issues.append("Meta description doesn't match domain")
            
            # Check for keyword stuffing (often in phishing)
            if meta_keywords:
                keywords = meta_keywords.get('content', '').lower()
                keyword_count = len(keywords.split(','))
                if keyword_count > 15:  # Excessive keywords
                    seo_issues.append(f"Keyword stuffing ({keyword_count} keywords)")
            
            if seo_issues:
                analysis['seo_issues'] = seo_issues
                flags.extend(seo_issues)
                risk_score += len(seo_issues) * 5  # 5 points per SEO issue
                
        except Exception as e:
            flags.append(f"HTML analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def _analyze_javascript(self, content: str, url: str = None) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze JavaScript for suspicious patterns."""
        risk_score = 0
        flags = []
        analysis = {
            'suspicious_patterns': [],
            'obfuscation_detected': False,
            'event_handlers': 0,
            'eval_usage': False
        }
        
        # Check if this is a major legitimate site that uses complex JS
        is_major_legitimate = False
        if url:
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            
            major_legitimate_sites = {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
                'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                'wikipedia.org', 'netflix.com', 'spotify.com', 'paypal.com'
            }
            is_major_legitimate = domain.lower() in major_legitimate_sites
        
        try:
            # Extract all script content
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Get inline scripts
            script_tags = soup.find_all('script')
            script_content = ' '.join([tag.string for tag in script_tags if tag.string])
            
            # Check for suspicious patterns (be lenient with major legitimate sites)
            for pattern in self.js_suspicious_patterns:
                if pattern in script_content:
                    analysis['suspicious_patterns'].append(pattern)
                    if not is_major_legitimate:
                        flags.append(f"Suspicious JavaScript: {pattern}")
                        risk_score += 10
                    else:
                        # Major legitimate sites commonly use these patterns
                        risk_score += 2  # Very low penalty
            
            # Check for obfuscation (common in malicious scripts)
            obfuscation_indicators = [
                'fromCharCode', 'unescape', 'escape', 'eval', 'atob', 'btoa',
                'String.fromCharCode', 'parseInt', 'String.charAt'
            ]
            
            obfuscation_score = 0
            for indicator in obfuscation_indicators:
                if indicator in script_content:
                    obfuscation_score += 1
            
            # Also check for very long strings or lots of hex/unicode
            hex_pattern = r'\\x[0-9a-f]{2}'
            unicode_pattern = r'\\u[0-9a-f]{4}'
            hex_matches = len(re.findall(hex_pattern, script_content))
            unicode_matches = len(re.findall(unicode_pattern, script_content))
            
            if hex_matches + unicode_matches > 20:
                obfuscation_score += 2
            
            if obfuscation_score >= 2:
                analysis['obfuscation_detected'] = True
                if not is_major_legitimate:
                    flags.append("JavaScript obfuscation detected")
                    risk_score += 25
                else:
                    flags.append("JavaScript complexity detected (normal for major sites)")
                    risk_score += 5  # Very low penalty for major legitimate sites
            
            # Count event handlers (especially form-related)
            event_handlers = re.findall(r'on(submit|click|load|change|mouse|key|focus|blur)', script_content)
            analysis['event_handlers'] = len(event_handlers)
            
            if analysis['event_handlers'] > 5:  # Many event handlers can be suspicious
                flags.append(f"High number of event handlers: {analysis['event_handlers']}")
                risk_score += 10
            
            # Check for direct eval usage
            analysis['eval_usage'] = 'eval(' in script_content
            if analysis['eval_usage']:
                flags.append("Direct eval() usage detected")
                risk_score += 15
            
            # NEW: Check for data forwarding patterns in JavaScript
            data_forwarding_patterns = [
                r'fetch\s*\(\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')',
                r'XMLHttpRequest.*open\s*\(\s*["\'](?:GET|POST)["\'],\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')',
                r'ajax.*url\s*:\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')',
                r'postMessage.*origin\s*:\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')',
                r'location\.href\s*=\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')',
                r'window\.open\s*\(\s*["\']https?://(?!.*' + re.escape(urllib.parse.urlparse(url).netloc if url else '') + r')'
            ]
            
            analysis['data_forwarding'] = False
            for pattern in data_forwarding_patterns:
                try:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        analysis['data_forwarding'] = True
                        if not is_major_legitimate:
                            flags.append("JavaScript forwards data to external domain")
                            risk_score += 25
                        break
                except:
                    pass
            
            # Check for credential harvesting patterns
            credential_patterns = [
                r'(password|username|email|login).*value.*send',
                r'document\.forms.*submit',
                r'input.*password.*post',
                r'btoa.*password|username',
                r'encodeURIComponent.*password|username'
            ]
            
            analysis['credential_harvesting'] = False
            for pattern in credential_patterns:
                if re.search(pattern, script_content, re.IGNORECASE):
                    analysis['credential_harvesting'] = True
                    if not is_major_legitimate:
                        flags.append("JavaScript may harvest credentials")
                        risk_score += 20
                    break
                
        except Exception as e:
            flags.append(f"JavaScript analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def _analyze_forms(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze forms for phishing indicators."""
        risk_score = 0
        flags = []
        analysis = {
            'form_count': 0,
            'password_fields': 0,
            'sensitive_fields': 0,
            'external_submission': False,
            'insecure_submission': False,
            'missing_security': False,
            'sensitive_forms': []
        }
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            analysis['form_count'] = len(forms)
            
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            
            for form in forms:
                form_info = {
                    'has_password': False,
                    'sensitive_field_count': 0,
                    'external_action': False,
                    'insecure_action': False,
                    'action_domain': None
                }
                
                # Check form action
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                
                if action:
                    # Check if action is an absolute URL
                    if action.startswith(('http://', 'https://')):
                        action_domain = urllib.parse.urlparse(action).netloc
                        if action_domain.startswith('www.'):
                            action_domain = action_domain[4:]
                        form_info['action_domain'] = action_domain
                        
                        # If action domain doesn't match the current domain
                        if action_domain != domain:
                            form_info['external_action'] = True
                            analysis['external_submission'] = True
                            flags.append(f"Form submits to external domain: {action_domain}")
                            risk_score += 30
                        
                        # Check if using HTTP for sensitive data
                        if action.startswith('http://'):
                            form_info['insecure_action'] = True
                            analysis['insecure_submission'] = True
                    
                    # Check for suspicious action URLs
                    suspicious_actions = [
                        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
                        'data:text/html', 'javascript:', 'about:blank'
                    ]
                    
                    for suspicious in suspicious_actions:
                        if suspicious in action.lower():
                            flags.append(f"Form uses suspicious action: {suspicious}")
                            risk_score += 25
                            break
                
                # Check for password fields
                password_fields = form.find_all('input', {'type': 'password'})
                form_info['has_password'] = len(password_fields) > 0
                analysis['password_fields'] += len(password_fields)
                
                # Check for sensitive input fields
                form_sensitive_count = 0
                inputs = form.find_all('input')
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    field_id = input_field.get('id', '').lower()
                    field_placeholder = input_field.get('placeholder', '').lower()
                    field_type = input_field.get('type', '').lower()
                    
                    # Enhanced sensitive field detection
                    sensitive_indicators = [
                        'password', 'email', 'username', 'login', 'user',
                        'ssn', 'social', 'credit', 'card', 'cvv', 'expir',
                        'phone', 'mobile', 'address', 'birth', 'dob',
                        'pin', 'security', 'answer', 'mother', 'maiden',
                        'passport', 'license', 'account', 'routing'
                    ]
                    
                    is_sensitive = (
                        field_type in ['password', 'email', 'tel'] or
                        any(term in field_name for term in sensitive_indicators) or
                        any(term in field_id for term in sensitive_indicators) or
                        any(term in field_placeholder for term in sensitive_indicators)
                    )
                    
                    if is_sensitive:
                        form_sensitive_count += 1
                        analysis['sensitive_fields'] += 1
                
                form_info['sensitive_field_count'] = form_sensitive_count
                
                # If form has sensitive data, add to sensitive forms list
                if form_info['has_password'] or form_sensitive_count > 0:
                    analysis['sensitive_forms'].append(form_info)
                
                # Check security indicators
                missing_security = False
                
                # Should have HTTPS if collecting sensitive data
                if url.startswith('http://') and analysis['sensitive_fields'] > 0:
                    missing_security = True
                    flags.append("Form collects sensitive data over HTTP")
                    risk_score += 20
                
                # Check for CSRF token (can be various names)
                csrf_present = False
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    if any(token in field_name for token in ['csrf', 'token', 'nonce']):
                        csrf_present = True
                        break
                
                if analysis['sensitive_fields'] > 0 and not csrf_present:
                    missing_security = True
                    flags.append("Form lacks CSRF protection")
                    risk_score += 10
                
                analysis['missing_security'] = missing_security
            
            # Overall form risk assessment
            if analysis['password_fields'] > 0:
                flags.append(f"Form contains {analysis['password_fields']} password fields")
                risk_score += 15
            
            if analysis['sensitive_fields'] > 2:
                flags.append(f"Form collects multiple sensitive fields ({analysis['sensitive_fields']})")
                risk_score += 10
                
        except Exception as e:
            flags.append(f"Form analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def _check_ssl(self, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Check SSL certificate validity."""
        risk_score = 0
        flags = []
        ssl_info = {
            'has_ssl': False,
            'cert_valid': False,
            'cert_matches_domain': False,
            'cert_expiry': None,
            'cert_authority': None
        }
        
        # Only check HTTPS URLs
        if not url.startswith('https://'):
            ssl_info['has_ssl'] = False
            return risk_score, flags, ssl_info
        
        try:
            import socket
            import ssl
            import OpenSSL.crypto as crypto
            from datetime import datetime
            
            ssl_info['has_ssl'] = True
            
            # Parse URL to get hostname
            hostname = urllib.parse.urlparse(url).netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]  # Remove port if present
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Check if certificate matches domain
                    cert_domains = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if 'subjectAltName' in str(ext.get_short_name()):
                            data = ext.get_data()
                            # Parse SANs (simplified approach)
                            sans = str(data)
                            for domain in sans.split(','):
                                if 'DNS:' in domain:
                                    cert_domains.append(domain.split('DNS:')[1].strip())
                    
                    common_name = x509.get_subject().CN
                    if common_name:
                        cert_domains.append(common_name)
                    
                    # Check if any cert domain matches our URL domain
                    domain_match = False
                    for cert_domain in cert_domains:
                        # Check for exact match or wildcard
                        if cert_domain == hostname or (cert_domain.startswith('*.') and hostname.endswith(cert_domain[1:])):
                            domain_match = True
                            break
                    
                    ssl_info['cert_matches_domain'] = domain_match
                    if not domain_match:
                        # Check if this is a major legitimate site with CDN/load balancing
                        domain = urllib.parse.urlparse(url).netloc
                        if domain.startswith('www.'):
                            domain = domain[4:]
                        
                        major_legitimate_sites = {
                            'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
                            'apple.com', 'amazon.com', 'facebook.com', 'twitter.com'
                        }
                        
                        if domain.lower() in major_legitimate_sites:
                            flags.append("SSL certificate from CDN (normal for major sites)")
                            risk_score += 5  # Very low penalty for major sites
                        else:
                            flags.append("SSL certificate doesn't match domain")
                            risk_score += 25
                    
                    # Check expiry
                    expiry = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    ssl_info['cert_expiry'] = expiry.isoformat()
                    
                    if expiry < datetime.now():
                        flags.append("SSL certificate has expired")
                        risk_score += 30
                        ssl_info['cert_valid'] = False
                    else:
                        ssl_info['cert_valid'] = True
                    
                    # Check issuer (CA)
                    issuer = x509.get_issuer()
                    ssl_info['cert_authority'] = issuer.CN if hasattr(issuer, 'CN') else str(issuer)
                    
                    # Self-signed certificates are suspicious
                    if issuer.CN == x509.get_subject().CN:
                        flags.append("Self-signed SSL certificate")
                        risk_score += 25
            
        except ssl.SSLError as e:
            flags.append(f"SSL Error: {str(e)}")
            risk_score += 20
        except Exception as e:
            flags.append(f"Failed to verify SSL: {str(e)}")
            # Don't add risk score for analysis failures
        
        return risk_score, flags, ssl_info

    def _analyze_url_structure(self, url: str) -> Tuple[float, List[str]]:
        """Analyze URL structure when content is not available."""
        risk_score = 0
        flags = []
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious URL patterns
            if 'paypal' in domain and 'paypal.com' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (PAYPAL) - POSSIBLE IMPERSONATION")
                risk_score += 40
            
            if 'amazon' in domain and 'amazon.com' not in domain and 'amazon.' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (AMAZON) - POSSIBLE IMPERSONATION")
                risk_score += 40
                
            if 'microsoft' in domain and 'microsoft.com' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (MICROSOFT) - POSSIBLE IMPERSONATION")
                risk_score += 40
                
            if 'google' in domain and 'google.com' not in domain and 'google.' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (GOOGLE) - POSSIBLE IMPERSONATION")
                risk_score += 40
            
            if 'facebook' in domain and 'facebook.com' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (FACEBOOK) - POSSIBLE IMPERSONATION")
                risk_score += 40
                
            if 'apple' in domain and 'apple.com' not in domain:
                flags.append("DOMAIN CONTAINS BRAND NAME (APPLE) - POSSIBLE IMPERSONATION")
                risk_score += 40
            
            # Check for suspicious TLDs when combined with brand names
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                flags.append("SUSPICIOUS TLD DETECTED (.tk/.ml/.ga/.cf) - OFTEN USED FOR PHISHING")
                risk_score += 30
            
            # Check for excessive hyphens (common in phishing)
            if domain.count('-') > 2:
                flags.append("EXCESSIVE HYPHENS IN DOMAIN - SUSPICIOUS PATTERN")
                risk_score += 20
            
            # Check for numeric domains or IP addresses
            if parsed.netloc.replace('.', '').isdigit():
                flags.append("IP ADDRESS USED INSTEAD OF DOMAIN - HIGH RISK")
                risk_score += 50
            
            # Check for data forwarding indicators in URL structure
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            # Suspicious URL patterns that suggest data forwarding
            data_forwarding_patterns = [
                'redirect', 'forward', 'proxy', 'gateway', 'relay',
                'submit', 'post', 'send', 'transfer', 'bounce'
            ]
            
            for pattern in data_forwarding_patterns:
                if pattern in path or pattern in query:
                    flags.append(f"URL CONTAINS DATA FORWARDING PATTERN: {pattern.upper()}")
                    risk_score += 15
                    break
            
            # Check for URL shortener patterns (often used to hide destination)
            url_shortener_patterns = [
                'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'ow.ly',
                'short', 'link', 'url', 'redir', 'go.', 'cli.ck'
            ]
            
            for pattern in url_shortener_patterns:
                if pattern in domain:
                    flags.append("URL SHORTENER DETECTED - MAY HIDE REAL DESTINATION")
                    risk_score += 25
                    break
            
            # Check for suspicious query parameters
            suspicious_params = [
                'return_url', 'redirect_uri', 'continue', 'next', 'goto',
                'destination', 'target', 'forward_to', 'callback'
            ]
            
            for param in suspicious_params:
                if param in query:
                    flags.append(f"SUSPICIOUS REDIRECT PARAMETER: {param.upper()}")
                    risk_score += 20
                    break
                
        except Exception as e:
            logger.error(f"Error in URL structure analysis: {e}")
            
        return risk_score, flags

    def _analyze_hidden_elements(self, soup, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Enhanced hidden element detection for LAYER 3: CONTENT ANALYSIS
        Detects various techniques used by phishing sites to hide malicious content.
        """
        risk_score = 0
        flags = []
        analysis = {
            'total_hidden_elements': 0,
            'hidden_forms': 0,
            'hidden_inputs': 0,
            'offscreen_elements': 0,
            'invisible_elements': 0,
            'tiny_elements': 0,
            'clipped_elements': 0,
            'css_hidden_elements': 0,
            'javascript_hidden': 0,
            'suspicious_hidden_content': [],
            'hidden_element_details': []
        }
        
        try:
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check if this is a major legitimate site (be more lenient)
            major_legitimate_sites = {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com',
                'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                'wikipedia.org', 'netflix.com', 'spotify.com', 'paypal.com'
            }
            is_major_legitimate = domain.lower() in major_legitimate_sites
            
            # 1. CSS display:none and visibility:hidden
            css_hidden = soup.select('[style*="display: none"], [style*="display:none"], [style*="visibility: hidden"], [style*="visibility:hidden"]')
            analysis['css_hidden_elements'] = len(css_hidden)
            
            # 2. Opacity-based hiding
            opacity_hidden = soup.select('[style*="opacity: 0"], [style*="opacity:0"], [style*="opacity: 0.0"], [style*="opacity:0.0"]')
            analysis['invisible_elements'] = len(opacity_hidden)
            
            # 3. HTML5 hidden attribute and ARIA hidden
            html_hidden = soup.select('[hidden], [aria-hidden="true"]')
            
            # 4. Off-screen positioning (left/top negative values)
            offscreen_selectors = [
                '[style*="position: absolute"][style*="left: -"]',
                '[style*="position:absolute"][style*="left:-"]',
                '[style*="position: fixed"][style*="left: -"]',
                '[style*="position:fixed"][style*="left:-"]',
                '[style*="top: -"]', '[style*="top:-"]',
                '[style*="margin-left: -"][style*="px"]',
                '[style*="margin-left:-"][style*="px"]'
            ]
            offscreen_elements = []
            for selector in offscreen_selectors:
                offscreen_elements.extend(soup.select(selector))
            analysis['offscreen_elements'] = len(offscreen_elements)
            
            # 5. Tiny/zero-sized elements (common hiding technique)
            tiny_selectors = [
                '[style*="width: 0"], [style*="width:0"]',
                '[style*="height: 0"], [style*="height:0"]',
                '[style*="width: 1px"], [style*="width:1px"]',
                '[style*="height: 1px"], [style*="height:1px"]',
                '[style*="font-size: 0"], [style*="font-size:0"]'
            ]
            tiny_elements = []
            for selector in tiny_selectors:
                tiny_elements.extend(soup.select(selector))
            analysis['tiny_elements'] = len(tiny_elements)
            
            # 6. Clipped elements (overflow:hidden with tiny dimensions)
            clipped_elements = soup.select('[style*="overflow: hidden"], [style*="overflow:hidden"]')
            # Filter for those that also have small dimensions
            actual_clipped = []
            for elem in clipped_elements:
                style = elem.get('style', '').lower()
                if ('width: 0' in style or 'height: 0' in style or 
                    'width:0' in style or 'height:0' in style):
                    actual_clipped.append(elem)
            analysis['clipped_elements'] = len(actual_clipped)
            
            # Combine all hidden elements
            all_hidden = set(css_hidden + opacity_hidden + html_hidden + offscreen_elements + tiny_elements + actual_clipped)
            analysis['total_hidden_elements'] = len(all_hidden)
            
            # 7. Check for hidden forms (especially dangerous)
            hidden_forms = 0
            for form in soup.find_all('form'):
                if form in all_hidden:
                    hidden_forms += 1
                    analysis['hidden_element_details'].append({
                        'type': 'hidden_form',
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET'),
                        'has_password': bool(form.find('input', {'type': 'password'}))
                    })
            analysis['hidden_forms'] = hidden_forms
            
            # 8. Check for hidden input fields (especially password/sensitive)
            hidden_inputs = 0
            sensitive_hidden_inputs = 0
            
            for input_elem in soup.find_all('input'):
                if input_elem in all_hidden or input_elem.parent in all_hidden:
                    hidden_inputs += 1
                    input_type = input_elem.get('type', '').lower()
                    input_name = input_elem.get('name', '').lower()
                    
                    # Check if it's sensitive data
                    sensitive_patterns = ['password', 'pass', 'pwd', 'credit', 'card', 'ssn', 'social']
                    is_sensitive = (input_type == 'password' or 
                                  any(pattern in input_name for pattern in sensitive_patterns))
                    
                    if is_sensitive:
                        sensitive_hidden_inputs += 1
                        analysis['hidden_element_details'].append({
                            'type': 'sensitive_hidden_input',
                            'input_type': input_type,
                            'name': input_name,
                            'parent_tag': input_elem.parent.name if input_elem.parent else 'unknown'
                        })
            
            analysis['hidden_inputs'] = hidden_inputs
            
            # 9. Check for JavaScript-based hiding (elements that might be hidden via JS)
            script_tags = soup.find_all('script')
            js_hiding_patterns = [
                'style.display = "none"', 'style.display="none"',
                'style.visibility = "hidden"', 'style.visibility="hidden"',
                'style.opacity = "0"', 'style.opacity="0"',
                '.hide()', '.fadeOut()', 'display:none', 'visibility:hidden'
            ]
            
            js_hiding_detected = 0
            for script in script_tags:
                if script.string:
                    script_content = script.string.lower()
                    for pattern in js_hiding_patterns:
                        if pattern in script_content:
                            js_hiding_detected += 1
                            break
            
            analysis['javascript_hidden'] = js_hiding_detected
            
            # 10. Look for suspicious content in hidden elements
            suspicious_keywords = [
                'login', 'password', 'username', 'email', 'credit', 'card',
                'ssn', 'social', 'security', 'bank', 'account', 'verify',
                'paypal', 'amazon', 'microsoft', 'apple', 'google'
            ]
            
            for elem in all_hidden:
                elem_text = elem.get_text().lower() if elem.get_text() else ''
                elem_attrs = ' '.join([f"{k}={v}" for k, v in elem.attrs.items()]).lower()
                all_elem_content = elem_text + ' ' + elem_attrs
                
                for keyword in suspicious_keywords:
                    if keyword in all_elem_content:
                        analysis['suspicious_hidden_content'].append({
                            'keyword': keyword,
                            'element': elem.name,
                            'content_preview': all_elem_content[:100]
                        })
                        break
            
            # Risk scoring based on findings
            if sensitive_hidden_inputs > 0:
                flags.append(f"CRITICAL: {sensitive_hidden_inputs} hidden sensitive input fields detected")
                risk_score += 50  # Very high risk for hidden password/sensitive fields
            
            if hidden_forms > 0:
                flags.append(f"WARNING: {hidden_forms} hidden forms detected")
                if not is_major_legitimate:
                    risk_score += 30
                else:
                    risk_score += 10  # Lower penalty for legitimate sites
            
            if analysis['suspicious_hidden_content']:
                flags.append(f"Suspicious content in {len(analysis['suspicious_hidden_content'])} hidden elements")
                risk_score += 25
            
            # General hidden element thresholds (adjusted for legitimate sites)
            if is_major_legitimate:
                hidden_threshold = 100  # Very high threshold for major sites
            else:
                hidden_threshold = 15   # Lower threshold for unknown sites
            
            if analysis['total_hidden_elements'] > hidden_threshold:
                flags.append(f"High number of hidden elements: {analysis['total_hidden_elements']}")
                if not is_major_legitimate:
                    risk_score += min(30, analysis['total_hidden_elements'] - hidden_threshold)
                else:
                    risk_score += 5  # Minimal penalty for major legitimate sites
            
            # Specific penalties for different hiding techniques
            if analysis['offscreen_elements'] > 5:
                flags.append(f"Elements positioned off-screen: {analysis['offscreen_elements']}")
                risk_score += 15
            
            if analysis['tiny_elements'] > 10:
                flags.append(f"Suspiciously tiny elements: {analysis['tiny_elements']}")
                risk_score += 15
            
            if js_hiding_detected > 0:
                flags.append(f"JavaScript-based element hiding detected")
                risk_score += 10
            
        except Exception as e:
            flags.append(f"Hidden element analysis error: {str(e)}")
            logger.error(f"Error in hidden element analysis: {e}")
        
        return risk_score, flags, analysis

# Update the LayeredPhishingDetector class to include the new layer



def _deployed_model_accuracy(default: float) -> float:
    """Held-out accuracy recorded by the training script (falls back to an estimate)."""
    try:
        with open(os.path.join(_HERE, 'models', 'evaluation_results.json')) as fh:
            return float(json.load(fh).get('accuracy', default))
    except Exception:
        return default


class Layer4_MLClassification(DetectionLayer):
    """
    Layer 3: Machine Learning Classification
    - Uses trained ML model to classify URLs
    - Provides confidence scores for phishing probability
    """
    
    def __init__(self):
        super().__init__("ML Classification", weight=1.5)  # Higher weight for ML predictions
        self.model = None
        self.vectorizer = None
        self.model_type = "Unknown"
        self.fallback_mode = False
        self._load_model()
    
    def _load_model(self):
        """Load ML model and vectorizer."""
        try:
            self.model, self.vectorizer = load_model()
            if self.model is not None and self.vectorizer is not None:
                # Check if it's our fallback model
                if hasattr(self.model, 'model_type') and self.model.model_type == "RandomForest_Fallback":
                    logger.info("Using fallback Random Forest model for ML classification")
                    self.model_type = "RandomForest_Fallback"
                    self.fallback_mode = True
                else:
                    self.model_type = getattr(self.model, 'model_type', type(self.model).__name__)
                    logger.info(f"ML model ({self.model_type}) and vectorizer loaded successfully")
            else:
                logger.warning("ML model or vectorizer not loaded")
                self.enabled = False
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.enabled = False
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL using ML model."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': []
        }
        
        try:
            if not self.model or not self.vectorizer:
                results['flags'].append("ML model not available")
                results['risk_score'] = 0
                return results
            
            # Start timing for inference
            start_time = datetime.now()
            
            # Get ML prediction
            prediction = predict_with_ml(url, self.model, self.vectorizer)
            
            # End timing
            inference_time = (datetime.now() - start_time).total_seconds()
            
            if prediction is None:
                results['flags'].append("ML prediction failed")
                results['risk_score'] = 30
                return results
            
            # Extract information from prediction
            is_phishing = prediction['prediction'] == 'phishing'
            confidence = prediction.get('confidence', 0)
            confidence_scores = prediction.get('confidence_scores', {})
            
            # Add results
            results['ml_prediction'] = prediction['prediction']
            results['confidence_scores'] = confidence_scores
            results['inference_time'] = inference_time
            results['model_info'] = {
                'type': self.model_type,
                'fallback_mode': self.fallback_mode,
                'accuracy': _deployed_model_accuracy(0.85 if self.fallback_mode else 0.92)
            }
            
            # Set risk score based on phishing probability
            if is_phishing:
                phish_confidence = confidence_scores.get('phishing', confidence)
                # Scale to risk score from 0-100
                results['risk_score'] = min(100, phish_confidence * 100)
                
                # Add flags based on confidence
                if phish_confidence > 0.8:
                    results['flags'].append("High probability of phishing")
                elif phish_confidence > 0.6:
                    results['flags'].append("Medium probability of phishing")
                else:
                    results['flags'].append("Low probability of phishing")
            else:
                # If legitimate, risk score is inverse of legitimate confidence
                legit_confidence = confidence_scores.get('legitimate', 1 - confidence)
                results['risk_score'] = min(100, (1 - legit_confidence) * 80)  # Cap at 80 for negative predictions
            
            # Add model info
            try:
                model_type = "RandomForest"
                if "XGBClassifier" in str(type(self.model)):
                    model_type = "XGBoost"
                
                # Check if model uses GPU
                gpu_accelerated = False
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    if 'tree_method' in params:
                        gpu_accelerated = 'gpu' in params['tree_method']
                
                results['model_info'] = {
                    'type': model_type,
                    'accuracy': 0.8147,  # Placeholder - should come from evaluation
                    'gpu_accelerated': gpu_accelerated
                }
            except:
                # Ignore if model info collection fails
                pass
            
        except Exception as e:
            results['flags'].append(f"ML classification error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results



class Layer5_EnsembleDecision(DetectionLayer):
    """
    Layer 4: Ensemble Decision
    - Combines results from previous layers
    - Resolves conflicts between layers
    - Produces weighted risk score
    """
    
    def __init__(self):
        super().__init__("Ensemble Decision")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Combine results from previous layers."""
        results = {
            'layer': self.name,
            'weighted_risk_score': 0.0,
            'layer_scores': {},
            'consensus': None,
            'conflicts': []
        }
        
        try:
            if not context or 'layer_results' not in context:
                results['weighted_risk_score'] = 50
                results['consensus'] = "ERROR"
                results['conflicts'].append("No layer results found")
                return results
            
            layer_results = context['layer_results']
            
            # Calculate weighted risk score
            total_weight = 0
            weighted_score = 0
            layer_votes = {'phishing': 0, 'legitimate': 0, 'unknown': 0}
            
            # Track scores for each layer
            for layer_result in layer_results:
                layer_name = layer_result.get('layer', 'Unknown')
                risk_score = layer_result.get('risk_score', 0)
                weight = layer_result.get('weight', 1.0)
                
                # Add to weighted score
                weighted_score += risk_score * weight
                total_weight += weight
                
                # Record layer score
                results['layer_scores'][layer_name] = risk_score
                
                # Determine layer vote
                if risk_score >= 60:  # High risk
                    layer_votes['phishing'] += 1
                elif risk_score <= 30:  # Low risk
                    layer_votes['legitimate'] += 1
                else:
                    layer_votes['unknown'] += 1
            # Calculate final weighted score
            if total_weight > 0:
                results['weighted_risk_score'] = weighted_score / total_weight
            else:
                results['weighted_risk_score'] = 50
            
            # Determine consensus
            if layer_votes['phishing'] > layer_votes['legitimate'] + layer_votes['unknown']:
                results['consensus'] = "PHISHING"
            elif layer_votes['legitimate'] > layer_votes['phishing'] + layer_votes['unknown']:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['phishing'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['legitimate'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "PHISHING"
            else:
                results['consensus'] = "UNCERTAIN"
            
            # Check for conflicts
            if layer_votes['phishing'] > 0 and layer_votes['legitimate'] > 0:
                results['conflicts'].append("Layers disagree on classification")
            
            # Check for strong ML disagreement
            ml_result = None
            for layer_result in layer_results:
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction == 'phishing' and results['weighted_risk_score'] < 40:
                        results['conflicts'].append("ML says phishing but other layers disagree")
                    elif ml_prediction == 'legitimate' and results['weighted_risk_score'] > 60:
                        results['conflicts'].append("ML says legitimate but other layers disagree")
                    ml_result = layer_result
                    break
            
            # If ML is very confident, increase its influence
            if ml_result and 'confidence_scores' in ml_result:
                ml_confidence = max(ml_result['confidence_scores'].values()) if ml_result['confidence_scores'] else 0
                if ml_confidence > 0.9:  # Very high confidence
                    ml_prediction = ml_result.get('ml_prediction')
                    if ml_prediction == 'phishing':
                        results['weighted_risk_score'] = max(results['weighted_risk_score'], 
                                                            results['weighted_risk_score'] * 1.2)  # Increase by 20%
                    elif ml_prediction == 'legitimate':
                        results['weighted_risk_score'] = min(results['weighted_risk_score'], 
                                                           results['weighted_risk_score'] * 0.8)  # Decrease by 20%
            
        except Exception as e:
            results['weighted_risk_score'] = 50
            results['consensus'] = "ERROR"
            results['conflicts'].append(f"Ensemble error: {str(e)}")
        
        return results



class Layer6_FinalVerdict(DetectionLayer):
    """
    Layer 5: Final Verdict
    - Determines final risk level
    - Provides recommendations
    - Aggregates warnings and details
    """
    
    def __init__(self):
        super().__init__("Final Verdict")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final verdict and recommendations."""
        results = {
            'final_verdict': RiskLevel.ERROR,
            'risk_percentage': 50,
            'confidence': 0.0,
            'recommendations': [],
            'summary': {},
            'early_termination': False
        }
        
        try:
            if not context:
                results['final_verdict'] = RiskLevel.ERROR
                results['risk_percentage'] = 50
                results['recommendations'].append("Analysis failed - insufficient data")
                return results
            
            # Check for early termination
            if 'final_result' in context and context['final_result'].get('early_termination', False):
                return context['final_result']
            
            # Get ensemble result
            ensemble_result = context.get('ensemble_result', {})
            risk_score = ensemble_result.get('weighted_risk_score', 50)
            consensus = ensemble_result.get('consensus', 'UNCERTAIN')
            conflicts = ensemble_result.get('conflicts', [])
            
            # Set risk percentage
            results['risk_percentage'] = risk_score
            
            # Determine confidence based on conflicts
            if not conflicts:
                confidence = 0.9  # High confidence if no conflicts
            elif len(conflicts) == 1:
                confidence = 0.7  # Medium confidence with one conflict
            else:
                confidence = 0.5  # Low confidence with multiple conflicts
                
            results['confidence'] = confidence
            
            # Determine final risk level - adjusted to catch critical threats better
            # More aggressive for IP addresses, brand impersonation, and blacklisted domains
            if risk_score >= 80:  # Decreased from 85
                results['final_verdict'] = RiskLevel.CRITICAL
            elif risk_score >= 55:  # Decreased from 65 - catch IP addresses and brand impersonation
                results['final_verdict'] = RiskLevel.HIGH
            elif risk_score >= 45:  # Decreased from 55
                results['final_verdict'] = RiskLevel.MEDIUM
            elif risk_score >= 25:  # Decreased from 35
                results['final_verdict'] = RiskLevel.LOW
            else:
                results['final_verdict'] = RiskLevel.SAFE
            
            # Generate recommendations based on risk level
            if results['final_verdict'] in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                results['recommendations'].extend([
                    "Do NOT proceed to this website",
                    "Do NOT enter any personal information",
                    "Do NOT download any files from this site"
                ])
            elif results['final_verdict'] == RiskLevel.MEDIUM:
                results['recommendations'].extend([
                    "Proceed with extreme caution",
                    "Verify the website through other channels before sharing information",
                    "Check the URL carefully for typos or unusual characters"
                ])
            elif results['final_verdict'] == RiskLevel.LOW:
                results['recommendations'].extend([
                    "Exercise normal caution",
                    "Verify the website if sharing sensitive information"
                ])
            else:  # SAFE
                results['recommendations'].extend([
                    "Website appears safe",
                    "Follow normal security practices"
                ])
            
            # Add any specific warnings from layers
            layer_flags = []
            for layer_result in context.get('layer_results', []):
                layer_flags.extend(layer_result.get('flags', []))
            
            if layer_flags:
                results['summary']['warnings'] = layer_flags[:5]  # Include top 5 warnings
                
            # If ML prediction exists, add to summary
            for layer_result in context.get('layer_results', []):
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction:
                        results['summary']['ml_prediction'] = ml_prediction
                    break
            
        except Exception as e:
            results['final_verdict'] = RiskLevel.ERROR
            results['risk_percentage'] = 50
            results['recommendations'].append(f"Analysis error: {str(e)}")
        
        return results



class LayeredPhishingDetector:
    """
    Main class implementing the layered phishing detection system.
    """
    
    def __init__(self):
        # Initialize layers with error handling
        self.layers = []
        
        try:
            self.layers = [
                Layer1_BasicValidation(),
                Layer2_FeatureAnalysis(),
                Layer3_ContentAnalysis(),
                Layer4_MLClassification(),
                Layer5_EnsembleDecision(),
                Layer6_FinalVerdict()
            ]
            
            # Check which layers are enabled
            enabled_layers = [layer for layer in self.layers if layer.enabled]
            disabled_layers = [layer for layer in self.layers if not layer.enabled]
            
            logger.info(f"Initialized {len(enabled_layers)} detection layers successfully")
            if disabled_layers:
                logger.warning(f"Disabled layers: {[layer.name for layer in disabled_layers]}")
                
        except Exception as e:
            logger.error(f"Error initializing layers: {e}")
            # Create minimal fallback layers
            self.layers = [
                Layer1_BasicValidation(),
                Layer6_FinalVerdict()
            ]
            logger.warning("Using minimal layer configuration due to initialization errors")
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL through all detection layers with improved error handling.
        """
        analysis_results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'layer_results': [],
            'ensemble_result': {},
            'final_result': {},
            'processing_time': 0.0,
            'error': None
        }
        
        start_time = datetime.now()
        
        try:
            # Validate URL first
            if not url or not isinstance(url, str):
                raise ValueError("Invalid URL provided")
            
            # Pass URL through each enabled layer
            context = {}
            
            for i, layer in enumerate(self.layers):
                if not layer.enabled:
                    logger.debug(f"Layer {layer.name} is disabled, skipping")
                    continue
                
                try:
                    logger.debug(f"Processing layer {i+1}: {layer.name}")
                    
                    # Special handling for ensemble and final layers
                    if isinstance(layer, Layer5_EnsembleDecision):
                        context['layer_results'] = analysis_results['layer_results']
                        layer_result = layer.analyze(url, context)
                        analysis_results['ensemble_result'] = layer_result
                    
                    elif isinstance(layer, Layer6_FinalVerdict):
                        context['ensemble_result'] = analysis_results['ensemble_result']
                        context['layer_results'] = analysis_results['layer_results']
                        layer_result = layer.analyze(url, context)
                        analysis_results['final_result'] = layer_result
                    
                    else:
                        layer_result = layer.analyze(url, context)
                        if layer_result:
                            layer_result['weight'] = layer.weight
                            analysis_results['layer_results'].append(layer_result)
                        
                        # Store context for subsequent layers
                        if layer_result:
                            context[layer.name.lower().replace(' ', '_') + '_result'] = layer_result
                    
                    # Early termination for critical issues in Layer 1
                    if (isinstance(layer, Layer1_BasicValidation) and 
                        not layer_result.get('passed', True) and 
                        layer_result.get('risk_score', 0) > 80):
                        
                        logger.warning("Critical issues detected in Layer 1, terminating analysis")
                        analysis_results['final_result'] = {
                            'final_verdict': RiskLevel.CRITICAL,
                            'risk_percentage': layer_result['risk_score'],
                            'confidence': 0.9,
                            'early_termination': True,
                            'recommendations': [
                                "🚨 Critical security threat detected",
                                "🚨 DO NOT proceed with this URL"
                            ]
                        }
                        break
                        
                except Exception as layer_error:
                    logger.error(f"Error in layer {layer.name}: {layer_error}")
                    # Continue with other layers instead of failing completely
                    error_result = {
                        'layer': layer.name,
                        'risk_score': 30,  # Default moderate risk for errors
                        'flags': [f"Layer error: {str(layer_error)}"],
                        'weight': layer.weight,
                        'error': True
                    }
                    analysis_results['layer_results'].append(error_result)
            
            # Ensure we have a final result even if layers failed
            if not analysis_results.get('final_result'):
                # Create fallback final result
                avg_risk = 50  # Default
                if analysis_results['layer_results']:
                    risks = [lr.get('risk_score', 50) for lr in analysis_results['layer_results']]
                    avg_risk = sum(risks) / len(risks)
                
                analysis_results['final_result'] = {
                    'final_verdict': RiskLevel.MEDIUM if avg_risk > 40 else RiskLevel.LOW,
                    'risk_percentage': avg_risk,
                    'confidence': 0.5,
                    'recommendations': ["Analysis completed with limited data"],
                    'fallback_result': True
                }
        
        except Exception as e:
            logger.error(f"Critical error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_result'] = {
                'final_verdict': RiskLevel.ERROR,
                'risk_percentage': 50,
                'confidence': 0.0,
                'recommendations': ["Analysis failed - treat with caution"],
                'error': str(e)
            }
        
        # Calculate processing time
        end_time = datetime.now()
        analysis_results['processing_time'] = (end_time - start_time).total_seconds()
        
        return analysis_results
    
    def get_quick_verdict(self, url: str) -> str:
        """Get a quick verdict for simple use cases."""
        results = self.analyze_url(url)
        final_result = results.get('final_result', {})
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        
        if isinstance(verdict, RiskLevel):
            return verdict.value
        return str(verdict)

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract features from a URL for phishing detection.
    
    Address Bar-based Features:
    - has_ip_address: Boolean indicating if the hostname is an IPv4 address
    - url_length: Classification based on URL length:
        - "Legitimate" if length < 54
        - "Suspicious" if length 54-75 (inclusive)  
        - "Phishing" if length > 75
    - is_shortened: Boolean indicating if the URL uses a known shortening service
    - double_slash_redirect: Boolean indicating if "//" appears after position 7
    - has_dash_in_domain: Boolean indicating if the domain contains a dash "-"
    - subdomain_level: Classification based on subdomain count:
        - "Legitimate" if subdomain count <= 1
        - "Suspicious" if subdomain count == 2
        - "Phishing" if subdomain count > 2
    - https_token_in_domain: Boolean indicating if "https" appears in domain name
    
    Domain-based Features:
    - domain_age: Classification based on domain age via WHOIS:
        - "Legitimate" if age >= 6 months
        - "Phishing" if age < 6 months or unavailable
    - domain_registration_length: Classification based on domain expiry:
        - "Legitimate" if expires > 1 year from now
        - "Phishing" if expires <= 1 year or unavailable
    - dns_record: Boolean indicating if DNS record exists for domain
    - alexa_rank: Classification based on website popularity:
        - "Legitimate" if rank < 100,000
        - "Suspicious" if rank 100,000-999,999
        - "Phishing" if rank > 999,999 or not found
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict[str, Any]: A dictionary containing extracted features
    """
    features = {}
    
    try:
        # Parse the URL to extract components
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        # Remove port number if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Check if hostname is an IPv4 address using regex
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features["has_ip_address"] = bool(re.match(ipv4_pattern, hostname))
        
        # Classify URL based on length
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:  # url_length > 75
            features["url_length"] = "Phishing"
        
        # Check if URL uses a known shortening service
        known_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", 
            "is.gd", "buff.ly", "rebrand.ly", "short.link", "tiny.cc",
            "url.ie", "v.gd", "lnkd.in", "youtu.be", "amzn.to"
        ]
        
        # Extract domain (remove www. prefix if present)
        domain = hostname.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        features["is_shortened"] = domain in known_shorteners
        
        # 1. Check for double slash redirection (// after position 7)
        last_double_slash_pos = url.rfind('//')
        features["double_slash_redirect"] = last_double_slash_pos > 7
        
        # Use tldextract for accurate domain parsing
        extracted = tldextract.extract(url)
        full_domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        
        # 2. Check for dash in domain name (check both domain and subdomain)
        has_dash_domain = '-' in extracted.domain
        has_dash_subdomain = '-' in extracted.subdomain if extracted.subdomain else False
        features["has_dash_in_domain"] = has_dash_domain or has_dash_subdomain
        
        # 3. Subdomain count classification
        # Count dots in subdomain part (tldextract automatically excludes www, domain, and suffix)
        subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
        # Remove empty parts and 'www' if present
        subdomain_parts = [part for part in subdomain_parts if part and part.lower() != 'www']
        subdomain_count = len(subdomain_parts)
        
        if subdomain_count <= 1:
            features["subdomain_level"] = "Legitimate"
        elif subdomain_count == 2:
            features["subdomain_level"] = "Suspicious"
        else:  # subdomain_count > 2
            features["subdomain_level"] = "Phishing"
        
        # 4. Check for "https" token in domain name (check subdomain + domain + suffix)
        # Combine all parts except the protocol
        all_domain_parts = []
        if extracted.subdomain:
            all_domain_parts.append(extracted.subdomain)
        if extracted.domain:
            all_domain_parts.append(extracted.domain)
        if extracted.suffix:
            all_domain_parts.append(extracted.suffix)
        
        complete_domain = '.'.join(all_domain_parts).lower()
        features["https_token_in_domain"] = 'https' in complete_domain
        
        # =================== DOMAIN-BASED FEATURES ===================
        
        # Get the main domain for WHOIS and DNS checks
        main_domain = full_domain if full_domain else f"{extracted.domain}.{extracted.suffix}"
        
        # 5. Domain Age using WHOIS - FIXED Implementation
        try:
            creation_date = None
            
            # Try standard WHOIS library first (it's more reliable than our custom one)
            if STANDARD_WHOIS_AVAILABLE:
                original_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(5)  # 5 second timeout
                
                try:
                    logger.debug(f"Attempting WHOIS lookup for {main_domain}")
                    domain_info = whois.whois(main_domain)
                    
                    # FIXED: Proper handling of creation_date
                    if domain_info and hasattr(domain_info, 'creation_date') and domain_info.creation_date:
                        creation_date = domain_info.creation_date
                        
                        # Handle case where creation_date might be a list
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        
                        logger.info(f"WHOIS successful for {main_domain}: creation_date = {creation_date}")
                    else:
                        logger.debug(f"WHOIS returned no creation_date for {main_domain}")
                        
                except Exception as std_error:
                    logger.debug(f"Standard WHOIS failed for {main_domain}: {std_error}")
                finally:
                    socket.setdefaulttimeout(original_timeout)
            
            # Try improved WHOIS as fallback
            if not creation_date and IMPROVED_WHOIS_AVAILABLE:
                try:
                    whois_client = ImprovedWhois(timeout=3)
                    whois_data = whois_client.whois(main_domain)
                    if whois_data and whois_data.get('creation_date'):
                        creation_date = whois_data.get('creation_date')
                        logger.debug(f"Improved WHOIS successful for {main_domain}")
                except Exception as improved_error:
                    logger.debug(f"Improved WHOIS failed for {main_domain}: {improved_error}")
            
            # Process the creation date if we found one
            if creation_date:
                try:
                    # Ensure creation_date is a datetime object
                    if isinstance(creation_date, str):
                        # Try common date formats
                        try:
                            creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                        except:
                            try:
                                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                            except:
                                logger.warning(f"Could not parse creation date format: {creation_date}")
                                creation_date = None
                    
                    if creation_date and isinstance(creation_date, datetime):
                        # Calculate domain age
                        domain_age_days = (datetime.now() - creation_date).days
                        domain_age_months = domain_age_days / 30.44  # Average days per month
                        
                        logger.info(f"Domain {main_domain} is {domain_age_days} days old ({domain_age_months:.1f} months)")
                        
                        # Set minimum age thresholds
                        min_age_months = 3 if main_domain.endswith('.ac.in') else 6
                        
                        if domain_age_months >= min_age_months:
                            features["domain_age"] = "Legitimate"
                            logger.info(f"Domain {main_domain} is old enough ({domain_age_months:.1f} months) - Legitimate")
                        else:
                            features["domain_age"] = "Phishing"
                            logger.warning(f"Domain {main_domain} is too new ({domain_age_months:.1f} months) - POTENTIAL PHISHING")
                    else:
                        logger.warning(f"Invalid creation date format for {main_domain}")
                        # Don't set domain_age here, let fallback logic handle it
                        
                except Exception as date_error:
                    logger.error(f"Error processing creation date for {main_domain}: {date_error}")
                    # Don't set domain_age here, let fallback logic handle it
            else:
                logger.debug(f"No creation date found for {main_domain}")
                # Don't set domain_age here, let fallback logic handle it
                
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {main_domain}: {e}")
            # Don't set domain_age here, let fallback logic handle it
        
        # Apply fallback logic only if we don't have domain_age set yet
        if 'domain_age' not in features:
            # Use improved fallback with better heuristics
            domain_lower = main_domain.lower()
            
            # Educational domains are usually legitimate
            if domain_lower.endswith('.ac.in') or domain_lower.endswith('.edu') or domain_lower.endswith('.gov'):
                features["domain_age"] = "Legitimate"
                logger.debug(f"Educational/government domain assumed legitimate: {domain_lower}")
            
            # Known major domains that are definitely old
            elif domain_lower in {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'apple.com',
                'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
                'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'paypal.com', 'ebay.com',
                'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com', 'bit.ly',
                'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'v.gd', 'youtu.be',
                'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com', 'instagram.com', 'w3schools.com',
                'mozilla.org', 'wordpress.com', 'blogger.com', 'medium.com', 'discord.com',
                'zoom.us', 'slack.com', 'whatsapp.com', 'telegram.org'
            }:
                features["domain_age"] = "Legitimate"  # Known established domains
                logger.debug(f"Known legitimate domain: {domain_lower}")
            
            # Suspicious TLDs often used for phishing - be more cautious
            elif any(domain_lower.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.pw']):
                features["domain_age"] = "Phishing"  # Suspicious TLDs
                logger.debug(f"Suspicious TLD detected: {domain_lower}")
            
            # For unknown domains where WHOIS fails, be more cautious about marking as phishing
            # Only mark as phishing if there are additional suspicious indicators
            else:
                # Check for suspicious patterns that might indicate a new phishing domain
                suspicious_patterns = [
                    r'\d{4,}',  # Long sequences of numbers
                    r'[a-z]+-[a-z]+-[a-z]+',  # Multiple hyphens
                    r'(secure|login|verify|account|update|confirm)',  # Phishing keywords
                ]
                
                is_suspicious = any(re.search(pattern, domain_lower) for pattern in suspicious_patterns)
                
                if is_suspicious:
                    features["domain_age"] = "Phishing"  # Suspicious patterns + no WHOIS = likely phishing
                    logger.debug(f"Suspicious domain pattern detected: {domain_lower}")
                else:
                    # For normal-looking domains where WHOIS just failed, be more lenient
                    # This prevents false positives on legitimate sites with WHOIS issues
                    features["domain_age"] = "Legitimate"  # Benefit of the doubt for normal domains
                    logger.debug(f"Normal domain pattern, WHOIS failed: {domain_lower}")
                logger.debug(f"WHOIS failed and no alternative verification - marking as suspicious: {domain_lower}")
        
        # 6. Domain Registration Length using WHOIS
        try:
            expiration_date = None
            
            # Try to get expiration date from improved WHOIS if available
            if IMPROVED_WHOIS_AVAILABLE and 'whois_data' in locals() and whois_data:
                expiration_date = whois_data.get('expiration_date')
                if expiration_date:
                    logger.debug(f"Got expiration date from improved WHOIS for {main_domain}")
            
            # Fallback to standard WHOIS expiration date
            if not expiration_date and STANDARD_WHOIS_AVAILABLE and 'domain_info' in locals() and hasattr(domain_info, 'expiration_date') and domain_info.expiration_date:
                expiration_date = domain_info.expiration_date
                
                # Handle case where expiration_date might be a list
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                # Validate expiration_date is a datetime object
                if not isinstance(expiration_date, datetime):
                    try:
                        if isinstance(expiration_date, str):
                            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d %H:%M:%S')
                        else:
                            features["domain_registration_length"] = "Phishing"
                    except:
                        features["domain_registration_length"] = "Phishing"
                
                # Calculate time until expiration
                days_until_expiry = (expiration_date - datetime.now()).days
                
                # Be more lenient for educational institutions
                min_days = 180 if main_domain.endswith('.ac.in') else 365
                
                if days_until_expiry <= min_days:
                    features["domain_registration_length"] = "Phishing"
                else:
                    features["domain_registration_length"] = "Legitimate"
            else:
                # Be lenient when no WHOIS data is available
                if main_domain.endswith('.ac.in') or main_domain.endswith('.edu'):
                    features["domain_registration_length"] = "Legitimate"
                # Known major domains that are definitely established
                elif main_domain.lower() in {
                    'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'apple.com',
                    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
                    'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'paypal.com', 'ebay.com',
                    'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com', 'bit.ly',
                    'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'v.gd', 'youtu.be',
                    'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com', 'instagram.com'
                }:
                    features["domain_registration_length"] = "Legitimate"  # Known established domains
                # For unknown domains, default to legitimate to reduce false positives
                else:
                    features["domain_registration_length"] = "Legitimate"  # Default to legitimate when unsure
                
        except Exception as e:
            # Be lenient with WHOIS failures - use intelligent defaults for domain registration length too
            # Educational domains are usually legitimate
            if main_domain.endswith('.ac.in') or main_domain.endswith('.edu'):
                features["domain_registration_length"] = "Legitimate"
            # Known major domains that are definitely established
            elif main_domain.lower() in {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'apple.com',
                'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
                'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'paypal.com', 'ebay.com',
                'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com', 'bit.ly',
                'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'v.gd', 'youtu.be',
                'bbc.com', 'cnn.com', 'nytimes.com', 'reuters.com', 'instagram.com'
            }:
                features["domain_registration_length"] = "Legitimate"  # Known established domains
            # For unknown domains, default to legitimate to reduce false positives
            else:
                features["domain_registration_length"] = "Legitimate"  # Default to legitimate when unsure
        
        # 7. DNS Record Exists
        try:
            socket.gethostbyname(main_domain)
            features["dns_record"] = True
        except socket.gaierror:
            features["dns_record"] = False
        except Exception as e:
            features["dns_record"] = False
        
        # 8. Alexa Rank (using dummy implementation for now)
        # In a real implementation, you would use an API like Alexa or similar ranking service
        try:
            # For demonstration, we'll use domain length as a proxy
            # In reality, you'd call an API like: alexa_rank = get_alexa_rank(main_domain)
            domain_length = len(main_domain)
            
            # Dummy logic: shorter domains tend to be more popular
            if domain_length <= 10:
                dummy_rank = 50000  # High ranking (legitimate)
            elif domain_length <= 15:
                dummy_rank = 150000  # Medium ranking
            else:
                dummy_rank = 999999  # Low ranking
            
            if dummy_rank < 100000:
                features["alexa_rank"] = "Legitimate"
            elif dummy_rank <= 999999:
                features["alexa_rank"] = "Suspicious"
            else:
                features["alexa_rank"] = "Phishing"
                
        except Exception as e:
            features["alexa_rank"] = "Phishing"  # No rank found
        
    except Exception as e:
        # If URL parsing fails, set default values for all features
        features["has_ip_address"] = False
        features["is_shortened"] = False
        features["double_slash_redirect"] = False
        features["has_dash_in_domain"] = False
        features["subdomain_level"] = "Legitimate"
        features["https_token_in_domain"] = False
        
        # Domain-based features defaults
        features["domain_age"] = "Phishing"
        features["domain_registration_length"] = "Phishing"
        features["dns_record"] = False
        features["alexa_rank"] = "Phishing"
        
        # Still classify URL length even if parsing fails
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:
            features["url_length"] = "Phishing"
    
    # TODO: Implement additional feature extraction logic
    # Features might include:
    # - URL length
    # - Number of dots, slashes, special characters
    # - Presence of suspicious keywords
    # - Domain-based features
    # - HTTPS usage
    # - etc.
    
    return features


def check_url(url: str) -> str:
    """
    Simple function to quickly check if a URL is suspicious.
    
    Args:
        url (str): URL to check
        
    Returns:
        str: Simple assessment ("SAFE", "SUSPICIOUS", "DANGEROUS")
    """
    try:
        features = extract_features(url)
        
        # Count high-risk indicators
        danger_count = 0
        if features['has_ip_address']:
            danger_count += 1
        if features['url_length'] == 'Phishing':
            danger_count += 1
        if features['double_slash_redirect']:
            danger_count += 1
        if features['https_token_in_domain']:
            danger_count += 1
        if features['domain_age'] == 'Phishing':
            danger_count += 1
        if not features['dns_record']:
            danger_count += 1
            
        # Count medium-risk indicators
        suspect_count = 0
        if features['is_shortened']:
            suspect_count += 1
        if features['has_dash_in_domain']:
            suspect_count += 1
        if features['subdomain_level'] in ['Suspicious', 'Phishing']:
            suspect_count += 1
        if features['url_length'] == 'Suspicious':
            suspect_count += 1
            
        # Make assessment
        if danger_count >= 2:
            return "DANGEROUS"
        elif danger_count >= 1 or suspect_count >= 3:
            return "SUSPICIOUS"
        elif suspect_count >= 1:
            return "CAUTION"
        else:
            return "SAFE"
            
    except Exception:
        return "ERROR"


def load_model() -> Tuple[Any, Any]:
    """
    Load a pre-trained machine learning model and vectorizer for phishing detection.
    
    Returns:
        Tuple[Any, Any]: The loaded ML model and vectorizer, or (None, None) if loading fails
    """
    try:
        # Try multiple possible locations for the models
        possible_model_dirs = [
            os.path.join(os.path.dirname(__file__), 'models'),  # Same directory as the script
            'models',  # Top-level models directory
            os.path.join(os.path.abspath(os.path.dirname(__file__)), 'models')  # Absolute path
        ]
        
        # Try each possible location
        for models_dir in possible_model_dirs:
            model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
            vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
        
            if os.path.exists(model_path):
                try:
                    logger.info(f"Attempting to load model from {model_path}")
                    
                    # Load model with error handling
                    model = joblib.load(model_path)
                    
                    # Validate model has required methods
                    if not hasattr(model, 'predict'):
                        logger.error("Loaded model doesn't have predict method")
                        continue
                    
                    # Test model prediction capability
                    try:
                        # Create a dummy test to check if model works
                        test_data = [[0] * 10]  # Dummy feature vector
                        _ = model.predict(test_data)
                        logger.info("Model prediction test passed")
                    except Exception as test_error:
                        logger.warning(f"Model prediction test failed: {test_error}")
                        # Continue loading but mark as potentially problematic
                    
                    # Check if vectorizer exists, if not we'll create a dummy one
                    if os.path.exists(vectorizer_path):
                        try:
                            vectorizer = joblib.load(vectorizer_path)
                            logger.info("Vectorizer loaded successfully")
                        except Exception as e:
                            logger.warning(f"Error loading vectorizer: {e}, creating dummy vectorizer")
                            # Create dummy vectorizer
                            from sklearn.feature_extraction.text import TfidfVectorizer
                            vectorizer = TfidfVectorizer(
                                analyzer='char_wb',
                                ngram_range=(3, 5),
                                max_features=10000
                            )
                            logger.warning("Using dummy vectorizer - ML predictions may be unreliable")
                    else:
                        # Create dummy vectorizer if file doesn't exist
                        from sklearn.feature_extraction.text import TfidfVectorizer
                        vectorizer = TfidfVectorizer(
                            analyzer='char_wb',
                            ngram_range=(3, 5),
                            max_features=10000
                        )
                        logger.warning("Vectorizer file not found, created dummy vectorizer")
                    
                    # Check if model has the problematic attributes
                    if hasattr(model, 'estimators_'):
                        logger.info("Model has estimators_ attribute - should work correctly")
                    else:
                        logger.warning("Model missing estimators_ attribute - may indicate compatibility issues")
                    
                    # Check scikit-learn version compatibility
                    try:
                        import sklearn
                        logger.info(f"Scikit-learn version: {sklearn.__version__}")
                    except:
                        pass
                    
                    logger.info(f"Successfully loaded ML model and vectorizer from {models_dir}")
                    
                    # Load evaluation results if available
                    results_path = os.path.join(models_dir, 'evaluation_results.json')
                    if os.path.exists(results_path):
                        try:
                            with open(results_path, 'r') as f:
                                results = json.load(f)
                            logger.info(f"Model accuracy: {results.get('accuracy', 'unknown')}")
                            if results.get('compatible', False):
                                logger.info("Model marked as compatible")
                            else:
                                logger.warning("Model compatibility not verified")
                        except Exception as json_error:
                            logger.warning(f"Could not load evaluation results: {json_error}")
                    
                    return model, vectorizer
                    
                except Exception as e:
                    logger.error(f"Error loading model from {model_path}: {e}")
                    logger.error(f"This may be due to scikit-learn version incompatibility")
                    logger.info("Consider running fix_model_error.py to retrain with compatible format")
                    continue
        
        # If we get here, we couldn't find the model in any location
        logger.warning(f"ML model files not found in any of these locations: {possible_model_dirs}")
        logger.info("To fix this:")
        logger.info("1. Run 'python fix_model_error.py' to retrain the model")
        logger.info("2. Or run 'python training/train_url_model.py' to train from scratch")
        logger.info("3. Make sure the dataset file exists in the project directory")
        
    except Exception as e:
        logger.error(f"Could not load model: {e}")
        logger.info("Suggestion: Run 'python fix_model_error.py' to create a compatible model")
    
    return None, None


def predict_with_ml(url: str, model: Any, vectorizer: Any) -> Dict[str, Any]:
    """
    Use the trained ML model to predict if a URL is phishing.
    
    Args:
        url (str): URL to analyze
        model: Trained ML model
        vectorizer: Fitted TF-IDF vectorizer
        
    Returns:
        Dict[str, Any]: Prediction results with confidence scores
    """
    try:
        # Check if model is our fallback model or has issues
        is_fallback = hasattr(model, 'model_type') and model.model_type == "RandomForest_Fallback"
        
        # Try regular ML prediction first
        try:
            # Regular approach: Transform URL using the vectorizer
            url_vec = vectorizer.transform([url])
            
            # Get prediction and confidence with error handling
            prediction = model.predict(url_vec)[0]
            
            # Try to get probability scores with fallback
            try:
                confidence_scores = model.predict_proba(url_vec)[0]
            except AttributeError as e:
                logger.warning(f"Model predict_proba failed: {e}, using fallback confidence")
                # Create fallback confidence scores
                prediction_value = float(prediction)
                if prediction_value == 1:  # phishing
                    confidence_scores = [0.2, 0.8]  # low legit, high phish
                else:  # legitimate
                    confidence_scores = [0.8, 0.2]  # high legit, low phish
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'confidence': float(max(confidence_scores)),
                'confidence_scores': {
                    'legitimate': float(confidence_scores[0]),
                    'phishing': float(confidence_scores[1])
                },
                'method': 'machine_learning'
            }
            
        except (AttributeError, ValueError, TypeError) as ml_error:
            logger.warning(f"ML prediction failed ({ml_error}), using feature-based fallback")
            # Fall back to feature-based prediction
            pass
        
        # Fallback approach: Use feature extraction
        logger.info("Using feature-based fallback prediction")
        try:
            # Extract features for fallback model
            features = extract_features(url)
            # Convert to vector
            feature_vector = features_to_vector(features)
            
            # Check if this looks like a legitimate site first
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Legitimate domain patterns
            legitimate_domains = {
                'google.com', 'youtube.com', 'gmail.com', 'microsoft.com', 
                'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
                'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
                'wikipedia.org', 'bbc.com', 'cnn.com', 'netflix.com', 'spotify.com'
            }
            
            # Check for exact match or subdomain of legitimate sites
            is_likely_legitimate = any(
                domain == legit_domain or domain.endswith('.' + legit_domain)
                for legit_domain in legitimate_domains
            )
            
            if is_likely_legitimate:
                return {
                    'prediction': 'legitimate',
                    'confidence': 0.85,
                    'confidence_scores': {
                        'legitimate': 0.85,
                        'phishing': 0.15
                    },
                    'method': 'whitelist_fallback',
                    'reason': 'Recognized legitimate domain'
                }
            
            # Rule-based prediction using feature scores with more conservative thresholds
            feature_score = sum(feature_vector)
            max_score = len(feature_vector) * 2  # Theoretical maximum
            
            # Normalize score and determine prediction
            normalized_score = min(1.0, feature_score / max_score)
            
            # Be much more conservative - only flag as phishing if very suspicious
            if normalized_score > 0.8:  # Increased threshold
                prediction = 1  # phishing
                phish_confidence = min(0.9, 0.7 + (normalized_score * 0.2))
            elif normalized_score > 0.65:  # Increased threshold
                prediction = 1  # suspicious, classify as phishing
                phish_confidence = 0.65
            else:
                prediction = 0  # legitimate
                phish_confidence = max(0.1, normalized_score * 0.4)  # Lower base risk
            
            legit_confidence = 1 - phish_confidence
            confidence_scores = [legit_confidence, phish_confidence]
            
            return {
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'confidence': float(max(confidence_scores)),
                'confidence_scores': {
                    'legitimate': float(confidence_scores[0]),
                    'phishing': float(confidence_scores[1])
                },
                'method': 'feature_based_conservative',
                'feature_score': feature_score,
                'normalized_score': normalized_score
            }
            
        except Exception as fe:
            logger.error(f"Feature-based fallback failed: {fe}")
            # Final fallback to rule-based classification
            pass
        # Final rule-based fallback
        try:
            features = extract_features(url)
            result = rule_based_classification(features)
            return {
                'prediction': result['prediction'],
                'confidence': float(result['confidence']),
                'confidence_scores': {
                    'legitimate': float(1 - result['confidence']) if result['prediction'] == 'phishing' else float(result['confidence']),
                    'phishing': float(result['confidence']) if result['prediction'] == 'phishing' else float(1 - result['confidence'])
                },
                'method': 'rule_based_fallback'
            }
        except Exception as re:
            logger.error(f"Rule-based fallback also failed: {re}")
            # Return safe default prediction
            return {
                'prediction': 'legitimate',
                'confidence': 0.5,
                'confidence_scores': {
                    'legitimate': 0.5,
                    'phishing': 0.5
                },
                'method': 'default_safe'
            }
            
    except Exception as e:
        logger.error(f"Complete ML prediction failure: {e}")
        # Return safe default
        return {
            'prediction': 'legitimate',
            'confidence': 0.5,
            'confidence_scores': {
                'legitimate': 0.5,
                'phishing': 0.5
            },
            'method': 'error_default'
        }


def features_to_vector(features: Dict[str, Any]) -> list:
    """Convert feature dictionary to numerical vector for ML models."""
    vector = []
    
    # Boolean features (0 or 1)
    vector.append(1 if features['has_ip_address'] else 0)
    vector.append(1 if features['is_shortened'] else 0)
    vector.append(1 if features['double_slash_redirect'] else 0)
    vector.append(1 if features['has_dash_in_domain'] else 0)
    vector.append(1 if features['https_token_in_domain'] else 0)
    vector.append(1 if features['dns_record'] else 0)
    
    # Categorical features (convert to numerical)
    url_length_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(url_length_map.get(features['url_length'], 2))
    
    subdomain_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(subdomain_map.get(features['subdomain_level'], 2))
    
    domain_age_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(domain_age_map.get(features['domain_age'], 1))
    
    reg_length_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(reg_length_map.get(features['domain_registration_length'], 1))
    
    alexa_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(alexa_map.get(features['alexa_rank'], 2))
    
    return vector


def rule_based_classification(features: Dict[str, Any]) -> Dict[str, Any]:
    """Improved rule-based classification with better legitimate site handling."""
    phishing_score = 0
    total_checks = 0
    
    # High risk indicators (only very suspicious features)
    total_checks += 6
    if features['has_ip_address']:
        phishing_score += 3  # Strong indicator
    if features['url_length'] == 'Phishing':
        phishing_score += 2
    if features['double_slash_redirect']:
        phishing_score += 2
    if features['https_token_in_domain']:
        phishing_score += 3  # Very suspicious
    if features['domain_age'] == 'Phishing':
        phishing_score += 1  # Reduced - new domains can be legitimate
    if not features['dns_record']:
        phishing_score += 3  # Strong indicator
    
    # Medium risk indicators (be more lenient)
    total_checks += 4
    if features['is_shortened']:
        phishing_score += 1  # Reduced - many legitimate services use shorteners
    if features['has_dash_in_domain']:
        phishing_score += 0.5  # Reduced - common in legitimate domains
    if features['subdomain_level'] == 'Phishing':
        phishing_score += 1.5
    elif features['subdomain_level'] == 'Suspicious':
        phishing_score += 0.5
    
    # Additional legitimate indicators (reduce score)
    if features['url_length'] == 'Legitimate':
        phishing_score -= 0.5
    if features['domain_age'] == 'Legitimate':
        phishing_score -= 1
    if features['alexa_rank'] == 'Legitimate':
        phishing_score -= 2
    
    # Ensure score is not negative
    phishing_score = max(0, phishing_score)
    
    # More conservative classification thresholds
    if phishing_score >= 6:  # Increased threshold - need very strong indicators
        prediction = 'phishing'
        confidence = min(0.9, 0.6 + (phishing_score / 15))
    elif phishing_score >= 4:  # Increased threshold
        prediction = 'phishing'
        confidence = min(0.8, 0.5 + (phishing_score / 20))
    elif phishing_score >= 2.5:  # New threshold for suspicious
        prediction = 'legitimate'  # Changed to legitimate but with lower confidence
        confidence = max(0.3, 0.7 - (phishing_score / 10))
    else:
        prediction = 'legitimate'
        confidence = min(0.9, 0.8 + (2 - phishing_score) / 10)
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'phishing_score': phishing_score,
        'method': 'rule_based_conservative'
    }


def classify_url(features: Dict[str, Any] = None, url: str = None, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Classify a URL as phishing or legitimate using both ML and rule-based methods.
    
    Args:
        features (Dict[str, Any]): Dictionary of extracted features (optional)
        url (str): URL to classify (required for ML method)
        model: Pre-trained ML model (optional)
        vectorizer: Fitted vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Classification result including prediction and confidence
    """
    try:
        # Try ML prediction first if model and URL are available
        if model is not None and vectorizer is not None and url is not None:
            ml_result = predict_with_ml(url, model, vectorizer)
            if ml_result is not None:
                # Also get rule-based prediction for comparison
                if features is None:
                    features = extract_features(url)
                rule_result = rule_based_classification(features)
                
                # Combine results
                ml_result['rule_based_prediction'] = rule_result['prediction']
                ml_result['rule_based_score'] = rule_result['phishing_score']
                ml_result['features'] = features
                
                return ml_result
        
        # Fall back to rule-based classification
        if features is None and url is not None:
            features = extract_features(url)
        elif features is None:
            raise ValueError("Either features or url must be provided")
            
        return rule_based_classification(features)
        
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        # Return safe default
        return {
            'prediction': 'error',
            'confidence': 0.0,
            'method': 'error',
            'error': str(e)
        }


def check_url_enhanced(url: str, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Enhanced URL checking with detailed analysis.
    
    Args:
        url (str): URL to check
        model: ML model (optional)
        vectorizer: Vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Detailed analysis results
    """
    try:
        # Extract features
        features = extract_features(url)
        
        # Get classification
        classification = classify_url(features=features, url=url, model=model, vectorizer=vectorizer)
        
        # Calculate risk assessment
        risk_level = "LOW"
        if classification['prediction'] == 'phishing':
            if classification['confidence'] > 0.8:
                risk_level = "HIGH"
            elif classification['confidence'] > 0.6:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW-MEDIUM"
        
        return {
            'url': url,
            'risk_level': risk_level,
            'classification': classification,
            'features': features,
            'recommendations': get_recommendations(features, classification)
        }
        
    except Exception as e:
        logger.error(f"Enhanced URL check failed: {e}")
        return {
            'url': url,
            'risk_level': "ERROR",
            'error': str(e)
        }


def get_recommendations(features: Dict[str, Any], classification: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    if classification['prediction'] == 'phishing':
        recommendations.append("⚠️  DO NOT enter personal information on this site")
        recommendations.append("⚠️  DO NOT download files from this site")
        
    if features.get('has_ip_address'):
        recommendations.append("🔍 URL uses IP address instead of domain name")
    
    if features.get('is_shortened'):
        recommendations.append("🔍 Shortened URL - check the actual destination")
    
    if features.get('https_token_in_domain'):
        recommendations.append("🔍 Domain contains 'https' - potential impersonation")
    
    if not features.get('dns_record'):
        recommendations.append("🔍 Domain has no DNS record - highly suspicious")
    
    if classification['prediction'] == 'legitimate':
        recommendations.append("✅ URL appears to be legitimate")
        recommendations.append("💡 Still verify the site's authenticity through official channels")
    
    return recommendations


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