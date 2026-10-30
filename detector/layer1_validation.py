"""Layer 1: basic URL validation and trusted-domain allowlist."""
from .common import Any, DetectionLayer, Dict, re, urllib


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
