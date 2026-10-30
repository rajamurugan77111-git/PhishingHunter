"""Layer 2: domain / WHOIS / SSL / lexical feature analysis."""
from .common import Any, DetectionLayer, Dict
from .url_heuristics import extract_features


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
