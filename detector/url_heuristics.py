"""Hand-crafted URL features, rule-based fallback classifier and recommendations."""
from .common import Any, Dict, IMPROVED_WHOIS_AVAILABLE, ImprovedWhois, List, STANDARD_WHOIS_AVAILABLE, datetime, logger, re, socket, tldextract, urllib, whois


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
