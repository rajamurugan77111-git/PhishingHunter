"""Layer 3: page content and behaviour analysis."""
from .common import Any, DetectionLayer, Dict, List, Optional, Tuple, datetime, logger, re, socket, urllib


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
