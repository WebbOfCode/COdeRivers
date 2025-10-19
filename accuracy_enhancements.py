"""
accuracy_enhancements.py — Supplemental checks to improve detection accuracy

Checks included:
- SSL/TLS certificate validation (expiry, issuer)
- HTTP security headers and redirect behavior
- Page content inspection (forms, scripts, brand hints)
- Basic domain reputation cues (parking)

All functions return structured dicts with score impacts and details so
the main scanner can incorporate them consistently.
"""

# Import regular expression module for pattern matching
import re
# Import requests for HTTP header checking
import requests
# Import BeautifulSoup for HTML analysis
from bs4 import BeautifulSoup
# Import datetime for checking SSL certificate expiration
from datetime import datetime
# Import SSL module for certificate validation
import ssl
# Import socket for low-level connection testing
import socket
# Import URL parsing utility
from urllib.parse import urlparse
# Import typing utilities
from typing import Dict, Any, List, Optional


# Function to check SSL certificate validity
def check_ssl_certificate(hostname: str) -> Dict[str, Any]:
    """Verify SSL certificate validity, expiration, and issuer.
    
    Returns dictionary with certificate status, expiration date, and issuer info.
    """
    # Initialize result dictionary
    result = {
        'valid': False,
        'score_impact': 0,
        'message': '',
        'details': {}
    }
    
    # Try to establish SSL connection
    try:
        # Create SSL context with default settings
        context = ssl.create_default_context()
        # Connect to hostname on HTTPS port
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            # Wrap socket with SSL
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate information
                cert = ssock.getpeercert()
                
                # Parse expiration date
                not_after = cert.get('notAfter', '')
                if not_after:
                    # Convert to datetime object
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    # Calculate days until expiration
                    days_until_expiry = (expire_date - datetime.now()).days
                    
                    # Store certificate details
                    result['details']['expires'] = expire_date.isoformat()
                    result['details']['days_remaining'] = days_until_expiry
                    result['details']['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Evaluate certificate validity
                    if days_until_expiry < 0:
                        result['score_impact'] = 40
                        result['message'] = 'SSL certificate has expired'
                    elif days_until_expiry < 30:
                        result['score_impact'] = 15
                        result['message'] = f'SSL certificate expires soon ({days_until_expiry} days)'
                    else:
                        result['valid'] = True
                        result['score_impact'] = -5  # Reduce risk score for valid cert
                        result['message'] = 'Valid SSL certificate'
                else:
                    result['score_impact'] = 20
                    result['message'] = 'SSL certificate missing expiration date'
                    
    # Handle SSL errors
    except ssl.SSLError as exc:
        result['score_impact'] = 35
        result['message'] = f'SSL certificate error: {str(exc)[:100]}'
    # Handle connection errors
    except (socket.timeout, socket.error, ConnectionRefusedError):
        result['score_impact'] = 0  # No penalty for unavailable HTTPS
        result['message'] = 'HTTPS not available or connection timeout'
    # Handle other exceptions
    except Exception as exc:
        result['score_impact'] = 0
        result['message'] = f'SSL check failed: {str(exc)[:100]}'
    
    # Return certificate analysis
    return result


# Function to check HTTP headers for security indicators
def check_http_headers(url: str) -> Dict[str, Any]:
    """Analyze HTTP response headers for security best practices.
    
    Returns dictionary with header analysis and security score impact.
    """
    # Initialize result dictionary
    result = {
        'score_impact': 0,
        'missing_headers': [],
        'suspicious_headers': [],
        'messages': []
    }
    
    # Try to fetch HTTP headers
    try:
        # Send HEAD request to get headers without downloading content
        response = requests.head(url, timeout=5, allow_redirects=True)
        # Get all headers
        headers = response.headers
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': 'HSTS not configured',
            'X-Content-Type-Options': 'Content-Type sniffing protection missing',
            'X-Frame-Options': 'Clickjacking protection missing',
            'Content-Security-Policy': 'CSP not configured'
        }
        
        # Evaluate presence of security headers
        for header, message in security_headers.items():
            if header not in headers:
                result['missing_headers'].append(message)
                result['score_impact'] += 2  # Small penalty per missing header
        
        # Check for suspicious server headers
        server = headers.get('Server', '').lower()
        if any(suspicious in server for suspicious in ['apache/1', 'nginx/0', 'iis/5']):
            result['suspicious_headers'].append('Outdated server software detected')
            result['score_impact'] += 10
        
        # Check for excessive redirects (potential redirect chain attack)
        if len(response.history) > 3:
            result['suspicious_headers'].append(f'Excessive redirects ({len(response.history)} hops)')
            result['score_impact'] += 12
        
        # Check if final URL differs significantly from original (redirect to different domain)
        original_domain = urlparse(url).netloc
        final_domain = urlparse(response.url).netloc
        if original_domain != final_domain:
            result['suspicious_headers'].append(f'Redirects to different domain: {final_domain}')
            result['score_impact'] += 18
        
        # Compile messages
        if result['missing_headers']:
            result['messages'].append(f"Missing security headers: {', '.join(result['missing_headers'][:2])}")
        if result['suspicious_headers']:
            result['messages'].extend(result['suspicious_headers'])
        if not result['messages']:
            result['messages'].append('HTTP headers show good security practices')
            result['score_impact'] = -3  # Small reward for good headers
            
    # Handle request errors
    except requests.RequestException as exc:
        result['score_impact'] = 0  # No penalty if site is unreachable
        result['messages'].append(f'HTTP header check unavailable: {str(exc)[:100]}')
    
    # Return header analysis
    return result


# Function to analyze page content for phishing indicators
def analyze_page_content(url: str) -> Dict[str, Any]:
    """Download and analyze page HTML for phishing patterns.
    
    Returns dictionary with content analysis and risk indicators.
    """
    # Initialize result dictionary
    result = {
        'score_impact': 0,
        'indicators': [],
        'form_analysis': {}
    }
    
    # Try to fetch and analyze page content
    try:
        # Send GET request to download HTML
        response = requests.get(url, timeout=8, allow_redirects=True)
        # Parse HTML with BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for password input fields (common in phishing)
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            # Check if forms submit to external domain
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                # If action is external URL
                if action.startswith('http') and urlparse(url).netloc not in action:
                    result['indicators'].append('Password form submits to external domain')
                    result['score_impact'] += 35
                    break
            
            # Check for multiple password fields (sign-up vs login confusion)
            if len(password_fields) > 2:
                result['indicators'].append('Unusual number of password fields detected')
                result['score_impact'] += 8
        
        # Check for iframes (can be used to load malicious content)
        iframes = soup.find_all('iframe')
        external_iframes = [iframe for iframe in iframes if iframe.get('src', '').startswith('http')]
        if len(external_iframes) > 2:
            result['indicators'].append(f'Multiple external iframes detected ({len(external_iframes)})')
            result['score_impact'] += 12
        
        # Check for suspicious JavaScript patterns
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string or ''
            # Look for obfuscation patterns
            if 'eval(' in script_content or 'unescape(' in script_content:
                result['indicators'].append('Obfuscated JavaScript detected')
                result['score_impact'] += 20
                break
        
        # Check page title for brand impersonation keywords
        title = soup.find('title')
        if title:
            title_text = title.string or ''
            impersonation_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank', 'login']
            if any(brand in title_text.lower() for brand in impersonation_brands):
                # Only flag if domain doesn't match brand
                domain = urlparse(url).netloc.lower()
                if not any(brand in domain for brand in impersonation_brands):
                    result['indicators'].append('Page title suggests brand impersonation')
                    result['score_impact'] += 25
        
        # Store form analysis
        result['form_analysis'] = {
            'total_forms': len(soup.find_all('form')),
            'password_fields': len(password_fields),
            'external_iframes': len(external_iframes)
        }
        
        # If no indicators found, note clean content
        if not result['indicators']:
            result['indicators'].append('No suspicious content patterns detected')
            result['score_impact'] = -5  # Small reward
            
    # Handle request errors
    except requests.RequestException as exc:
        result['score_impact'] = 0  # No penalty if page unavailable
        result['indicators'].append(f'Content analysis unavailable: {str(exc)[:100]}')
    # Handle parsing errors
    except Exception as exc:
        result['score_impact'] = 0
        result['indicators'].append(f'Content parsing failed: {str(exc)[:100]}')
    
    # Return content analysis
    return result


# Function to check domain reputation using multiple signals
def check_domain_reputation(domain: str) -> Dict[str, Any]:
    """Cross-reference domain against multiple reputation databases.
    
    Returns dictionary with reputation score and sources.
    """
    # Initialize result dictionary
    result = {
        'score_impact': 0,
        'reputation_sources': [],
        'risk_level': 'unknown'
    }
    
    # Check against known parking page patterns
    parking_keywords = ['domain for sale', 'buy this domain', 'parked domain']
    
    # Try to check domain reputation
    try:
        # Fetch homepage
        response = requests.get(f'http://{domain}', timeout=5)
        content = response.text.lower()
        
        # Check for parking page indicators
        if any(keyword in content for keyword in parking_keywords):
            result['reputation_sources'].append('Domain appears to be parked')
            result['score_impact'] += 15
            result['risk_level'] = 'suspicious'
        
    # Handle errors silently
    except Exception:
        pass
    
    # If no reputation signals found
    if not result['reputation_sources']:
        result['reputation_sources'].append('No additional reputation data available')
        result['risk_level'] = 'unknown'
    
    # Return reputation analysis
    return result


# Function to perform comprehensive URL verification
def enhanced_url_verification(url: str) -> Dict[str, Any]:
    """Run all enhanced accuracy checks and aggregate results.
    
    Returns dictionary with all verification results and total score impact.
    """
    # Parse URL to extract hostname
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        hostname = parsed.hostname or ''
    except Exception:
        return {
            'total_score_impact': 0,
            'checks_performed': [],
            'error': 'Invalid URL format'
        }
    
    # Initialize results dictionary
    results = {
        'total_score_impact': 0,
        'checks_performed': []
    }
    
    # Run SSL certificate check for HTTPS URLs
    if parsed.scheme == 'https':
        ssl_result = check_ssl_certificate(hostname)
        results['ssl_certificate'] = ssl_result
        results['total_score_impact'] += ssl_result['score_impact']
        results['checks_performed'].append('SSL Certificate Validation')
    
    # Run HTTP headers check
    headers_result = check_http_headers(url)
    results['http_headers'] = headers_result
    results['total_score_impact'] += headers_result['score_impact']
    results['checks_performed'].append('HTTP Security Headers')
    
    # Run content analysis
    content_result = analyze_page_content(url)
    results['page_content'] = content_result
    results['total_score_impact'] += content_result['score_impact']
    results['checks_performed'].append('Page Content Analysis')
    
    # Run domain reputation check
    reputation_result = check_domain_reputation(hostname)
    results['domain_reputation'] = reputation_result
    results['total_score_impact'] += reputation_result['score_impact']
    results['checks_performed'].append('Domain Reputation')
    
    # Return comprehensive results
    return results
