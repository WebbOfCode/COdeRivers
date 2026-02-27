"""
accuracy_enhancements.py — Extra Checks for Better Detection

The main scanner does a lot, but these extra checks help catch
things that slip through the cracks:

- SSL/TLS certificate validation (is the cert valid? expired?)
- HTTP security headers (does the site follow best practices?)
- Page content analysis (forms, scripts, iframes)
- Domain reputation (is this a parked domain?)

These are the "trust but verify" checks. They give us more
confidence in our verdict.
"""

import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional


def check_ssl_certificate(hostname: str) -> Dict[str, Any]:
    """
    Validate SSL certificate for HTTPS sites.
    
    We check:
    - Is the certificate valid?
    - Has it expired?
    - Who issued it?
    - How soon does it expire?
    
    Expired or invalid certs are red flags. Legit sites keep
their certs current.
    
    Returns dict with validity status and score impact.
    """
    result = {
        'valid': False,
        'score_impact': 0,
        'message': '',
        'details': {}
    }
    
    try:
        # Create SSL context with default settings
        context = ssl.create_default_context()
        
        # Connect to the server on HTTPS port
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate info
                cert = ssock.getpeercert()
                
                # Parse expiration date
                not_after = cert.get('notAfter', '')
                if not_after:
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expire_date - datetime.now()).days
                    
                    result['details']['expires'] = expire_date.isoformat()
                    result['details']['days_remaining'] = days_until_expiry
                    result['details']['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    
                    # Evaluate certificate
                    if days_until_expiry < 0:
                        # Certificate is expired - big red flag
                        result['score_impact'] = 40
                        result['message'] = 'SSL certificate has expired'
                    elif days_until_expiry < 30:
                        # Expiring soon - maintenance issue, slightly suspicious
                        result['score_impact'] = 15
                        result['message'] = f'SSL certificate expires soon ({days_until_expiry} days)'
                    else:
                        # All good! Valid cert with time remaining
                        result['valid'] = True
                        result['score_impact'] = -5  # Reduce risk score for good cert
                        result['message'] = 'Valid SSL certificate'
                else:
                    # No expiration date? That's weird.
                    result['score_impact'] = 20
                    result['message'] = 'SSL certificate missing expiration date'
                    
    except ssl.SSLError as exc:
        # SSL error (invalid cert, wrong hostname, etc)
        result['score_impact'] = 35
        result['message'] = f'SSL certificate error: {str(exc)[:100]}'
    except (socket.timeout, socket.error, ConnectionRefusedError):
        # Can't connect via HTTPS - might not support it
        result['score_impact'] = 0
        result['message'] = 'HTTPS not available or connection timeout'
    except Exception as exc:
        # Something else went wrong
        result['score_impact'] = 0
        result['message'] = f'SSL check failed: {str(exc)[:100]}'
    
    return result


def check_http_headers(url: str) -> Dict[str, Any]:
    """
    Analyze HTTP security headers.
    
    Security headers tell browsers how to handle a site:
    - HSTS: Force HTTPS
    - X-Frame-Options: Prevent clickjacking
    - CSP: Control what resources can load
    
    Missing headers don't mean a site is malicious, but having
them shows the site owner cares about security.
    
    Returns dict with header analysis and score impact.
    """
    result = {
        'score_impact': 0,
        'missing_headers': [],
        'suspicious_headers': [],
        'messages': []
    }
    
    try:
        # Send HEAD request (just get headers, not the whole page)
        response = requests.head(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
        # Security headers that should be present
        security_headers = {
            'Strict-Transport-Security': 'HSTS not configured',
            'X-Content-Type-Options': 'Content-Type sniffing protection missing',
            'X-Frame-Options': 'Clickjacking protection missing',
            'Content-Security-Policy': 'CSP not configured'
        }
        
        # Check for missing headers
        for header, message in security_headers.items():
            if header not in headers:
                result['missing_headers'].append(message)
                result['score_impact'] += 2  # Small penalty per header
        
        # Check for outdated server software
        server = headers.get('Server', '').lower()
        if any(suspicious in server for suspicious in ['apache/1', 'nginx/0', 'iis/5']):
            result['suspicious_headers'].append('Outdated server software detected')
            result['score_impact'] += 10
        
        # Check for excessive redirects (might be redirect chain attack)
        if len(response.history) > 3:
            result['suspicious_headers'].append(f'Excessive redirects ({len(response.history)} hops)')
            result['score_impact'] += 12
        
        # Check if we ended up on a different domain than we started
        original_domain = urlparse(url).netloc
        final_domain = urlparse(response.url).netloc
        if original_domain != final_domain:
            result['suspicious_headers'].append(f'Redirects to different domain: {final_domain}')
            result['score_impact'] += 18
        
        # Build human-readable messages
        if result['missing_headers']:
            result['messages'].append(f"Missing security headers: {', '.join(result['missing_headers'][:2])}")
        if result['suspicious_headers']:
            result['messages'].extend(result['suspicious_headers'])
        if not result['messages']:
            result['messages'].append('HTTP headers show good security practices')
            result['score_impact'] = -3  # Small reward for good headers
            
    except requests.RequestException as exc:
        # Site unreachable - no penalty
        result['score_impact'] = 0
        result['messages'].append(f'HTTP header check unavailable: {str(exc)[:100]}')
    
    return result


def analyze_page_content(url: str) -> Dict[str, Any]:
    """
    Analyze page HTML for phishing patterns.
    
    We download the actual page content and look for:
    - Password fields sending data elsewhere
    - Multiple password fields (confusion attack)
    - External iframes (loading content from elsewhere)
    - Obfuscated JavaScript
    - Brand impersonation in page titles
    
    Returns dict with content analysis and indicators.
    """
    result = {
        'score_impact': 0,
        'indicators': [],
        'form_analysis': {}
    }
    
    try:
        # Download the page
        response = requests.get(url, timeout=8, allow_redirects=True)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check for password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                # Password form submitting to different domain = BIG RED FLAG
                if action.startswith('http') and urlparse(url).netloc not in action:
                    result['indicators'].append('Password form submits to external domain')
                    result['score_impact'] += 35
                    break
            
            # Unusual number of password fields
            if len(password_fields) > 2:
                result['indicators'].append('Unusual number of password fields detected')
                result['score_impact'] += 8
        
        # Check for iframes (especially external ones)
        iframes = soup.find_all('iframe')
        external_iframes = [iframe for iframe in iframes if iframe.get('src', '').startswith('http')]
        if len(external_iframes) > 2:
            result['indicators'].append(f'Multiple external iframes detected ({len(external_iframes)})')
            result['score_impact'] += 12
        
        # Check for obfuscated JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string or ''
            # eval() and unescape() are red flags for obfuscation
            if 'eval(' in script_content or 'unescape(' in script_content:
                result['indicators'].append('Obfuscated JavaScript detected')
                result['score_impact'] += 20
                break
        
        # Check page title for brand impersonation
        title = soup.find('title')
        if title:
            title_text = title.string or ''
            impersonation_brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'bank', 'login']
            if any(brand in title_text.lower() for brand in impersonation_brands):
                domain = urlparse(url).netloc.lower()
                # If title mentions "PayPal" but domain isn't paypal.com...
                if not any(brand in domain for brand in impersonation_brands):
                    result['indicators'].append('Page title suggests brand impersonation')
                    result['score_impact'] += 25
        
        # Store form analysis for reporting
        result['form_analysis'] = {
            'total_forms': len(soup.find_all('form')),
            'password_fields': len(password_fields),
            'external_iframes': len(external_iframes)
        }
        
        # If nothing suspicious found, that's good news
        if not result['indicators']:
            result['indicators'].append('No suspicious content patterns detected')
            result['score_impact'] = -5  # Small reward
            
    except requests.RequestException as exc:
        # Page unreachable - no penalty
        result['score_impact'] = 0
        result['indicators'].append(f'Content analysis unavailable: {str(exc)[:100]}')
    except Exception as exc:
        # Parsing failed - no penalty
        result['score_impact'] = 0
        result['indicators'].append(f'Content parsing failed: {str(exc)[:100]}')
    
    return result


def check_domain_reputation(domain: str) -> Dict[str, Any]:
    """
    Check domain reputation using various signals.
    
    Currently checks for parked domains ("this domain for sale" pages).
    Might add more checks later (DNSBL, etc).
    
    Returns dict with reputation info and score impact.
    """
    result = {
        'score_impact': 0,
        'reputation_sources': [],
        'risk_level': 'unknown'
    }
    
    # Keywords that suggest a parked domain
    parking_keywords = ['domain for sale', 'buy this domain', 'parked domain']
    
    try:
        # Fetch homepage
        response = requests.get(f'http://{domain}', timeout=5)
        content = response.text.lower()
        
        # Check for parking page indicators
        if any(keyword in content for keyword in parking_keywords):
            result['reputation_sources'].append('Domain appears to be parked')
            result['score_impact'] += 15
            result['risk_level'] = 'suspicious'
        
    except Exception:
        # Can't reach domain, can't check reputation
        pass
    
    if not result['reputation_sources']:
        result['reputation_sources'].append('No additional reputation data available')
        result['risk_level'] = 'unknown'
    
    return result


def enhanced_url_verification(url: str) -> Dict[str, Any]:
    """
    Run all enhanced checks and combine results.
    
    This is the main entry point for the enhanced verification.
    It runs all the individual checks and aggregates their results.
    
    Returns comprehensive dict with all check results and total score impact.
    """
    # Parse URL to get hostname
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        hostname = parsed.hostname or ''
    except Exception:
        return {
            'total_score_impact': 0,
            'checks_performed': [],
            'error': 'Invalid URL format'
        }
    
    results = {
        'total_score_impact': 0,
        'checks_performed': []
    }
    
    # SSL check (only for HTTPS URLs)
    if parsed.scheme == 'https':
        ssl_result = check_ssl_certificate(hostname)
        results['ssl_certificate'] = ssl_result
        results['total_score_impact'] += ssl_result['score_impact']
        results['checks_performed'].append('SSL Certificate Validation')
    
    # HTTP headers check
    headers_result = check_http_headers(url)
    results['http_headers'] = headers_result
    results['total_score_impact'] += headers_result['score_impact']
    results['checks_performed'].append('HTTP Security Headers')
    
    # Content analysis
    content_result = analyze_page_content(url)
    results['page_content'] = content_result
    results['total_score_impact'] += content_result['score_impact']
    results['checks_performed'].append('Page Content Analysis')
    
    # Domain reputation check
    reputation_result = check_domain_reputation(hostname)
    results['domain_reputation'] = reputation_result
    results['total_score_impact'] += reputation_result['score_impact']
    results['checks_performed'].append('Domain Reputation')
    
    return results
