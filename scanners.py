# Import regular expression module for pattern matching
import re
# Import URL parsing utility from urllib
from urllib.parse import urlparse
# Import integration functions for DNS, WHOIS, and Safe Browsing checks
from integrations import has_mx, has_spf, get_whois_info, safe_browsing_check


# Set of suspicious top-level domains commonly used for phishing
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}
# Set of suspicious words often found in phishing URLs
SUSPICIOUS_WORDS = {'login', 'secure', 'update', 'bank', 'verify', 'confirm', 'account'}


# Function to check if hostname looks like an IP address
def looks_like_ip(hostname: str) -> bool:
    # Use regex to match IPv4 pattern (4 groups of digits separated by dots)
    return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))


# Main function to analyze a URL for phishing indicators
def analyze_url(url: str) -> dict:
    # Docstring explaining function purpose and return value
    """Return a small heuristics-based analysis of the URL.

    Result dict contains: score (0-100), reasons (list), and suggested_action.
    """
    # Initialize empty list to store reasons for score
    reasons = []
    # Initialize score at zero (higher score = more suspicious)
    score = 0

    # Try to parse the URL
    try:
        # Parse URL, adding http:// if no scheme present
        parsed = urlparse(url if '://' in url else 'http://' + url)
    # If URL parsing fails, catch the exception
    except Exception:
        # Return maximum score and error message for invalid URL
        return {'score': 100, 'reasons': ['Invalid URL format'], 'suggested_action': 'Do not visit'}

    # Extract hostname from parsed URL (empty string if None)
    host = parsed.hostname or ''
    # Extract path from parsed URL (empty string if None)
    path = parsed.path or ''

    # Check if hostname is an IP address (suspicious)
    if looks_like_ip(host):
        # Add reason to list
        reasons.append('Hostname is an IP address')
        # Add 40 points to score (high risk indicator)
        score += 40

    # Check if domain uses a suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        # Check if hostname ends with this suspicious TLD
        if host.endswith(tld):
            # Add reason with specific TLD to list
            reasons.append(f'Suspicious top-level domain ({tld})')
            # Add 25 points to score
            score += 25
            # Stop checking after first match
            break

    # Check if URL is unusually long (possible obfuscation)
    if len(url) > 100:
        # Add reason to list
        reasons.append('URL is unusually long')
        # Add 10 points to score
        score += 10

    # Check for suspicious words in hostname and path
    # Convert hostname and path to lowercase for case-insensitive matching
    low = (host + ' ' + path).lower()
    # Find all suspicious words present in the URL
    found = [w for w in SUSPICIOUS_WORDS if w in low]
    # If any suspicious words found
    if found:
        # Add reason with list of found words
        reasons.append('Contains suspicious words: ' + ', '.join(found))
        # Add 20 points to score
        score += 20

    # Check for multiple subdomains (obfuscation technique)
    if host.count('.') >= 3:
        # Add reason to list
        reasons.append('Many subdomains (possible obfuscation)')
        # Add 5 points to score
        score += 5

    # Perform email domain and DNS checks
    # Use hostname as domain for checks
    domain = host
    # Try to perform DNS and WHOIS checks
    try:
        # Only check if domain exists
        if domain:
            # Check if domain has MX records (email capability)
            if not has_mx(domain):
                # Add reason if no MX records found
                reasons.append('No MX records found for domain (email delivery unlikely)')
                # Add 10 points to score
                score += 10
            # Check if domain has SPF record (email authentication)
            if not has_spf(domain):
                # Add reason if no SPF record found
                reasons.append('No SPF record found for domain')
                # Add 5 points to score
                score += 5
            # Get WHOIS information for domain
            who = get_whois_info(domain)
            # Check if WHOIS info exists and has creation date
            if who and who.get('creation_date'):
                # Add positive indicator if WHOIS info found
                reasons.append('WHOIS: domain registration info found')
            # If no WHOIS info or creation date
            else:
                # Add reason for missing WHOIS info
                reasons.append('WHOIS: no registration info / private')
                # Add 5 points to score
                score += 5
    # If DNS/WHOIS checks fail, catch exception
    except Exception:
        # Non-fatal error - don't break the entire analysis
        pass

    # Perform Google Safe Browsing API check
    # Call Safe Browsing API with the URL
    sb = safe_browsing_check(url)
    # Check if API call was successful
    if sb.get('ok'):
        # Get list of threat matches from response
        matches = sb.get('matches', [])
        # If any threats detected
        if matches:
            # Extract unique threat types from matches
            threat_types = ', '.join(set(m.get('threatType', 'UNKNOWN') for m in matches))
            # Add warning with threat types to reasons
            reasons.append(f'⚠️ Google Safe Browsing: flagged as {threat_types}')
            # Add 50 points to score (major threat indicator)
            score += 50
    # If API call failed and error is not about missing API key
    elif sb.get('error') and 'API key' not in sb.get('error', ''):
        # Add Safe Browsing error to reasons (but not if just missing key)
        reasons.append(f'Safe Browsing check failed: {sb.get("error")}')

    # Cap the score at maximum of 100
    score = min(100, score)

    # Determine suggested action based on score
    if score >= 60:
        # High score = likely malicious
        suggested = 'Do not visit — likely malicious'
    elif score >= 30:
        # Medium score = possibly suspicious
        suggested = 'Caution — possibly suspicious'
    else:
        # Low score = likely safe (but still be cautious)
        suggested = 'Likely safe, but remain cautious'

    # If no reasons were added (clean URL)
    if not reasons:
        # Add default message
        reasons = ['No obvious heuristics detected']

    # Return dictionary with score, reasons, and suggested action
    return {'score': score, 'reasons': reasons, 'suggested_action': suggested}
