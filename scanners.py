# Import regular expression module for pattern matching
import re
# Import math module for non-linear score aggregation
import math
# Import URL parsing utility from urllib
from urllib.parse import urlparse
# Import integration functions for DNS, WHOIS, and Safe Browsing checks
from integrations import has_mx, has_spf, get_whois_info, safe_browsing_check
# Import threat intelligence aggregation helper
from threat_intel import collect_threat_intel


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
    """Return a heuristics and intelligence based analysis of the URL.

    Result dict contains the score (0-100), reasons, suggested action, a
    detailed breakdown, and raw threat intelligence hits/errors.
    """
    # Initialize list that will hold human readable reasons
    reasons = []
    # Initialize list capturing granular scoring contributions
    breakdown = []
    # Initialize list capturing numeric score inputs for aggregation
    score_inputs = []

    # Define helper function to record scoring signals consistently
    def record(weight: int, message: str, category: str) -> None:
        # Add weight to list when it contributes to score
        if weight > 0:
            score_inputs.append(weight)
        # Format human readable reason including category label
        label = f'[{category}] {message}' if category else message
        # Append reason to reason list
        reasons.append(label)
        # Append entry to breakdown list with metadata
        breakdown.append({'points': weight, 'category': category, 'message': message})

    # Try to parse the provided URL safely
    try:
        # Parse URL, defaulting to http scheme when missing
        parsed = urlparse(url if '://' in url else 'http://' + url)
    # Handle parsing errors gracefully
    except Exception:
        # Return high risk result for invalid URLs
        return {
            'score': 100,
            'reasons': ['Invalid URL format'],
            'suggested_action': 'Do not visit — malformed URL',
            'breakdown': [],
            'intel_hits': [],
            'intel_errors': [],
        }

    # Extract hostname for domain level heuristics
    host = parsed.hostname or ''
    # Extract path segment for keyword scanning
    path = parsed.path or ''

    # Evaluate whether hostname is presented as raw IP address
    if looks_like_ip(host):
        # Record network based signal with high weight
        record(45, 'Hostname is a direct IP address', 'network')

    # Inspect domain suffix against suspicious TLD catalogue
    for tld in SUSPICIOUS_TLDS:
        # Check whether host ends with flagged top-level domain
        if host.endswith(tld):
            # Record top-level domain heuristic
            record(28, f'Suspicious top-level domain ({tld})', 'domain')
            # Exit loop once a match is found
            break

    # Evaluate overall URL length for obfuscation patterns
    if len(url) > 100:
        # Record presentation heuristic for excessively long URLs
        record(12, 'URL length exceeds 100 characters', 'presentation')

    # Normalize host and path for keyword scanning
    low = (host + ' ' + path).lower()
    # Determine suspicious vocabulary present in URL components
    found = [word for word in SUSPICIOUS_WORDS if word in low]
    # If suspicious terms discovered then record heuristic
    if found:
        # Record string based heuristic with associated weight
        record(22, 'Contains high risk keywords: ' + ', '.join(sorted(found)), 'keywords')

    # Count subdomains as indicator of obfuscation
    if host.count('.') >= 3:
        # Record subdomain heavy structure heuristic
        record(7, 'Hostname contains multiple nested subdomains', 'domain structure')

    # Capture domain for DNS and WHOIS lookups
    domain = host
    # Execute DNS and WHOIS checks when domain is available
    if domain:
        # Use try-except to insulate scoring from lookup errors
        try:
            # Determine whether MX records exist for domain
            if not has_mx(domain):
                # Record absence of MX records as medium risk indicator
                record(12, 'No MX records detected for domain', 'dns')
            # Determine whether SPF records are published
            if not has_spf(domain):
                # Record absence of SPF record as low-medium indicator
                record(6, 'No SPF record detected for domain', 'dns')
            # Retrieve WHOIS registration metadata
            who = get_whois_info(domain)
            # If WHOIS info lacks creation date treat as suspicious
            if not who or not who.get('creation_date'):
                # Record missing WHOIS footprint heuristic
                record(8, 'WHOIS data missing or privacy protected', 'whois')
            else:
                # Record presence of WHOIS info as neutral informational note
                record(0, 'WHOIS registration data resolved successfully', 'whois')
        # Swallow lookup errors while emitting informational note
        except Exception as dns_error:
            # Record lookup failure with zero weight for transparency
            record(0, f'DNS/WHOIS lookup failed: {dns_error}', 'infrastructure')

    # Issue Google Safe Browsing lookup for reputation signal
    sb = safe_browsing_check(url)
    # When Safe Browsing query succeeds inspect matches
    if sb.get('ok'):
        # Extract matches list from API response
        matches = sb.get('matches', [])
        # When threats are present record high severity signal
        if matches:
            # Create comma separated list of threat types
            threat_types = ', '.join(sorted(set(match.get('threatType', 'UNKNOWN') for match in matches)))
            # Record Safe Browsing flag with elevated weight
            record(70, f'Google Safe Browsing flagged threat types: {threat_types}', 'external intel')
    # When Safe Browsing fails and error is not missing API key report issue
    elif sb.get('error') and 'API key' not in sb.get('error', ''):
        # Record failure message with zero scoring weight
        record(0, f'Safe Browsing lookup failed: {sb.get("error")}', 'external intel')

    # Aggregate external intelligence feeds for additional signals
    intel_result = collect_threat_intel(url)
    # Extract list of hits from aggregated intelligence
    intel_hits = intel_result.get('hits', [])
    # Extract list of errors from aggregated intelligence
    intel_errors = intel_result.get('errors', [])
    # Iterate through intelligence hits to incorporate into scoring
    for hit in intel_hits:
        # Normalize severity field to lower case for weight mapping
        severity = (hit.get('severity') or 'medium').lower()
        # Map severity strings to integer score weights
        severity_weight = {'low': 20, 'medium': 40, 'high': 65}.get(severity, 40)
        # Compose descriptive message summarizing intelligence finding
        message = f"{hit.get('source', 'Intel')} match — {hit.get('description', 'flagged threat')} (severity: {severity})"
        # Record intelligence signal with mapped weight
        record(severity_weight, message, 'external intel')

    # Record any intelligence source errors as informational notes
    for intel_error in intel_errors:
        # Compose message describing the error for transparency
        error_message = f"{intel_error.get('source', 'Intel source')} unavailable: {intel_error.get('message', 'Unknown error')}"
        # Record informational note with zero scoring weight
        record(0, error_message, 'external intel')

    # Define helper to compute non-linear aggregate risk score
    def aggregate_score(inputs):
        # Return early when there are no scoring inputs
        if not inputs:
            return 0
        # Calculate raw sum of score contributions
        raw = sum(inputs)
        # Convert raw score into bounded 0-100 value with diminishing returns
        return min(100, int(round(100 * (1 - math.exp(-raw / 60.0)))))

    # Compute final score using aggregated contributions
    score = aggregate_score(score_inputs)

    # Determine suggested action thresholds based on final score
    if score >= 70:
        # High risk bucket indicates malicious likelihood
        suggested = 'Do not visit — very high risk'
    elif score >= 45:
        # Moderate risk bucket indicates strong suspicion
        suggested = 'Use extreme caution — suspicious indicators present'
    elif score >= 20:
        # Low risk bucket still warrants caution
        suggested = 'Proceed carefully — mixed signals found'
    else:
        # Minimal risk bucket indicates likely safe outcome
        suggested = 'Likely safe, but remain vigilant'

    # Ensure there is at least one reason to display to the user
    if not reasons:
        # Provide default reason when no signals are present
        reasons = ['No obvious heuristics detected']

    # Return comprehensive analysis dictionary
    return {
        'score': score,
        'reasons': reasons,
        'suggested_action': suggested,
        'breakdown': breakdown,
        'intel_hits': intel_hits,
        'intel_errors': intel_errors,
    }
