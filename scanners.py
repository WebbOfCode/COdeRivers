"""
scanners.py — The Brain of the Operation

This module does the actual URL analysis. It's like a detective that looks at
a URL and decides "yeah this is sus" or "seems legit."

How it works:
1. Parse the URL (make sure it's not garbage)
2. Check for red flags (suspicious TLDs, IP addresses, sketchy keywords)
3. Query external services (DNS, WHOIS, Google Safe Browsing)
4. Run enhanced checks (SSL, headers, content analysis)
5. AI analysis (content inspection, not LLM stuff)
6. Crunch the numbers and return a verdict

Shout out to threat intel feeds for keeping us all safe 🙏
"""

import re  # regex is love, regex is life
import math  # for the fancy scoring math
import ipaddress
import unicodedata
from urllib.parse import urlparse  # breaking URLs into pieces

import tldextract  # for extracting registrable domain (eTLD+1)

# Our custom modules - they do the heavy lifting
from integrations import has_mx, has_spf, get_whois_info, safe_browsing_check
from threat_intel import collect_threat_intel
from accuracy_enhancements import enhanced_url_verification
from ai_analyzer import analyze_site_with_ai


# Suspicious TLDs - these are the sketchy neighborhoods of the internet
# Free domains attract... interesting characters
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq'}

# Keywords that make us raise an eyebrow
# If you see these in a URL, proceed with caution
SUSPICIOUS_WORDS = {'login', 'secure', 'update', 'bank', 'verify', 'confirm', 'account'}


def looks_like_ip(hostname: str) -> bool:
    """
    Check if the hostname is a valid IP address (v4 or v6).
    
    Legit sites use domain names. Scammers love IPs because they're free
    and disposable. If you see an IP in a URL, that's sus.
    
    Uses the ipaddress stdlib so '999.999.999.999' no longer passes.
    """
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_registrable_domain(hostname: str) -> str:
    """
    Extract the registrable domain (eTLD+1) from a hostname.
    
    'login.microsoft.com'  -> 'microsoft.com'
    'a.b.cdn.cloudflare.net' -> 'cloudflare.net'
    'example.co.uk'  -> 'example.co.uk'
    
    Returns empty string if extraction fails or hostname is an IP.
    """
    if not hostname or looks_like_ip(hostname):
        return ''
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f'{ext.domain}.{ext.suffix}'
    return ''


def _has_mixed_scripts(text: str) -> bool:
    """Detect mixed Unicode scripts (Latin + Cyrillic, etc.) — homoglyph trick."""
    scripts = set()
    for ch in text:
        if ch in '.-':
            continue
        cat = unicodedata.category(ch)
        if cat.startswith('L'):  # letter characters
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                pass
    # 'LATIN' alone is fine; 'LATIN' + 'CYRILLIC' is suspicious
    scripts.discard('DIGIT')
    return len(scripts) > 1


def is_public_lookup_domain(hostname: str) -> bool:
    """Return True only for hostnames suitable for DNS/WHOIS enrichment."""
    if not hostname:
        return False

    host = hostname.strip().lower()
    if host in {'localhost'}:
        return False
    if host.endswith(('.local', '.lan', '.home', '.internal')):
        return False
    if '.' not in host:
        return False

    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return True


def analyze_url(url: str) -> dict:
    """
    Main analysis function - the detective work happens here.
    
    Returns a dict with:
    - score: 0-100 risk score (higher = more dangerous)
    - reasons: human-readable list of what we found
    - suggested_action: what to do about it
    - breakdown: detailed scoring for nerds
    - intel_hits: matches from threat intel feeds
    - and more...
    
    This is where we earn our keep.
    """
    # Lists to collect our findings
    reasons = []      # What we found (human readable)
    breakdown = []    # Detailed scoring breakdown
    score_inputs = [] # Raw numbers for the math

    # Helper to consistently record findings
    def record(weight: int, message: str, category: str) -> None:
        """Log a finding with its score impact."""
        score_inputs.append(weight)  # always include, even negatives
        label = f'[{category}] {message}' if category else message
        reasons.append(label)
        breakdown.append({'points': weight, 'category': category, 'message': message})

    # Step 1: Parse the URL
    # If they didn't include http://, we add it. Be helpful like that.
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
    except Exception:
        # URL is so broken we can't even parse it
        # That's an automatic "don't go there"
        return {
            'score': 100,
            'reasons': ['Invalid URL format - what even is this?'],
            'suggested_action': 'Do not visit — this URL is malformed',
            'breakdown': [],
            'intel_hits': [],
            'intel_errors': [],
        }

    # Extract the parts we care about
    host = parsed.hostname or ''
    path = parsed.path or ''

    # Derive registrable domain once — used for DNS/WHOIS and context-aware heuristics
    reg_domain = get_registrable_domain(host)

    # Step 2: Heuristic checks - looking for red flags
    
    # Red flag: Raw IP address
    # Nobody legit uses IPs in URLs unless they're a server admin
    if looks_like_ip(host):
        record(45, 'Hostname is a direct IP address', 'network')

    # Red flag: Suspicious TLD
    # Some TLDs are basically the wild west
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            record(28, f'Suspicious top-level domain ({tld})', 'domain')
            break  # One is enough, don't pile on

    # Red flag: Obscenely long URL
    # Legit URLs aren't novels. Long URLs are often hiding something.
    if len(url) > 100:
        record(12, 'URL length exceeds 100 characters', 'presentation')

    # --- Modern phishing signals ---

    # Punycode / IDN — internationalized domain that could be a lookalike
    if host.startswith('xn--') or '.xn--' in host:
        record(18, 'Punycode (internationalized) domain detected — possible lookalike', 'domain')

    # Mixed Unicode scripts in hostname (Latin + Cyrillic, etc.)
    if _has_mixed_scripts(host):
        record(20, 'Mixed Unicode scripts in hostname — possible homoglyph attack', 'domain')

    # '@' in authority section — classic phishing trick (user@evil.com)
    if '@' in (parsed.netloc or ''):
        record(35, 'URL contains @ in authority — may redirect to a different host', 'presentation')

    # Excessive hyphens in hostname — common in phishing domains
    if host.count('-') >= 4:
        record(10, 'Excessive hyphens in hostname (common in phishing domains)', 'domain structure')

    # --- Improved keyword scoring ---
    # Only penalize keywords that appear in the *hostname* (not innocent paths
    # like /account/settings). Require 2+ keywords OR keyword in subdomain
    # portion to trigger — one keyword in a path is normal.
    host_lower = host.lower()
    path_lower = path.lower()
    ext = tldextract.extract(host)
    subdomain_part = (ext.subdomain or '').lower()

    host_kw = [w for w in SUSPICIOUS_WORDS if w in host_lower]
    path_kw = [w for w in SUSPICIOUS_WORDS if w in path_lower]
    all_kw = sorted(set(host_kw + path_kw))

    if host_kw:
        # Keywords in the hostname itself are strong signals
        if any(w in subdomain_part for w in host_kw):
            # Keywords in a subdomain (login.evil.com) — strongest signal
            record(22, 'Suspicious keywords in subdomain: ' + ', '.join(sorted(host_kw)), 'keywords')
        else:
            record(15, 'Suspicious keywords in hostname: ' + ', '.join(sorted(host_kw)), 'keywords')
    elif len(path_kw) >= 2:
        # Multiple suspicious keywords in the path — worth noting
        record(10, 'Multiple suspicious keywords in URL path: ' + ', '.join(sorted(path_kw)), 'keywords')
    # Single keyword in path only (like /account/settings) → no penalty

    # --- Conditional subdomain depth check ---
    # Deep subdomains alone aren't suspicious (CDNs, cloud providers).
    # Only penalize when combined with other phishing-ish structure.
    if host.count('.') >= 3:
        has_kw_in_sub = any(w in subdomain_part for w in SUSPICIOUS_WORDS)
        has_punycode = host.startswith('xn--') or '.xn--' in host
        has_many_hyphens = host.count('-') >= 4
        if has_kw_in_sub or has_punycode or has_many_hyphens:
            record(12, 'Deep subdomain structure combined with suspicious patterns', 'domain structure')
        else:
            # Informational only — no score penalty
            record(0, 'Hostname has multiple subdomains (common for CDNs/cloud services)', 'domain structure')

    # Step 3: Infrastructure checks
    # DNS and WHOIS tell us a lot about legitimacy.
    # We use the registrable domain (eTLD+1) so 'login.microsoft.com'
    # checks 'microsoft.com' — where MX/SPF/WHOIS actually live.
    lookup_domain = reg_domain or host
    if lookup_domain and is_public_lookup_domain(lookup_domain):
        try:
            # Check for MX records (does this domain handle email?)
            if not has_mx(lookup_domain):
                record(3, f'No MX records detected for {lookup_domain} (common for non-email domains)', 'dns')
            
            # Check for SPF records (email authentication)
            if not has_spf(lookup_domain):
                record(2, f'No SPF record detected for {lookup_domain} (informational)', 'dns')
            
            # WHOIS lookup - when was this domain created?
            who = get_whois_info(lookup_domain)
            if not who or not who.get('creation_date'):
                record(0, f'WHOIS data unavailable for {lookup_domain} (privacy-protected or new TLD)', 'whois')
            else:
                record(0, f'WHOIS registration data resolved for {lookup_domain}', 'whois')
                
        except Exception as dns_error:
            # DNS lookups fail sometimes, don't crash the whole scan
            record(0, f'DNS/WHOIS lookup failed for {lookup_domain}: {dns_error}', 'infrastructure')
    elif host:
        record(0, 'Skipped DNS/WHOIS enrichment for local or non-public hostname', 'infrastructure')

    # Step 4: Google Safe Browsing check
    # If Google says it's bad, it's probably bad
    sb = safe_browsing_check(url)
    if sb.get('ok'):
        matches = sb.get('matches', [])
        if matches:
            # Oof, Google flagged this one
            threat_types = ', '.join(sorted(set(match.get('threatType', 'UNKNOWN') for match in matches)))
            record(70, f'Google Safe Browsing flagged threat types: {threat_types}', 'external intel')
    elif sb.get('error') and 'API key' not in sb.get('error', ''):
        # Safe Browsing failed but not because of config
        record(0, f'Safe Browsing lookup failed: {sb.get("error")}', 'external intel')

    # Step 5: Threat Intelligence feeds
    # URLHaus, AlienVault OTX, etc.
    intel_result = collect_threat_intel(url)
    intel_hits = intel_result.get('hits', [])
    intel_errors = intel_result.get('errors', [])
    
    for hit in intel_hits:
        severity = (hit.get('severity') or 'medium').lower()
        # Map severity to score impact
        severity_weight = {'low': 20, 'medium': 40, 'high': 65}.get(severity, 40)
        message = f"{hit.get('source', 'Intel')} match — {hit.get('description', 'flagged threat')} (severity: {severity})"
        record(severity_weight, message, 'external intel')

    # Log any intel source errors (for transparency)
    for intel_error in intel_errors:
        error_message = f"{intel_error.get('source', 'Intel source')} unavailable: {intel_error.get('message', 'Unknown error')}"
        record(0, error_message, 'external intel')

    # Step 6: Enhanced accuracy checks
    # SSL certificates, HTTP headers, content analysis, domain rep
    enhanced_checks = {}
    try:
        enhanced_checks = enhanced_url_verification(url)

        # Record each enhanced check as ONE bucket: first message carries
        # the weight, remaining messages are explanations (weight 0).

        # SSL findings (single message — no multiplication issue)
        if 'ssl_certificate' in enhanced_checks:
            ssl_check = enhanced_checks['ssl_certificate']
            if ssl_check.get('message'):
                record(ssl_check['score_impact'], ssl_check['message'], 'ssl/tls')

        # HTTP header findings — bucket weight once
        if 'http_headers' in enhanced_checks:
            headers_check = enhanced_checks['http_headers']
            messages = headers_check.get('messages', [])
            for i, message in enumerate(messages):
                weight = headers_check['score_impact'] if i == 0 else 0
                record(weight, message, 'http security')

        # Content analysis findings — bucket weight once
        if 'page_content' in enhanced_checks:
            content_check = enhanced_checks['page_content']
            indicators = content_check.get('indicators', [])
            for i, indicator in enumerate(indicators):
                weight = content_check['score_impact'] if i == 0 else 0
                record(weight, indicator, 'content analysis')

        # Reputation findings — bucket weight once
        if 'domain_reputation' in enhanced_checks:
            rep_check = enhanced_checks['domain_reputation']
            sources = rep_check.get('reputation_sources', [])
            for i, source in enumerate(sources):
                weight = rep_check['score_impact'] if i == 0 else 0
                record(weight, source, 'reputation')
                    
    except Exception as enhanced_error:
        # Don't let enhanced checks break the main analysis
        record(0, f'Enhanced verification unavailable: {str(enhanced_error)[:100]}', 'accuracy checks')

    # Step 7: AI-style content analysis
    # Not actual AI, just smart pattern matching on page content
    ai_analysis = {}
    try:
        ai_analysis = analyze_site_with_ai(url)
        ai_status = ai_analysis.get('status')
        if ai_status == 'ok':
            ai_score = ai_analysis.get('risk_score') or 0
            ai_summary = ai_analysis.get('summary', '')
            message = ai_summary[:140] + ('...' if len(ai_summary) > 140 else '')
            if ai_score >= 65:
                record(30, f'AI review flagged high risk: {message}', 'ai analysis')
            elif ai_score >= 40:
                record(15, f'AI review noted concerns: {message}', 'ai analysis')
            else:
                record(0, 'AI review did not find high risk patterns', 'ai analysis')
        else:
            record(0, f"AI review unavailable: {ai_analysis.get('error', 'unknown error')}", 'ai analysis')
    except Exception as ai_error:
        ai_analysis = {'status': 'error', 'error': str(ai_error)}
        record(0, f'AI review failed: {str(ai_error)[:100]}', 'ai analysis')

    # Step 8: Calculate final score
    # We use diminishing returns so adding more signals doesn't explode the score
    def aggregate_score(inputs):
        """Combine all scores with diminishing returns."""
        if not inputs:
            return 0
        raw = max(0, sum(inputs))  # floor at 0 so good signals can offset risk
        # This formula caps at 100 but gives diminishing returns as score grows
        return min(100, int(round(100 * (1 - math.exp(-raw / 60.0)))))

    score = aggregate_score(score_inputs)

    # Determine what action to suggest based on score
    if score >= 70:
        suggested = 'Do not visit — very high risk'
    elif score >= 45:
        suggested = 'Use extreme caution — suspicious indicators present'
    elif score >= 20:
        suggested = 'Proceed carefully — mixed signals found'
    else:
        suggested = 'Likely safe, but remain vigilant'

    # Make sure we always have something to show
    if not reasons:
        reasons = ['No obvious heuristics detected — this looks clean']

    # Package it all up and send it home
    return {
        'score': score,
        'reasons': reasons,
        'suggested_action': suggested,
        'breakdown': breakdown,
        'intel_hits': intel_hits,
        'intel_errors': intel_errors,
        'enhanced_checks': enhanced_checks,
        'ai_analysis': ai_analysis,
    }
