"""
integrations.py — Talking to External Services

This module handles all the external API calls:
- DNS lookups (MX and SPF records)
- WHOIS queries (who registered this domain?)
- Google Safe Browsing (is Google flagging this?)

These are our "phone calls" to other services. Sometimes they answer,
sometimes they don't. We handle both gracefully.
"""

import dns.resolver      # For DNS lookups (MX, SPF, etc)
import whois             # For WHOIS queries
from typing import Tuple, List
from functools import lru_cache  # Cache expensive lookups
import os
import requests


@lru_cache(maxsize=256)
def get_mx_records(domain: str) -> List[str]:
    """
    Get MX (Mail Exchange) records for a domain.
    
    MX records tell us where email for this domain should go.
    Legit businesses usually have MX records. Random sketchy domains often don't.
    
    Returns list of mail server hostnames, empty list if none found.
    """
    try:
        # Query DNS for MX records
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        # Strip trailing dots from hostnames (DNS quirk)
        return [str(r.exchange).rstrip('.') for r in answers]
    except Exception:
        # No MX records or DNS failed
        return []


def has_mx(domain: str) -> bool:
    """Quick check: does this domain have MX records?"""
    return bool(get_mx_records(domain))


@lru_cache(maxsize=256)
def has_spf(domain: str) -> bool:
    """
    Check if domain has an SPF (Sender Policy Framework) record.
    
    SPF is an email authentication thing. It says "only these servers
    can send email for my domain." Not having it isn't terrible, but
    having it shows the domain owner cares about email security.
    
    Returns True if SPF record found, False otherwise.
    """
    try:
        # Query TXT records (SPF is stored as TXT)
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for r in answers:
            # TXT records can have multiple strings, join them
            txt = ''.join([t.decode() if isinstance(t, bytes) else str(t) for t in r.strings])
            # Look for SPF version marker
            if 'v=spf1' in txt:
                return True
    except Exception:
        # DNS lookup failed, oh well
        pass
    return False


@lru_cache(maxsize=256)
def get_whois_info(domain: str) -> dict:
    """
    Get WHOIS registration info for a domain.
    
    WHOIS tells us:
    - When the domain was registered
    - Who registered it (sometimes)
    - When it expires
    
    New domains are more suspicious than old ones.
    Private registration isn't bad, just less transparent.
    
    Returns dict with domain info, empty dict if lookup fails.
    """
    try:
        w = whois.whois(domain)
        return {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
        }
    except Exception:
        # WHOIS lookup failed (common for some TLDs)
        return {}


def safe_browsing_check(url: str, api_key: str = None) -> dict:
    """
    Check a URL against Google Safe Browsing API.
    
    Google maintains a massive database of known malicious URLs.
    If they flag something, we should probably listen.
    
    Args:
        url: The URL to check
        api_key: Optional API key (falls back to env var)
    
    Returns:
        {'ok': True, 'matches': [...]} if check succeeded
        {'ok': False, 'error': '...'} if something went wrong
    """
    # Basic validation
    if not url or not url.strip():
        return {'ok': False, 'error': 'Invalid or empty URL provided'}
    
    # Get API key from param or environment
    key = api_key or os.environ.get('SAFE_BROWSING_API_KEY')
    if not key:
        return {'ok': False, 'error': 'No Safe Browsing API key provided'}

    # Build the API request
    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}'
    
    payload = {
        'client': {
            'clientId': 'safe-url-check',
            'clientVersion': '1.0'
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING', 
                'POTENTIALLY_HARMFUL_APPLICATION',
                'UNWANTED_SOFTWARE'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }

    try:
        # Make the API call
        resp = requests.post(endpoint, json=payload, timeout=10)
        resp.raise_for_status()
        
        # Parse response
        data = resp.json()
        matches = data.get('matches', [])
        return {'ok': True, 'matches': matches}
        
    except requests.HTTPError as e:
        return {'ok': False, 'error': f'HTTP error: {e}'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}
