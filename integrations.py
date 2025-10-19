"""
integrations.py — External integrations for DNS, WHOIS, and Safe Browsing

Functions:
- get_mx_records / has_mx: DNS MX record checks
- has_spf: SPF presence via TXT records
- get_whois_info: Domain registration metadata
- safe_browsing_check: Google Safe Browsing v4 lookup
"""

# Import DNS resolver library for MX and SPF record lookups
import dns.resolver
# Import WHOIS library for domain registration information
import whois
# Import typing hints for function signatures
from typing import Tuple, List
# Import lru_cache decorator to cache expensive lookups
from functools import lru_cache
# Import os module to read environment variables
import os
# Import requests library for HTTP API calls
import requests


# Function to retrieve MX (Mail Exchange) records for a domain
@lru_cache(maxsize=256)
def get_mx_records(domain: str) -> List[str]:
    # Try to query DNS for MX records
    try:
        # Resolve MX records for the given domain
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        # Extract and strip trailing dots from MX hostnames, return as list
        return [str(r.exchange).rstrip('.') for r in answers]
    # If DNS lookup fails, catch the exception
    except Exception:
        # Return empty list if no MX records found
        return []


# Function to check if a domain has MX records (indicates email capability)
def has_mx(domain: str) -> bool:
    # Call get_mx_records and return True if any records exist
    return bool(get_mx_records(domain))


# Function to check if a domain has SPF (Sender Policy Framework) record
@lru_cache(maxsize=256)
def has_spf(domain: str) -> bool:
    # Try to query DNS for TXT records
    try:
        # Resolve TXT records for the given domain
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        # Loop through each TXT record
        for r in answers:
            # Decode bytes to string if needed, join all parts of the TXT record
            txt = ''.join([t.decode() if isinstance(t, bytes) else str(t) for t in r.strings])
            # Check if the TXT record contains SPF version identifier
            if 'v=spf1' in txt:
                # Return True if SPF record found
                return True
    # If DNS lookup fails, catch the exception
    except Exception:
        # Silently pass if error occurs
        pass
    # Return False if no SPF record found
    return False


# Function to retrieve WHOIS information for a domain
@lru_cache(maxsize=256)
def get_whois_info(domain: str) -> dict:
    # Try to perform WHOIS lookup
    try:
        # Query WHOIS database for domain information
        w = whois.whois(domain)
        # Return dictionary with key domain registration details
        return {
            # Domain name from WHOIS record
            'domain_name': w.domain_name,
            # Registrar company name
            'registrar': w.registrar,
            # Domain creation/registration date
            'creation_date': w.creation_date,
            # Domain expiration date
            'expiration_date': w.expiration_date,
        }
    # If WHOIS lookup fails, catch the exception
    except Exception:
        # Return empty dictionary if lookup fails
        return {}


# Function to check a URL against Google Safe Browsing API
def safe_browsing_check(url: str, api_key: str = None) -> dict:
    # Docstring explaining function purpose and return value
    """Check a URL using Google Safe Browsing v4 API.

    Returns a dict with keys: ok (bool), matches (list) or error message.
    If api_key is None, will attempt to read from SAFE_BROWSING_API_KEY env var.
    """
    # Validate URL is not empty or None
    if not url or not url.strip():
        # Return error for empty/invalid URLs
        return {'ok': False, 'error': 'Invalid or empty URL provided'}
    
    # Get API key from parameter or environment variable
    key = api_key or os.environ.get('SAFE_BROWSING_API_KEY')
    # Check if API key is available
    if not key:
        # Return error dict if no API key provided
        return {'ok': False, 'error': 'No Safe Browsing API key provided'}

    # Build the Safe Browsing API endpoint URL with the API key
    endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}'
    # Construct the JSON payload for the API request
    payload = {
        # Client identification section
        'client': {
            # Application identifier
            'clientId': 'safe-url-check',
            # Application version
            'clientVersion': '1.0'
        },
        # Threat information section specifying what to check
        'threatInfo': {
            # List of threat types to check for
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'POTENTIALLY_HARMFUL_APPLICATION', 'UNWANTED_SOFTWARE'],
            # Platform types to check (any platform)
            'platformTypes': ['ANY_PLATFORM'],
            # Type of threat entries (URL in this case)
            'threatEntryTypes': ['URL'],
            # List of URLs to check (single URL)
            'threatEntries': [{'url': url}]
        }
    }

    # Try to make the API request
    try:
        # POST request to Safe Browsing API with JSON payload and 10 second timeout
        resp = requests.post(endpoint, json=payload, timeout=10)
        # Raise exception if HTTP error status code returned
        resp.raise_for_status()
        # Parse JSON response from API
        data = resp.json()
        # Extract matches list from response (empty list if no threats found)
        matches = data.get('matches', [])
        # Return success dict with matches
        return {'ok': True, 'matches': matches}
    # Catch HTTP-specific errors (4xx, 5xx status codes)
    except requests.HTTPError as e:
        # Return error dict with HTTP error details
        return {'ok': False, 'error': f'HTTP error: {e}'}
    # Catch any other exceptions (network errors, timeout, etc.)
    except Exception as e:
        # Return error dict with generic error message
        return {'ok': False, 'error': str(e)}

