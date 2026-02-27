"""
threat_intel.py — Checking the Threat Feeds

We query external threat intelligence sources to see if a URL
is known to be malicious. Think of these as "most wanted" lists
for bad URLs.

Sources:
- URLHaus: Database of malware distribution sites
- AlienVault OTX: Community-driven threat intelligence

These APIs require keys (free to get), but we handle missing
keys gracefully - we just can't check that source.
"""

import os
from typing import Dict, List, Tuple
from urllib.parse import quote
import requests


# Type aliases for clarity
IntelHit = Dict[str, str]      # A threat match we found
IntelError = Dict[str, str]    # Something went wrong
IntelResult = Tuple[List[IntelHit], List[IntelError]]


def query_urlhaus(url: str) -> IntelResult:
    """
    Check URLHaus for known malicious URLs.
    
    URLHaus is a project that tracks malware distribution sites.
    If a URL is in their database, it's distributing malware. Period.
    
    Note: URLHaus now requires an API key (free at urlhaus.abuse.ch/api/)
    
    Returns: (list of hits, list of errors)
    """
    hits: List[IntelHit] = []
    errors: List[IntelError] = []
    
    if not url or not url.strip():
        return hits, errors
    
    # Get API key from environment
    api_key = os.environ.get('URLHAUS_API_KEY')
    
    endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'
    payload = {'url': url}
    headers = {
        'User-Agent': 'Safe-URL-Check/2.0 (https://github.com/WebbOfCode/Safe-URL-Check)',
        'Accept': 'application/json'
    }
    
    if api_key:
        headers['Auth-Key'] = api_key
    
    try:
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        
        # 401 = need API key
        if response.status_code == 401:
            errors.append({
                'source': 'URLHaus',
                'message': 'API key required (get free key at https://urlhaus.abuse.ch/api/)'
            })
            return hits, errors
        
        response.raise_for_status()
        data = response.json()
        
        if data.get('query_status') == 'ok':
            # Found a match! This URL is bad news.
            signature = data.get('threat', data.get('signature', 'Unknown threat'))
            status = data.get('url_status', 'unknown')
            hits.append({
                'source': 'URLHaus',
                'severity': 'high' if status.lower() == 'online' else 'medium',
                'description': f'URL flagged by URLHaus ({signature})',
            })
        elif data.get('query_status') == 'no_results':
            # URL not in database - that's good news
            pass
        else:
            errors.append({
                'source': 'URLHaus',
                'message': f"Unexpected response: {data.get('query_status', 'unknown')}"
            })
            
    except requests.HTTPError as exc:
        errors.append({'source': 'URLHaus', 'message': f'HTTP error: {exc}'})
    except requests.RequestException as exc:
        errors.append({'source': 'URLHaus', 'message': f'Request failure: {exc}'})
    
    return hits, errors


def query_otx(url: str) -> IntelResult:
    """
    Check AlienVault OTX for threat intelligence.
    
    OTX (Open Threat Exchange) is a community platform where security
    researchers share threat indicators. If a URL is in a "pulse"
    (their term for a threat report), it might be suspicious.
    
    Returns: (list of hits, list of errors)
    """
    hits: List[IntelHit] = []
    errors: List[IntelError] = []
    
    if not url or not url.strip():
        return hits, errors
    
    api_key = os.environ.get('OTX_API_KEY')
    if not api_key:
        errors.append({'source': 'AlienVault OTX', 'message': 'No OTX API key configured'})
        return hits, errors
    
    # URL-encode the URL for the API path
    encoded_url = quote(url, safe='')
    endpoint = f'https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general'
    headers = {'X-OTX-API-KEY': api_key}
    
    try:
        response = requests.get(endpoint, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        pulses = data.get('pulse_info', {}).get('pulses', [])
        
        # Each pulse is a threat report that mentions this URL
        for pulse in pulses:
            name = pulse.get('name', 'OTX pulse')
            severity = pulse.get('severity', 'medium').lower()
            hits.append({
                'source': 'AlienVault OTX',
                'severity': severity,
                'description': f'Pulse match: {name}',
            })
            
    except requests.HTTPError as exc:
        errors.append({'source': 'AlienVault OTX', 'message': f'HTTP error: {exc}'})
    except requests.RequestException as exc:
        errors.append({'source': 'AlienVault OTX', 'message': f'Request failure: {exc}'})
    
    return hits, errors


def collect_threat_intel(url: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Aggregate threat intelligence from all available sources.
    
    We query each source and combine the results. If one source fails,
    we still report what we got from the others.
    
    Returns: {'hits': [...], 'errors': [...]}
    """
    hits: List[IntelHit] = []
    errors: List[IntelError] = []
    
    sources = [query_urlhaus, query_otx]
    
    for func in sources:
        source_hits, source_errors = func(url)
        hits.extend(source_hits)
        errors.extend(source_errors)
    
    return {'hits': hits, 'errors': errors}
