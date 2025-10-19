"""
threat_intel.py — Aggregate external threat intelligence sources

Sources supported:
- URLHaus (requires API key)
- AlienVault OTX (optional API key)

Each query function returns (hits, errors) to preserve transparency and
prevent a single source failure from breaking analysis.
"""

# Import os module to access environment variables for API keys
import os
# Import typing utilities for type annotations
from typing import Dict, List, Tuple
# Import url encoding helper for constructing API URLs
from urllib.parse import quote
# Import requests library for making HTTP requests
import requests


# Type alias for threat intelligence hit dictionaries
IntelHit = Dict[str, str]
# Type alias for threat intelligence errors
IntelError = Dict[str, str]
# Type alias for combined result tuple (hits list, errors list)
IntelResult = Tuple[List[IntelHit], List[IntelError]]


# Function to query the URLHaus public API for malicious URL intel
def query_urlhaus(url: str) -> IntelResult:
    # Initialize list that will store successful intelligence hits
    hits: List[IntelHit] = []
    # Initialize list that will store any errors encountered
    errors: List[IntelError] = []
    
    # Validate URL is not empty
    if not url or not url.strip():
        # Return empty results for invalid URLs without logging error
        return hits, errors
    
    # URLHaus API now requires authentication - check for API key
    api_key = os.environ.get('URLHAUS_API_KEY')
    
    # Define the endpoint for the URLHaus lookup API
    endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'
    # Create payload dictionary with target URL
    payload = {'url': url}
    # Prepare headers with User-Agent (required by URLHaus)
    headers = {
        'User-Agent': 'Safe-URL-Check/2.0 (https://github.com/WebbOfCode/Safe-URL-Check)',
        'Accept': 'application/json'
    }
    
    # Add API key to headers if configured
    if api_key:
        headers['Auth-Key'] = api_key
    
    # Try block to handle network operations safely
    try:
        # Issue POST request with headers and JSON response expected
        response = requests.post(endpoint, data=payload, headers=headers, timeout=10)
        
        # Check if we got 401 Unauthorized (API key required)
        if response.status_code == 401:
            # Log that URLHaus now requires API key
            errors.append({
                'source': 'URLHaus',
                'message': 'API key required (get free key at https://urlhaus.abuse.ch/api/)'
            })
            return hits, errors
        
        # Raise HTTPError for other non-successful status codes
        response.raise_for_status()
        # Parse JSON from the response body
        data = response.json()
        # Check whether the query completed successfully
        if data.get('query_status') == 'ok':
            # Extract threat signature name if present
            signature = data.get('threat', data.get('signature', 'Unknown threat'))
            # Extract URLHaus threat status value
            status = data.get('url_status', 'unknown')
            # Build hit dictionary with metadata
            hits.append({
                'source': 'URLHaus',
                'severity': 'high' if status.lower() == 'online' else 'medium',
                'description': f'URL flagged by URLHaus ({signature})',
            })
        # Handle case where the URL was not found in database
        elif data.get('query_status') == 'no_results':
            # No action needed because query simply has no hits
            pass
        # For any other status treat as an error condition
        else:
            # Append dictionary describing the error encountered
            errors.append({'source': 'URLHaus', 'message': f"Unexpected response: {data.get('query_status', 'unknown')}"})
    # Catch HTTP error responses
    except requests.HTTPError as exc:
        # Append error description for logging and downstream display
        errors.append({'source': 'URLHaus', 'message': f'HTTP error: {exc}'})
    # Catch any other request related exceptions such as timeouts
    except requests.RequestException as exc:
        # Append network error details to error list
        errors.append({'source': 'URLHaus', 'message': f'Request failure: {exc}'})
    # Return tuple containing list of hits and list of errors
    return hits, errors


# Function to query AlienVault OTX URL reputation API if configured
def query_otx(url: str) -> IntelResult:
    # Initialize list for storing intelligence hits
    hits: List[IntelHit] = []
    # Initialize list for storing encountered errors
    errors: List[IntelError] = []
    
    # Validate URL is not empty
    if not url or not url.strip():
        # Return empty results for invalid URLs without logging error
        return hits, errors
    
    # Retrieve API key from environment variables
    api_key = os.environ.get('OTX_API_KEY')
    # If no API key configured then exit early with configuration notice
    if not api_key:
        # Append configuration error warning but do not treat as hard failure
        errors.append({'source': 'AlienVault OTX', 'message': 'No OTX API key configured'})
        # Return empty hits with configuration error message
        return hits, errors
    # Safely encode the URL for inclusion in the API route
    encoded_url = quote(url, safe='')
    # Construct complete API endpoint for URL general info
    endpoint = f'https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general'
    # Prepare HTTP headers including API key for authentication
    headers = {'X-OTX-API-KEY': api_key}
    # Try block to handle network request operations
    try:
        # Send GET request with headers and timeout control
        response = requests.get(endpoint, headers=headers, timeout=10)
        # Raise HTTPError for unsuccessful status codes
        response.raise_for_status()
        # Parse JSON payload from response
        data = response.json()
        # Extract general pulse info array containing threat data
        pulses = data.get('pulse_info', {}).get('pulses', [])
        # Iterate through pulses returned by OTX
        for pulse in pulses:
            # Extract pulse name for description context
            name = pulse.get('name', 'OTX pulse')
            # Extract pulse threat indicator severity level
            severity = pulse.get('severity', 'medium')
            # Normalize severity to lower case for consistent handling
            normalized = severity.lower()
            # Append hit dictionary describing the intelligence finding
            hits.append({
                'source': 'AlienVault OTX',
                'severity': normalized,
                'description': f'Pulse match: {name}',
            })
    # Handle HTTP level errors explicitly
    except requests.HTTPError as exc:
        # Append error dictionary containing details
        errors.append({'source': 'AlienVault OTX', 'message': f'HTTP error: {exc}'})
    # Handle generic request exceptions (timeouts, connection errors, etc.)
    except requests.RequestException as exc:
        # Append error dictionary with associated message
        errors.append({'source': 'AlienVault OTX', 'message': f'Request failure: {exc}'})
    # Return tuple with list of hits and list of errors
    return hits, errors


# Function to aggregate intelligence from all configured sources
def collect_threat_intel(url: str) -> Dict[str, List[Dict[str, str]]]:
    # Initialize list to accumulate all intelligence hits
    hits: List[IntelHit] = []
    # Initialize list to accumulate all errors generated
    errors: List[IntelError] = []
    # Define list of source query functions to execute sequentially
    sources = [query_urlhaus, query_otx]
    # Iterate over each intelligence source function
    for func in sources:
        # Try to gather hits and errors from the current source
        source_hits, source_errors = func(url)
        # Extend global list with source specific hits
        hits.extend(source_hits)
        # Extend global list with source specific errors
        errors.extend(source_errors)
    # Return dictionary containing combined hits and errors
    return {'hits': hits, 'errors': errors}
