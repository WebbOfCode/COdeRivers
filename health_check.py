"""
health_check.py — Service health probes and overall status aggregation

Endpoints probed (where configured):
- Google Safe Browsing
- URLHaus
- AlienVault OTX
- DNS resolution
- WHOIS lookup

Exports:
- get_all_health_status(): list of per-service status dicts
- get_overall_health(): computed rollup used by UI and /api/health
"""

# Import os module to access environment variables
import os
# Import typing utilities for type annotations
from typing import Dict, Any, List
# Import requests library for making HTTP requests to test APIs
import requests
# Import time module for measuring response times
import time
# Import socket for DNS resolution testing
import socket
# Import dns resolver for testing DNS APIs
import dns.resolver
# Import datetime for timestamp tracking
from datetime import datetime


# Type alias for health status dictionaries
HealthStatus = Dict[str, Any]


# Function to check Google Safe Browsing API health
def check_safe_browsing_health() -> HealthStatus:
    """Test if Google Safe Browsing API is accessible and responding correctly.
    
    Returns dictionary with status, latency, and any error messages.
    """
    # Get API key from environment
    api_key = os.environ.get('SAFE_BROWSING_API_KEY')
    # Start timer to measure response time
    start_time = time.time()
    
    # If no API key configured
    if not api_key:
        return {
            'service': 'Google Safe Browsing',
            'status': 'unconfigured',
            'latency_ms': 0,
            'message': 'API key not configured in environment',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Try to ping the Safe Browsing API with a test URL
    try:
        # Construct API endpoint URL
        endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        # Create minimal test payload
        payload = {
            'client': {'clientId': 'safe-url-check', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': 'http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/'}]
            }
        }
        # Send POST request to API with timeout
        response = requests.post(endpoint, json=payload, timeout=5)
        # Calculate elapsed time in milliseconds
        latency = (time.time() - start_time) * 1000
        
        # Check if request was successful
        if response.status_code == 200:
            return {
                'service': 'Google Safe Browsing',
                'status': 'healthy',
                'latency_ms': round(latency, 2),
                'message': 'API responding correctly',
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            return {
                'service': 'Google Safe Browsing',
                'status': 'degraded',
                'latency_ms': round(latency, 2),
                'message': f'HTTP {response.status_code}: {response.text[:100]}',
                'timestamp': datetime.utcnow().isoformat()
            }
    # Catch request errors
    except requests.RequestException as exc:
        # Calculate elapsed time even for failures
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'Google Safe Browsing',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Function to check URLHaus API health
def check_urlhaus_health() -> HealthStatus:
    """Test if URLHaus API is accessible and responding correctly.
    
    Returns dictionary with status, latency, and any error messages.
    """
    # Get API key from environment (now required by URLHaus)
    api_key = os.environ.get('URLHAUS_API_KEY')
    # Start timer to measure response time
    start_time = time.time()
    
    # Try to ping the URLHaus API with a test URL
    try:
        # Define the endpoint for the URLHaus lookup API
        endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'
        # Create test payload with known clean URL
        payload = {'url': 'http://example.com'}
        # Prepare headers with User-Agent (required) and optional API key
        headers = {
            'User-Agent': 'Safe-URL-Check/2.0 (https://github.com/WebbOfCode/Safe-URL-Check)',
            'Accept': 'application/json'
        }
        
        # Add API key if configured
        if api_key:
            headers['Auth-Key'] = api_key
        
        # Send POST request to API with timeout
        response = requests.post(endpoint, data=payload, headers=headers, timeout=5)
        # Calculate elapsed time in milliseconds
        latency = (time.time() - start_time) * 1000
        
        # Check if we got 401 (API key required but not provided)
        if response.status_code == 401:
            return {
                'service': 'URLHaus',
                'status': 'unconfigured',
                'latency_ms': round(latency, 2),
                'message': 'API key required (get free key at https://urlhaus.abuse.ch/api/)',
                'timestamp': datetime.utcnow().isoformat()
            }
        # Check if request was successful
        elif response.status_code == 200:
            # Parse response to verify format
            data = response.json()
            # Verify query_status field exists
            if 'query_status' in data:
                return {
                    'service': 'URLHaus',
                    'status': 'healthy',
                    'latency_ms': round(latency, 2),
                    'message': 'API responding correctly',
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'service': 'URLHaus',
                    'status': 'degraded',
                    'latency_ms': round(latency, 2),
                    'message': 'Unexpected response format',
                    'timestamp': datetime.utcnow().isoformat()
                }
        else:
            return {
                'service': 'URLHaus',
                'status': 'degraded',
                'latency_ms': round(latency, 2),
                'message': f'HTTP {response.status_code}',
                'timestamp': datetime.utcnow().isoformat()
            }
    # Catch request errors
    except requests.RequestException as exc:
        # Calculate elapsed time even for failures
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'URLHaus',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Function to check AlienVault OTX API health
def check_otx_health() -> HealthStatus:
    """Test if AlienVault OTX API is accessible and responding correctly.
    
    Returns dictionary with status, latency, and any error messages.
    """
    # Get API key from environment
    api_key = os.environ.get('OTX_API_KEY')
    # Start timer to measure response time
    start_time = time.time()
    
    # If no API key configured
    if not api_key:
        return {
            'service': 'AlienVault OTX',
            'status': 'unconfigured',
            'latency_ms': 0,
            'message': 'API key not configured (optional)',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Try to ping the OTX API
    try:
        # Construct API endpoint for general info
        endpoint = 'https://otx.alienvault.com/api/v1/indicators/url/http%3A%2F%2Fexample.com/general'
        # Prepare HTTP headers including API key
        headers = {'X-OTX-API-KEY': api_key}
        # Send GET request with headers and timeout
        response = requests.get(endpoint, headers=headers, timeout=5)
        # Calculate elapsed time in milliseconds
        latency = (time.time() - start_time) * 1000
        
        # Check if request was successful
        if response.status_code == 200:
            return {
                'service': 'AlienVault OTX',
                'status': 'healthy',
                'latency_ms': round(latency, 2),
                'message': 'API responding correctly',
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            return {
                'service': 'AlienVault OTX',
                'status': 'degraded',
                'latency_ms': round(latency, 2),
                'message': f'HTTP {response.status_code}',
                'timestamp': datetime.utcnow().isoformat()
            }
    # Catch request errors
    except requests.RequestException as exc:
        # Calculate elapsed time even for failures
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'AlienVault OTX',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Function to check DNS resolution capabilities
def check_dns_health() -> HealthStatus:
    """Test if DNS resolution is working correctly.
    
    Returns dictionary with status, latency, and any error messages.
    """
    # Start timer to measure response time
    start_time = time.time()
    
    # Try to resolve a known domain
    try:
        # Create resolver instance
        resolver = dns.resolver.Resolver()
        # Set timeout for DNS query
        resolver.timeout = 3
        resolver.lifetime = 3
        # Query A records for a reliable domain
        answers = resolver.resolve('google.com', 'A')
        # Calculate elapsed time in milliseconds
        latency = (time.time() - start_time) * 1000
        
        # Check if we got results
        if answers:
            return {
                'service': 'DNS Resolution',
                'status': 'healthy',
                'latency_ms': round(latency, 2),
                'message': f'DNS working correctly ({len(answers)} records)',
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            return {
                'service': 'DNS Resolution',
                'status': 'degraded',
                'latency_ms': round(latency, 2),
                'message': 'No DNS records returned',
                'timestamp': datetime.utcnow().isoformat()
            }
    # Catch DNS errors
    except Exception as exc:
        # Calculate elapsed time even for failures
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'DNS Resolution',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'DNS query failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Function to check WHOIS lookup capabilities
def check_whois_health() -> HealthStatus:
    """Test if WHOIS queries are working correctly.
    
    Returns dictionary with status, latency, and any error messages.
    """
    # Start timer to measure response time
    start_time = time.time()
    
    # Try to perform WHOIS lookup on a known domain
    try:
        # Import whois library
        import whois
        # Query WHOIS for a reliable domain
        result = whois.whois('google.com')
        # Calculate elapsed time in milliseconds
        latency = (time.time() - start_time) * 1000
        
        # Check if we got valid results
        if result and hasattr(result, 'domain_name'):
            return {
                'service': 'WHOIS Lookup',
                'status': 'healthy',
                'latency_ms': round(latency, 2),
                'message': 'WHOIS queries working correctly',
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            return {
                'service': 'WHOIS Lookup',
                'status': 'degraded',
                'latency_ms': round(latency, 2),
                'message': 'Incomplete WHOIS data returned',
                'timestamp': datetime.utcnow().isoformat()
            }
    # Catch WHOIS errors
    except Exception as exc:
        # Calculate elapsed time even for failures
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'WHOIS Lookup',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'WHOIS query failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


# Main function to get health status of all services
def get_all_health_status() -> List[HealthStatus]:
    """Run health checks on all external services and return status list.
    
    Returns list of health status dictionaries for each service.
    """
    # Create list to store all health statuses
    health_statuses = []
    
    # Check Google Safe Browsing API
    health_statuses.append(check_safe_browsing_health())
    
    # Check URLHaus API
    health_statuses.append(check_urlhaus_health())
    
    # Check AlienVault OTX API
    health_statuses.append(check_otx_health())
    
    # Check DNS resolution
    health_statuses.append(check_dns_health())
    
    # Check WHOIS lookup
    health_statuses.append(check_whois_health())
    
    # Return complete list of health statuses
    return health_statuses


# Function to calculate overall system health score
def get_overall_health() -> Dict[str, Any]:
    """Calculate overall system health based on all service statuses.
    
    Returns dictionary with overall status, percentage, and service breakdown.
    """
    # Get all individual health statuses
    statuses = get_all_health_status()
    
    # Count services by status
    healthy_count = sum(1 for s in statuses if s['status'] == 'healthy')
    total_services = len(statuses)
    unconfigured_count = sum(1 for s in statuses if s['status'] == 'unconfigured')
    
    # Calculate health percentage (excluding unconfigured services)
    active_services = total_services - unconfigured_count
    health_percentage = (healthy_count / active_services * 100) if active_services > 0 else 0
    
    # Determine overall status
    if health_percentage == 100:
        overall_status = 'healthy'
    elif health_percentage >= 75:
        overall_status = 'degraded'
    else:
        overall_status = 'critical'
    
    # Return comprehensive health report
    return {
        'overall_status': overall_status,
        'health_percentage': round(health_percentage, 1),
        'healthy_services': healthy_count,
        'total_services': active_services,
        'services': statuses,
        'timestamp': datetime.utcnow().isoformat()
    }
