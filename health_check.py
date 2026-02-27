"""
health_check.py — Keeping Tabs on Our Dependencies

This module monitors the health of all our external services.
We check if they're responding, how fast they're responding,
and whether they're configured correctly.

Services we monitor:
- Google Safe Browsing API
- URLHaus API
- AlienVault OTX API
- DNS resolution
- WHOIS lookup capabilities

This powers the "System Status" widget on the homepage so users
can see if everything is working properly.
"""

import os
from typing import Dict, Any, List
import requests
import time
import socket
import dns.resolver
from datetime import datetime


HealthStatus = Dict[str, Any]


def check_safe_browsing_health() -> HealthStatus:
    """
    Check if Google Safe Browsing API is working.
    
    We ping their API with a test URL to make sure:
    - Our API key is valid
    - The API is responding
    - Response times are reasonable
    
    Returns health status dict.
    """
    api_key = os.environ.get('SAFE_BROWSING_API_KEY')
    start_time = time.time()
    
    # No API key configured
    if not api_key:
        return {
            'service': 'Google Safe Browsing',
            'status': 'down',
            'latency_ms': 0,
            'message': 'API key not configured in environment (required)',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    try:
        # Test the API with Google's test URL
        endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}'
        payload = {
            'client': {'clientId': 'safe-url-check', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': 'http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/'}]
            }
        }
        
        response = requests.post(endpoint, json=payload, timeout=5)
        latency = (time.time() - start_time) * 1000
        
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
            
    except requests.RequestException as exc:
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'Google Safe Browsing',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


def check_urlhaus_health() -> HealthStatus:
    """
    Check if URLHaus API is working.
    
    URLHaus now requires an API key, so we check:
    - Is the key configured?
    - Is the API responding?
    
    Returns health status dict.
    """
    api_key = os.environ.get('URLHAUS_API_KEY')
    start_time = time.time()
    
    if not api_key:
        return {
            'service': 'URLHaus',
            'status': 'down',
            'latency_ms': 0,
            'message': 'API key not configured in environment (required)',
            'timestamp': datetime.utcnow().isoformat()
        }

    try:
        endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'
        payload = {'url': 'http://example.com'}  # Test with clean URL
        headers = {
            'User-Agent': 'Safe-URL-Check/2.0 (https://github.com/WebbOfCode/Safe-URL-Check)',
            'Accept': 'application/json'
        }
        
        if api_key:
            headers['Auth-Key'] = api_key
        
        response = requests.post(endpoint, data=payload, headers=headers, timeout=5)
        latency = (time.time() - start_time) * 1000
        
        if response.status_code == 401:
            return {
                'service': 'URLHaus',
                'status': 'down',
                'latency_ms': round(latency, 2),
                'message': 'API key required (get free key at https://urlhaus.abuse.ch/api/)',
                'timestamp': datetime.utcnow().isoformat()
            }
        elif response.status_code == 200:
            data = response.json()
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
            
    except requests.RequestException as exc:
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'URLHaus',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


def check_otx_health() -> HealthStatus:
    """
    Check if AlienVault OTX API is working.
    
    OTX requires an API key. We test with a known URL.
    
    Returns health status dict.
    """
    api_key = os.environ.get('OTX_API_KEY')
    start_time = time.time()
    
    if not api_key:
        return {
            'service': 'AlienVault OTX',
            'status': 'down',
            'latency_ms': 0,
            'message': 'API key not configured in environment (required)',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    try:
        endpoint = 'https://otx.alienvault.com/api/v1/indicators/url/http%3A%2F%2Fexample.com/general'
        headers = {'X-OTX-API-KEY': api_key}
        
        response = requests.get(endpoint, headers=headers, timeout=5)
        latency = (time.time() - start_time) * 1000
        
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
            
    except requests.RequestException as exc:
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'AlienVault OTX',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'Connection failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


def check_dns_health() -> HealthStatus:
    """
    Check if DNS resolution is working.
    
    We try to resolve google.com as a basic connectivity test.
    If this fails, something is very wrong with the network.
    
    Returns health status dict.
    """
    start_time = time.time()
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        answers = resolver.resolve('google.com', 'A')
        latency = (time.time() - start_time) * 1000
        
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
            
    except Exception as exc:
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'DNS Resolution',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'DNS query failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


def check_whois_health() -> HealthStatus:
    """
    Check if WHOIS lookups are working.
    
    We try a WHOIS query on google.com as a test.
    
    Returns health status dict.
    """
    start_time = time.time()
    
    try:
        import whois
        result = whois.whois('google.com')
        latency = (time.time() - start_time) * 1000
        
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
            
    except Exception as exc:
        latency = (time.time() - start_time) * 1000
        return {
            'service': 'WHOIS Lookup',
            'status': 'down',
            'latency_ms': round(latency, 2),
            'message': f'WHOIS query failed: {str(exc)[:100]}',
            'timestamp': datetime.utcnow().isoformat()
        }


def get_all_health_status() -> List[HealthStatus]:
    """
    Run all health checks and return results.
    
    This is called by the homepage to populate the system status widget.
    
    Returns list of health status dicts, one per service.
    """
    health_statuses = []
    
    health_statuses.append(check_safe_browsing_health())
    health_statuses.append(check_urlhaus_health())
    health_statuses.append(check_otx_health())
    health_statuses.append(check_dns_health())
    health_statuses.append(check_whois_health())
    
    return health_statuses


def get_overall_health() -> Dict[str, Any]:
    """
    Calculate overall system health score.
    
    We count how many services are healthy vs total services,
then calculate a percentage. This gives users a quick overview
    of system status.
    
    Returns dict with overall status, percentage, and service details.
    """
    statuses = get_all_health_status()
    
    # Count healthy services
    healthy_count = sum(1 for s in statuses if s['status'] == 'healthy')
    total_services = len(statuses)
    health_percentage = (healthy_count / total_services * 100) if total_services > 0 else 0
    
    # Determine overall status label
    if health_percentage == 100:
        overall_status = 'healthy'
    elif health_percentage >= 75:
        overall_status = 'degraded'
    else:
        overall_status = 'critical'
    
    return {
        'overall_status': overall_status,
        'health_percentage': round(health_percentage, 1),
        'healthy_services': healthy_count,
        'total_services': total_services,
        'services': statuses,
        'timestamp': datetime.utcnow().isoformat()
    }
