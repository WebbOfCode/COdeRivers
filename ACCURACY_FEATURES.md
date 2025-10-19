# Safe URL Check - Enhanced Accuracy & API Health Monitoring

## 🎯 New Features

### API Health Dashboard
Real-time monitoring of all external services with live status indicators:
- **Google Safe Browsing API** - Threat database lookups
- **URLHaus API** - Malware URL intelligence
- **AlienVault OTX** - Open threat exchange (optional)
- **DNS Resolution** - Domain name system queries
- **WHOIS Lookup** - Domain registration data

**Health Status Levels:**
- ✅ **Healthy** - Service operational (green indicator)
- ⚠️ **Degraded** - Service responding slowly (yellow indicator)
- ❌ **Down** - Service unavailable (red indicator)
- ○ **Unconfigured** - Optional service not configured (gray indicator)

Access the health dashboard:
- **Visual Widget**: Homepage displays live status of all services
- **API Endpoint**: `GET /api/health` returns JSON health data

### Enhanced Accuracy Features

#### 1. SSL Certificate Validation
- Verifies HTTPS certificate validity
- Checks expiration dates (warns if <30 days remaining)
- Validates certificate issuer
- **Impact**: Expired/invalid certificates add 15-40 risk points

#### 2. HTTP Security Headers Analysis
- Checks for security headers (HSTS, CSP, X-Frame-Options, etc.)
- Detects excessive redirects (>3 hops)
- Identifies cross-domain redirects
- Flags outdated server software
- **Impact**: Missing headers add 2-18 risk points

#### 3. Page Content Analysis
- Inspects HTML for phishing patterns
- Detects password forms submitting to external domains (+35 points)
- Identifies suspicious iframes and obfuscated JavaScript (+12-20 points)
- Checks for brand impersonation in page titles (+25 points)
- Analyzes form structures and input fields

#### 4. Domain Reputation Checks
- Detects parked domains
- Cross-references multiple reputation databases
- Identifies domain parking indicators (+15 points)

## 📊 Accuracy Improvements

**Multi-Layer Verification:**
1. **Heuristic Analysis** - URL patterns, keywords, structure
2. **DNS/WHOIS Validation** - Domain age, MX records, SPF
3. **Threat Intelligence** - Safe Browsing, URLHaus, OTX
4. **SSL/TLS Verification** - Certificate validity and expiration
5. **HTTP Security** - Headers, redirects, server info
6. **Content Inspection** - HTML forms, scripts, iframes
7. **Reputation Scoring** - Domain parking, brand impersonation

**Enhanced Score Calculation:**
- Combines all verification layers
- Non-linear aggregation prevents false positives
- Positive findings (valid SSL, good headers) reduce risk score
- Negative findings (phishing patterns, expired certs) increase risk
- Transparent breakdown shows exact contribution of each check

## 🚀 Usage

### Health Monitoring
```python
from health_check import get_overall_health

# Get comprehensive health report
health = get_overall_health()
print(f"System Health: {health['health_percentage']}%")
print(f"Status: {health['overall_status']}")

# Check individual services
for service in health['services']:
    print(f"{service['service']}: {service['status']} ({service['latency_ms']}ms)")
```

### Enhanced URL Analysis
```python
from scanners import analyze_url

# Analyze URL with all enhanced checks
result = analyze_url('https://example.com')

# Access enhanced verification results
enhanced = result.get('enhanced_checks', {})
print(f"SSL Status: {enhanced.get('ssl_certificate', {}).get('message')}")
print(f"Content Indicators: {enhanced.get('page_content', {}).get('indicators')}")
print(f"Total Enhanced Impact: {enhanced.get('total_score_impact')} points")
```

## 🔧 Configuration

### Required Environment Variables
```bash
SAFE_BROWSING_API_KEY=your_google_api_key_here
```

### Optional Environment Variables
```bash
OTX_API_KEY=your_alienvault_otx_key_here  # Optional threat intelligence
```

### Installation
```bash
# Install new dependencies
pip install -r requirements.txt

# New packages added:
# - beautifulsoup4>=4.12.0  (for HTML content analysis)
```

## 📈 Performance

**Health Check Timing:**
- Each service check: 3-5 seconds timeout
- Parallel execution for all services
- Cached on homepage (refresh to update)

**Enhanced Verification:**
- SSL check: ~1 second
- HTTP headers: ~2 seconds
- Content analysis: ~3-8 seconds (downloads HTML)
- Domain reputation: ~2 seconds
- Total additional time: 8-15 seconds per scan

**Optimization:**
- Enhanced checks run in parallel when possible
- Errors don't block other checks
- Timeouts prevent hanging requests
- Failed checks don't affect other verification layers

## 🛡️ Accuracy Metrics

**Before Enhancement:**
- 7 heuristic checks
- 3 DNS/WHOIS checks
- 3 threat intelligence sources
- **Total: 13 verification points**

**After Enhancement:**
- 7 heuristic checks
- 3 DNS/WHOIS checks
- 3 threat intelligence sources
- SSL certificate validation
- HTTP security headers (4 checks)
- Content analysis (4 pattern types)
- Domain reputation checks
- **Total: 22+ verification points**

**Accuracy Improvement:**
- 69% more verification layers
- Reduced false positives via multi-layer consensus
- Better detection of sophisticated phishing (SSL, content analysis)
- Real-time service health prevents silent failures

## 📝 API Response Format

### Health Endpoint (`/api/health`)
```json
{
  "overall_status": "healthy",
  "health_percentage": 100.0,
  "healthy_services": 4,
  "total_services": 4,
  "timestamp": "2025-10-19T12:34:56.789Z",
  "services": [
    {
      "service": "Google Safe Browsing",
      "status": "healthy",
      "latency_ms": 234.56,
      "message": "API responding correctly",
      "timestamp": "2025-10-19T12:34:56.789Z"
    }
  ]
}
```

### Enhanced Check Result
```json
{
  "score": 45,
  "reasons": [...],
  "suggested_action": "Use extreme caution",
  "breakdown": [...],
  "enhanced_checks": {
    "total_score_impact": 12,
    "checks_performed": ["SSL Certificate Validation", "HTTP Security Headers", ...],
    "ssl_certificate": {
      "valid": true,
      "score_impact": -5,
      "message": "Valid SSL certificate",
      "details": {
        "expires": "2026-01-15T00:00:00",
        "days_remaining": 88
      }
    },
    "http_headers": {
      "score_impact": 8,
      "messages": ["Missing security headers: HSTS, CSP"],
      "missing_headers": [...]
    }
  }
}
```

## 🎨 UI Components

**Health Widget** (Homepage):
- Displays overall system health percentage
- Color-coded status badge (green/yellow/red)
- Individual service indicators with latency
- Real-time status updates
- Responsive mobile design

**Enhanced Results** (Scan page):
- SSL certificate details
- HTTP security findings
- Content analysis warnings
- Domain reputation score
- Comprehensive breakdown table

## 🔒 Security & Privacy

**Health Monitoring:**
- No user data transmitted
- Only test queries to external APIs
- Latency measurements for performance
- No logging of health check results

**Enhanced Checks:**
- SSL validation uses Python's SSL module
- HTTP requests respect robots.txt
- Content downloads limited to 5MB
- No JavaScript execution (static HTML parsing only)
- Timeout protection on all network calls

## 📚 Error Handling

All enhanced checks include graceful degradation:
- SSL check fails → No penalty, continues with other checks
- Content unavailable → Analysis proceeds without it
- API timeout → Logged as informational, doesn't affect score
- Parse errors → Caught and reported without failing entire scan

**Transparency:** All errors displayed to user in breakdown section

## 🎯 Next Steps

**Future Enhancements:**
1. Machine learning-based scoring
2. Historical threat intelligence
3. Screenshot-based visual analysis
4. Real-time URL sandboxing
5. Blockchain domain verification
6. Social media reputation signals

---

**Version:** 2.0.0  
**Last Updated:** October 19, 2025  
**Maintained by:** Demarick Webb Rivera
