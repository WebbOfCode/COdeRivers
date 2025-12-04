# Safe URL Check - Project Overview

## 🎯 What This Project Does

**Safe URL Check** is a phishing detection web application that analyzes URLs to determine if they're potentially malicious or safe to visit. It's a Flask-based web application that combines multiple layers of verification to provide comprehensive URL safety analysis.

## 📊 Project Statistics

- **Total Lines of Code**: ~2,173 lines (Python, SQL, Markdown)
- **Main Technology**: Python 3.9+ with Flask web framework
- **Architecture**: Multi-layer verification system with external API integrations
- **Current Version**: 2.0.0 (with enhanced accuracy features)
- **Last Updated**: October 19, 2025

## 🏗️ Architecture Overview

### Core Components

1. **Web Application Layer** (`app.py`)
   - Flask-based web server
   - Rate limiting (60 requests/minute, 10/minute for scans)
   - REST API endpoints for scanning and health monitoring
   - Serves static pages (privacy, terms, security)

2. **URL Analysis Engine** (`scanners.py`)
   - Main analysis pipeline coordinating all verification layers
   - Heuristic pattern detection
   - Non-linear score aggregation (0-100 risk score)
   - Integration point for all scanning modules

3. **External Integrations** (`integrations.py`)
   - Google Safe Browsing API (malware/phishing detection)
   - DNS resolution (MX, SPF records)
   - WHOIS lookups (domain registration data)

4. **Threat Intelligence** (`threat_intel.py`)
   - URLHaus API integration (malware URL database)
   - AlienVault OTX integration (open threat exchange)
   - Aggregates hits from multiple threat feeds

5. **Enhanced Accuracy Checks** (`accuracy_enhancements.py`)
   - SSL/TLS certificate validation
   - HTTP security headers analysis
   - Page content inspection for phishing patterns
   - Domain reputation checking

6. **AI Content Analyzer** (`ai_analyzer.py`)
   - Heuristic-based content analysis
   - Form and script pattern detection
   - Brand impersonation detection
   - Social engineering phrase detection

7. **Health Monitoring** (`health_check.py`)
   - Real-time API health checks
   - Service latency measurement
   - Overall system health aggregation
   - Status dashboard on homepage

## 🔍 How URL Analysis Works

When a user submits a URL, the system performs **7 layers of verification**:

### Layer 1: Heuristic Analysis
- IP address detection (+45 points)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq) (+28 points)
- URL length check (+12 points if >100 chars)
- Suspicious keywords (login, secure, bank, etc.) (+22 points)
- Subdomain complexity (+7 points if 3+ levels)

### Layer 2: DNS/WHOIS Validation
- MX records check (+12 points if missing)
- SPF record check (+6 points if missing)
- WHOIS data validation (+8 points if missing/protected)

### Layer 3: Threat Intelligence
- **Google Safe Browsing**: Checks against Google's threat database (+70 points if flagged)
- **URLHaus**: Malware URL database lookup (20-65 points based on severity)
- **AlienVault OTX**: Open threat exchange pulses (20-65 points based on severity)

### Layer 4: SSL/TLS Verification
- Certificate validity check
- Expiration date monitoring (+15-40 points if expired/expiring)
- Issuer validation
- Valid certificates reduce risk score (-5 points)

### Layer 5: HTTP Security Analysis
- Security headers (HSTS, CSP, X-Frame-Options) (+2-8 points if missing)
- Redirect chain detection (+12 points if >3 hops)
- Cross-domain redirect detection (+18 points)
- Server software version check (+10 points if outdated)

### Layer 6: Content Inspection
- Password forms to external domains (+35 points)
- Multiple external iframes (+12 points)
- Obfuscated JavaScript patterns (+20 points)
- Brand impersonation in page title (+25 points)
- Form structure analysis

### Layer 7: AI Content Analysis
- Credential harvesting form detection (+18-35 points)
- Urgent/social engineering language (+8-18 points)
- Brand impersonation detection (+28 points)
- Link shortener usage (+20 points)
- Obfuscated scripts (+10-20 points)

## 🎨 User Interface

### Pages Available

1. **Homepage** (`/`)
   - Hero section with branding
   - URL scanning form
   - Live system health widget
   - Feature highlights
   - Links to privacy/terms/security pages

2. **Results Page** (`/check`)
   - Risk score (0-100) with color coding
   - Suggested action based on score
   - Detailed breakdown by category
   - Enhanced verification results
   - Threat intelligence hits
   - AI analysis summary

3. **API Health Endpoint** (`/api/health`)
   - JSON response with system status
   - Service-by-service health breakdown
   - Latency metrics
   - Overall health percentage

4. **Static Pages**
   - Privacy Policy (`/privacy`)
   - Terms of Service (`/terms`)
   - Security Information (`/security`)

## 🔧 Technical Stack

### Backend Dependencies
- **Flask 3.1.2+**: Web framework
- **requests 2.0.0+**: HTTP client for API calls
- **dnspython 2.4.2+**: DNS resolution
- **python-whois 0.7.3+**: WHOIS lookups
- **flask-limiter 3.7.0+**: Rate limiting
- **beautifulsoup4 4.12.0+**: HTML parsing for content analysis

### Frontend
- HTML5 templates with Jinja2
- Custom CSS styling (`static/style.css`)
- Responsive design
- SVG logo (`static/logo.svg`)
- Google Fonts (Montserrat)

## 📈 Scoring System

### Risk Score Ranges
- **0-19**: Likely safe, but remain vigilant
- **20-44**: Proceed carefully — mixed signals found
- **45-69**: Use extreme caution — suspicious indicators present
- **70-100**: Do not visit — very high risk

### Score Calculation
Uses **non-linear aggregation** with diminishing returns:
```python
score = 100 * (1 - exp(-raw_sum / 60.0))
```

This prevents single indicators from dominating the score and reduces false positives.

## 🔐 Security Features

### Rate Limiting
- General endpoints: 60 requests/minute
- Scan endpoint: 10 requests/minute per IP
- Prevents abuse and DoS attacks

### Privacy
- No personal data storage
- No URL logging
- API health checks use test queries only
- No JavaScript execution during analysis

### External API Requirements
All external APIs now **require authentication**:
- **SAFE_BROWSING_API_KEY**: Required (Google Safe Browsing)
- **URLHAUS_API_KEY**: Required (URLHaus)
- **OTX_API_KEY**: Required (AlienVault OTX)

## 🚀 How to Run

### Windows (Recommended)
```bash
# Double-click start.bat or run:
start.bat
```

The startup script will:
1. Create a Python virtual environment
2. Install all dependencies
3. Load .env configuration
4. Start the Flask server on http://127.0.0.1:5000

### Manual Setup
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Edit .env with your API keys

# Run the application
python app.py
```

## 📁 File Structure

```
COdeRivers/
├── app.py                      # Flask application entry point
├── scanners.py                 # Core URL analysis pipeline
├── integrations.py             # DNS, WHOIS, Safe Browsing
├── threat_intel.py             # URLHaus, OTX integrations
├── accuracy_enhancements.py    # SSL, headers, content checks
├── ai_analyzer.py              # AI-style content analysis
├── health_check.py             # API health monitoring
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
├── start.bat                   # Windows startup script
├── README.md                   # Brief project description
├── ACCURACY_FEATURES.md        # Detailed feature documentation
├── static/
│   ├── style.css              # Application styling
│   └── logo.svg               # Brand logo
├── templates/
│   ├── index.html             # Homepage
│   ├── result.html            # Scan results page
│   ├── privacy.html           # Privacy policy
│   ├── terms.html             # Terms of service
│   └── security.html          # Security information
├── models.sql                 # Database schema (if used)
└── seed.sql                   # Database seed data (if used)
```

## 🎯 Key Features Summary

### Accuracy Enhancements (69% more verification points)
- **Before**: 13 verification points
- **After**: 22+ verification points

### Multi-Source Verification
- 3 threat intelligence sources
- 5 external service checks
- 7 analysis layers
- AI-powered content inspection

### Real-Time Health Monitoring
- Live service status indicators
- Latency measurements
- Health percentage calculation
- Automatic degradation detection

### User Experience
- Clean, modern interface
- Instant results
- Detailed breakdowns
- Mobile-responsive design
- No registration required

## 🔮 Future Enhancements (Planned)

1. Machine learning-based scoring
2. Historical threat intelligence
3. Screenshot-based visual analysis
4. Real-time URL sandboxing
5. Blockchain domain verification
6. Social media reputation signals

## 👤 Maintenance

**Maintained by**: Demarick Webb Rivera  
**Repository**: WebbOfCode/COdeRivers  
**Project Name**: Safe-URL-Check (also known as "Phishing URL Checker")

## 📝 Recent Changes

The most recent commit shows that API usage was fixed and made required. Previously, some APIs were optional, but now:
- Google Safe Browsing API is required
- URLHaus API is required
- AlienVault OTX API is required
- DNS and WHOIS services are always checked

All services are now considered critical for system health monitoring.

## 🎓 Educational Value

This project demonstrates:
- Multi-layer security analysis
- API integration patterns
- Web application security best practices
- Rate limiting implementation
- Health monitoring systems
- Content analysis techniques
- Non-linear scoring algorithms
- Graceful error handling
- RESTful API design

## 🌟 Strengths

1. **Comprehensive Analysis**: 7 layers of verification with 22+ checkpoints
2. **Real-Time Monitoring**: Live health dashboard for all services
3. **User-Friendly**: Simple interface, clear results
4. **Well-Documented**: Extensive inline comments and documentation
5. **Security-Conscious**: Rate limiting, no data storage, privacy-focused
6. **Modular Design**: Clean separation of concerns
7. **Error Handling**: Graceful degradation when services fail
8. **Transparent**: Shows exactly what was checked and why

## 📌 Current Status

The project is in a **production-ready state** with:
- ✅ Working core functionality
- ✅ All verification layers operational
- ✅ Health monitoring implemented
- ✅ UI/UX polished
- ✅ Documentation complete
- ⚠️ Requires API keys to be configured
- ⚠️ All external APIs now mandatory (not optional)

The application is ready to be deployed and used for URL safety analysis once the required API keys are configured in the `.env` file.
