"""
Safe-URL-Check — Main Flask App

Real talk: this is the entry point. Everything starts here.
Routes handle the web stuff, templates do the HTML dance.

Built by Demarick because he was tired of sketchy links ruining his day.
"""

# Import Flask - it's like Express but for people who like Python
from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
from pathlib import Path

# Load env vars from .env file for local dev
# In production (Vercel), they handle this stuff for us
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.joinpath('.env')
    if env_path.exists():
        # Only load .env if it exists (dev mode vibes)
        load_dotenv(dotenv_path=env_path)
except Exception:
    # python-dotenv not installed? whatever, we ball
    pass

# Rate limiting - because some people can't have nice things
# Prevents the API from getting hammered by bots
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Our custom scanner - the brain of the operation
from scanners import analyze_url

# Health check module - keeps tabs on our external services
from health_check import get_all_health_status, get_overall_health

# Initialize Flask app
app = Flask(__name__)

# Set up rate limiter
# 60 requests/minute is plenty for normal use
# If someone's hitting us harder than that, probably sus
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["60 per minute"]
)


@app.get('/')
@limiter.exempt
def home():
    """Homepage - where the magic begins."""
    # Grab health status to show users our services are working
    health_status = get_overall_health()
    return render_template('index.html', health=health_status)


# Static pages - the legal stuff nobody reads but everyone needs
@app.get('/privacy')
@limiter.exempt
def privacy_page():
    """Privacy policy - we actually care about your data."""
    return render_template('privacy.html')


@app.get('/terms')
@limiter.exempt
def terms_page():
    """Terms of service - the fine print."""
    return render_template('terms.html')


@app.get('/security')
@limiter.exempt
def security_page():
    """Security page - how we keep things locked down."""
    return render_template('security.html')


# Health check endpoint - for monitoring/uptime checks
@app.get('/api/health')
@limiter.exempt
def api_health():
    """JSON health check - returns status of all our services."""
    health_data = get_overall_health()
    return jsonify(health_data)


# The main event - URL scanning endpoint
@app.post('/check')
@limiter.limit('10 per minute')  # Be nice to our servers
def check():
    """Scan a URL and return results. This is where the work happens."""
    # Grab URL from form data
    url = request.form.get('url', '').strip()
    
    # Basic validation - gotta have something to scan
    if not url:
        # User didn't give us a URL, send them back home
        return redirect(url_for('home'))
    
    # Run the analysis - this does ALL the heavy lifting
    result = analyze_url(url)
    
    # Render results page with our findings
    return render_template('result.html', url=url, result=result)


# Development server config
if __name__ == '__main__':
    # Grab config from environment or use sensible defaults
    host = os.environ.get('HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('PORT', '5000'))
    except ValueError:
        port = 5000  # fallback if someone puts garbage in PORT
    
    # Debug mode - only for local dev, NEVER in production
    debug = os.environ.get('FLASK_DEBUG', os.environ.get('DEBUG', '0')) in ('1', 'true', 'True')
    
    # Disable reloader by default - fixes Windows double-click weirdness
    use_reloader = os.environ.get('FLASK_RELOAD', '0') in ('1', 'true', 'True')
    
    # Fire it up!
    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=True)
