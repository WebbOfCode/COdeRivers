"""
Safe-URL-Check — Flask application entry point

Routes:
- GET /            : Landing page with scanner form and health widget
- GET /api/health  : JSON health summary for external monitoring
- POST /check      : Runs analysis pipeline and renders result view

This file wires HTTP routes to scanner logic and templates.
"""

# Import Flask framework and utilities for web application
from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
# Import limiter class to enforce rate limits on endpoints
from flask_limiter import Limiter
# Import helper to derive client IP address for rate limiting
from flask_limiter.util import get_remote_address
# Import URL analysis function from scanners module
from scanners import analyze_url
# Import health monitoring functions
from health_check import get_all_health_status, get_overall_health

# Create Flask application instance
app = Flask(__name__)
# Configure rate limiter to protect /check endpoint from abuse
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["60 per minute"]
)


# Route handler for homepage (GET request)
@app.get('/')
@limiter.exempt
def home():
    # Get API health status for display on homepage
    health_status = get_overall_health()
    # Render and return the index.html template with health data
    return render_template('index.html', health=health_status)


# Static informational pages — Privacy, Terms, Security
@app.get('/privacy')
@limiter.exempt
def privacy_page():
    """Render Privacy Policy with optional metadata."""
    return render_template('privacy.html')


@app.get('/terms')
@limiter.exempt
def terms_page():
    """Render Terms of Service."""
    return render_template('terms.html')


@app.get('/security')
@limiter.exempt
def security_page():
    """Render Security page."""
    return render_template('security.html')


# Route handler for health check API endpoint (GET request)
@app.get('/api/health')
@limiter.exempt
def api_health():
    # Get comprehensive health status
    health_data = get_overall_health()
    # Return health data as JSON
    return jsonify(health_data)


# Route handler for URL checking (POST request)
@app.post('/check')
@limiter.limit('10 per minute')
def check():
    # Get URL from form data, default to empty string, strip whitespace
    url = request.form.get('url', '').strip()
    # If URL is empty after stripping
    if not url:
        # Redirect user back to homepage
        return redirect(url_for('home'))
    # Analyze the URL using the scanner function
    result = analyze_url(url)
    # Render result page with URL and analysis results
    return render_template('result.html', url=url, result=result)


# Development entry point (when executed directly)
if __name__ == '__main__':
    # Configurable host/port/debug with safe defaults; disable reloader to prevent batch window closing
    host = os.environ.get('HOST', '0.0.0.0')
    try:
        port = int(os.environ.get('PORT', '5000'))
    except ValueError:
        port = 5000
    debug = os.environ.get('FLASK_DEBUG', os.environ.get('DEBUG', '0')) in ('1', 'true', 'True')
    # Disable the Werkzeug reloader by default to avoid parent process exit on Windows double-click
    use_reloader = os.environ.get('FLASK_RELOAD', '0') in ('1', 'true', 'True')
    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=True)
