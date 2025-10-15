# Import Flask framework and utilities for web application
from flask import Flask, render_template, request, redirect, url_for
# Import limiter class to enforce rate limits on endpoints
from flask_limiter import Limiter
# Import helper to derive client IP address for rate limiting
from flask_limiter.util import get_remote_address
# Import URL analysis function from scanners module
from scanners import analyze_url

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
    # Render and return the index.html template
    return render_template('index.html')


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


# Check if script is run directly (not imported)
if __name__ == '__main__':
    # Start Flask development server on all interfaces (0.0.0.0) port 5000 with debug mode enabled
    app.run(host='0.0.0.0', port=5000, debug=True)
