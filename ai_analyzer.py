"""
ai_analyzer.py — Content Analysis That Isn't Actually AI

Yeah, the name says "AI" but it's really just smart pattern matching.
We download the page, look at the HTML, and check for sketchy stuff.

What we look for:
- Forms that send passwords to weird places
- Brand impersonation ("PayPal" on not-paypal.com)
- Urgent language ("ACT NOW OR YOUR ACCOUNT WILL BE DELETED!!!")
- Obfuscated JavaScript (why you hiding, script?)
- URL shorteners (where does this actually go?)

No neural networks here, just good old-fashioned regex and common sense.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


# Version tracking - because we actually maintain this thing
ANALYZER_VERSION = "2025.10.19"

# User agent - be polite, identify ourselves
USER_AGENT = "Safe-URL-Check/2.0 (+https://github.com/WebbOfCode/Safe-URL-Check)"

# Don't download the whole internet, just enough to analyze
MAX_HTML_CHARS = 350_000

# Words that make us go "hmm..." when we see them on a page
SUSPICIOUS_TERMS = {
    "login",
    "signin",
    "password",
    "banking",
    "verify",
    "account",
    "confirm",
    "secure",
    "update",
    "credentials",
}

# Phrases that scammers love to use
# Real banks don't send emails saying "URGENT ACTION REQUIRED"
SOCIAL_ENGINEERING_PHRASES = (
    "verify your account",
    "update your information",
    "suspended account",
    "limited time",
    "urgent action",
    "security alert",
    "unusual activity",
)

# Big brands that get impersonated a LOT
BRAND_KEYWORDS = (
    "paypal",
    "amazon",
    "microsoft",
    "office365",
    "apple",
    "icloud",
    "google",
    "bank of america",
    "wells fargo",
    "chase",
)

# URL shorteners - convenient for legit uses, abused by scammers
URL_SHORTENERS = {
    "bit.ly",
    "goo.gl",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "buff.ly",
    "is.gd",
    "rebrand.ly",
    "cutt.ly",
}

# JavaScript patterns that suggest obfuscation
# Normal code doesn't need eval() and unescape()
OBFUSCATED_JS_PATTERNS = (
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"new Function", re.IGNORECASE),
    re.compile(r"atob\s*\(", re.IGNORECASE),
    re.compile(r"unescape\s*\(", re.IGNORECASE),
)


@dataclass
class SiteSnapshot:
    """
    What we know about a site after downloading it.
    
    Think of this as our notes from visiting the page.
    """
    ok: bool                    # Did we successfully download it?
    final_url: str             # Where we ended up after redirects
    status_code: Optional[int]  # HTTP status code
    content_type: str          # What kind of content (text/html, etc)
    html: str                  # The actual HTML content
    redirect_count: int        # How many redirects we followed
    error: Optional[str] = None  # If something went wrong, what happened

    @property
    def final_domain(self) -> str:
        """Extract just the domain from the final URL."""
        parsed = urlparse(self.final_url)
        return parsed.hostname or ""


def _normalise_url(url: str) -> str:
    """Make sure URL has a scheme. No scheme = add http://"""
    return url if "://" in url else f"http://{url}"


def _fetch_site(url: str, timeout: int = 8) -> SiteSnapshot:
    """
    Download a webpage for analysis.
    
    We follow redirects, respect timeouts, and don't download giant files.
    Safety first!
    """
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as exc:
        # Something went wrong - network error, timeout, etc
        return SiteSnapshot(
            ok=False,
            final_url=url,
            status_code=None,
            content_type="",
            html="",
            redirect_count=0,
            error=str(exc)[:200],
        )

    content_type = response.headers.get("Content-Type", "")
    html = response.text or ""
    
    # Don't keep the whole page if it's massive
    truncated = False
    if len(html) > MAX_HTML_CHARS:
        html = html[:MAX_HTML_CHARS]
        truncated = True

    error = None
    if truncated:
        error = "Content truncated for analysis"

    return SiteSnapshot(
        ok=True,
        final_url=response.url,
        status_code=response.status_code,
        content_type=content_type,
        html=html,
        redirect_count=len(response.history or []),
        error=error,
    )


def _extract_text_tokens(text: str) -> Counter:
    """Break text into words so we can count them. Simple but effective."""
    words = re.findall(r"[a-zA-Z0-9_-]+", text.lower())
    return Counter(words)


def _collect_features(domain: str, snapshot: SiteSnapshot) -> Dict[str, Any]:
    """
    Analyze the HTML and extract features that might indicate phishing.
    
    This is where we actually look at what's on the page:
    - Forms collecting passwords
    - Links going to weird places
    - Suspicious text content
    - Sketchy scripts
    """
    html = snapshot.html
    
    # Parse HTML with BeautifulSoup - this thing is magic
    soup: Optional[BeautifulSoup] = None
    if html:
        soup = BeautifulSoup(html, "html.parser")

    # Get the text content (without HTML tags)
    text_content = soup.get_text(" ", strip=True) if soup else ""
    text_lower = text_content.lower()
    tokens = _extract_text_tokens(text_content)

    # Analyze forms - what are they collecting and where do they send it?
    forms = soup.find_all("form") if soup else []
    total_forms = len(forms)
    password_fields = 0
    external_forms = 0
    
    for form in forms:
        inputs = form.find_all("input") if form else []
        for field in inputs:
            field_type = (field.get("type") or "").lower()
            if field_type == "password":
                password_fields += 1
        
        # Check if form submits to a different domain
        action = form.get("action", "")
        if action.startswith("http://") or action.startswith("https://"):
            target_domain = urlparse(action).hostname or ""
            if domain and target_domain and target_domain != domain:
                external_forms += 1

    # Look at scripts - any obfuscated nastiness?
    scripts = soup.find_all("script") if soup else []
    script_strings = [script.string or "" for script in scripts]
    obfuscated_count = sum(
        1 for content in script_strings 
        for pattern in OBFUSCATED_JS_PATTERNS 
        if pattern.search(content)
    )

    # Analyze links - where do they go?
    links = soup.find_all("a", href=True) if soup else []
    total_links = len(links)
    external_links = 0
    unique_external_domains: set[str] = set()
    
    for link in links:
        href = link.get("href", "")
        if href.startswith("http://") or href.startswith("https://"):
            link_domain = urlparse(href).hostname or ""
            if domain and link_domain and link_domain != domain:
                external_links += 1
                unique_external_domains.add(link_domain)

    # Check for suspicious terms in the text
    suspicious_terms = sorted(term for term in SUSPICIOUS_TERMS if term in tokens)
    
    # Count urgent/scary phrases
    urgent_hits = sum(text_lower.count(phrase) for phrase in SOCIAL_ENGINEERING_PHRASES)

    # Check for brand impersonation
    # If they mention "PayPal" but the domain isn't paypal.com, that's sus
    brand_hits = [brand for brand in BRAND_KEYWORDS if brand in text_lower]
    brand_impersonation = [
        brand for brand in brand_hits 
        if brand not in snapshot.final_domain.lower()
    ] if snapshot.final_domain else brand_hits

    # Check for contact info (legit sites usually have this)
    contact_info_present = bool(re.search(r"support@|contact@|help@", text_lower))
    phone_numbers = bool(re.search(r"\b\+?\d[\d\s().-]{6,}\b", text_lower))

    # Is this a URL shortener?
    shortener_used = snapshot.final_domain.lower() in URL_SHORTENERS if snapshot.final_domain else False

    content_length = len(text_content)
    external_ratio = (external_links / total_links) if total_links else 0.0

    # Package up all our findings
    return {
        "total_forms": total_forms,
        "password_fields": password_fields,
        "external_forms": external_forms,
        "total_links": total_links,
        "external_links": external_links,
        "external_ratio": external_ratio,
        "unique_external_domains": len(unique_external_domains),
        "suspicious_terms": suspicious_terms,
        "urgent_hits": urgent_hits,
        "brand_impersonation": brand_impersonation,
        "contact_info": contact_info_present,
        "phone_numbers": phone_numbers,
        "obfuscated_scripts": obfuscated_count,
        "content_length": content_length,
        "shortener_used": shortener_used,
        "text_available": bool(text_content),
    }


def _score_features(features: Dict[str, Any], snapshot: SiteSnapshot) -> Dict[str, Any]:
    """
    Turn the features we collected into a risk score.
    
    This is where we decide "how bad is this?" based on what we found.
    """
    score = 0
    signals: List[Dict[str, Any]] = []

    def note(weight: int, message: str) -> None:
        """Add a signal with its weight to the score."""
        nonlocal score
        if weight >= 0:
            score += weight
        else:
            score = max(0, score + weight)
        signals.append({"weight": weight, "message": message})

    # Score based on what we found
    
    if features["external_forms"]:
        # Forms sending data elsewhere is a HUGE red flag
        note(35, f"{features['external_forms']} form(s) submit to external domains")
    
    if features["password_fields"]:
        note(18, "Password input detected in page forms")
    
    if features["shortener_used"]:
        note(20, "URL uses a link shortener domain")
    
    if features["suspicious_terms"]:
        joined = ", ".join(features["suspicious_terms"][:4])
        note(min(24, 6 * len(features["suspicious_terms"])), f"Suspicious keywords present: {joined}")
    
    if features["urgent_hits"]:
        note(min(18, 8 + features["urgent_hits"] * 3), "Urgent security phrasing detected repeatedly")
    
    if features["brand_impersonation"]:
        joined = ", ".join(features["brand_impersonation"][:3])
        note(28, f"Brand references do not match domain: {joined}")
    
    if features["obfuscated_scripts"]:
        note(min(20, 10 + features["obfuscated_scripts"] * 4), "Obfuscated JavaScript patterns detected")
    
    if features["external_ratio"] >= 0.7 and features["total_links"] >= 6:
        note(12, "Majority of hyperlinks point to other domains")
    
    if snapshot.redirect_count >= 3:
        note(10, f"Multiple redirects observed ({snapshot.redirect_count} hops)")
    
    if snapshot.final_domain and features["total_forms"] == 0 and features["content_length"] < 400:
        note(6, "Landing page contains very little readable content")

    # Good signals - reduce the score slightly
    if features["contact_info"] and features["phone_numbers"]:
        note(-6, "Contact details detected on the page")

    # Cap score at 0-100
    risk_score = max(0, min(100, score))

    # Determine risk label
    if risk_score >= 70:
        risk_label = "high"
    elif risk_score >= 40:
        risk_label = "medium"
    else:
        risk_label = "low"

    # Build a human-readable summary
    top_signals = sorted(signals, key=lambda item: item.get("weight", 0), reverse=True)
    if top_signals:
        reasons = [item["message"] for item in top_signals[:2]]
        if risk_label == "high":
            summary = "High risk content patterns detected: " + "; ".join(reasons)
        elif risk_label == "medium":
            summary = "Mixed signals observed: " + "; ".join(reasons)
        else:
            summary = "Most signals look benign; top notes: " + "; ".join(reasons)
    else:
        summary = "No notable content-based phishing patterns detected."

    # Calculate confidence based on how much content we analyzed
    coverage = min(1.0, features["content_length"] / 6000) if features["text_available"] else 0.0
    status_multiplier = 1.0 if snapshot.status_code and 200 <= snapshot.status_code < 400 else 0.6
    confidence = round(0.3 + 0.7 * coverage * status_multiplier, 2) if features["text_available"] else 0.2
    confidence = max(0.0, min(1.0, confidence))

    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "summary": summary,
        "signals": signals,
        "confidence": confidence,
    }


def analyze_site_with_ai(url: str, *, snapshot: SiteSnapshot | None = None) -> Dict[str, Any]:
    """
    Main entry point for content analysis.
    
    Downloads the page, extracts features, scores them, returns results.
    
    (Yes, it's called "analyze_site_with_ai" but it's really just
    smart pattern matching. Marketing won that battle.)
    """
    if not url or not url.strip():
        return {
            "status": "error",
            "error": "No URL provided",
            "analysis_version": ANALYZER_VERSION,
        }

    normalised_url = _normalise_url(url.strip())
    snapshot = snapshot or _fetch_site(normalised_url)
    
    if not snapshot.ok:
        return {
            "status": "error",
            "error": snapshot.error or "Failed to retrieve content",
            "analysis_version": ANALYZER_VERSION,
            "metadata": {
                "final_url": snapshot.final_url,
                "status_code": snapshot.status_code,
            },
        }

    domain = urlparse(normalised_url).hostname or ""
    features = _collect_features(domain, snapshot)
    scored = _score_features(features, snapshot)

    # Build metadata for debugging/transparency
    metadata = {
        "final_url": snapshot.final_url,
        "status_code": snapshot.status_code,
        "content_type": snapshot.content_type,
        "redirect_count": snapshot.redirect_count,
        "analysis_version": ANALYZER_VERSION,
    }
    if snapshot.error:
        metadata["note"] = snapshot.error

    return {
        "status": "ok",
        "risk_score": scored["risk_score"],
        "risk_label": scored["risk_label"],
        "summary": scored["summary"],
        "signals": scored["signals"],
        "confidence": scored["confidence"],
        "metadata": metadata,
        "features": features,
    }
