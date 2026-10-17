"""
Explainable URL feature extraction and analysis.
Never contacts the URL. Output is both a rich numeric feature vector for ML and an explanatory heuristic assessment.
"""
import ipaddress
import math
import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "tr.im", "isgd.com"
}

KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "signin", "wallet", "support", "billing", "service",
    "authenticate", "security", "customer", "portal", "webscr", "ebayisapi",
    "validate", "recover", "session", "appleid", "paypal", "microsoft"
]

BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon",
    "chase", "bankofamerica", "wellsfargo", "facebook", "instagram",
    "dropbox", "adobe", "yahoo", "binance", "coinbase"
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
    "fit", "rest", "buzz", "country", "kim", "surf", "club"
}

MODE = "heuristic (rule-based, not a trained ML model)"

def validate_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if len(url) > 2048:
        raise ValueError("URL is too long (max 2048 characters)")
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("URL must start with http:// or https://")
    p = urlparse(url)
    if not p.hostname or " " in url:
        raise ValueError("URL has no valid hostname")
    return url

def shannon_entropy(s: str) -> float:
    """Calculates Shannon character entropy to detect algorithmic or obfuscated patterns."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 4)

def extract_features(url: str) -> dict:
    """Robust, comprehensive URL feature extractor."""
    try:
        p = urlparse(url)
    except Exception:
        p = urlparse("http://invalid.invalid")

    host = (p.hostname or "").lower()
    path = p.path or ""
    query = p.query or ""
    
    # Check IP host
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    parts = host.split(".")
    try:
        port = p.port
    except ValueError:
        port = None

    # TLD
    tld = parts[-1] if len(parts) > 1 and not is_ip else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Keywords hits
    url_lower = url.lower()
    keyword_hits = [k for k in KEYWORDS if k in url_lower]
    keyword_hits_host = [k for k in KEYWORDS if k in host]

    # Brand imitation in subdomain or path
    brand_imitation = 0
    main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for b in BRANDS:
        if b in url_lower and b not in main_domain:
            brand_imitation = 1
            break

    # Digits
    num_digits_host = sum(c.isdigit() for c in host)
    num_digits_url = sum(c.isdigit() for c in url)
    host_len = max(len(host), 1)
    url_len = max(len(url), 1)

    return {
        # Preserved original features for backward compatibility
        "url_length": len(url),
        "hostname_length": len(host),
        "num_dots": host.count("."),
        "num_subdomains": max(len(parts) - 2, 0) if not is_ip else 0,
        "is_ip_host": is_ip,
        "has_at_symbol": "@" in url,
        "is_https": p.scheme.lower() == "https",
        "is_shortener": host in SHORTENERS,
        "num_hyphens_host": host.count("-"),
        "has_punycode": "xn--" in host,
        "num_digits_host": num_digits_host,
        "keyword_hits": keyword_hits,
        "query_length": len(query),
        "path_depth": path.count("/"),
        "has_port": port is not None and port not in (80, 443),

        # Enriched features for improved ML accuracy
        "path_length": len(path),
        "num_dots_url": url.count("."),
        "num_hyphens_url": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits_url": num_digits_url,
        "ratio_digits_host": round(num_digits_host / host_len, 4),
        "ratio_digits_url": round(num_digits_url / url_len, 4),
        "has_tilde": "~" in url,
        "has_percent": "%" in url,
        "entropy_host": shannon_entropy(host),
        "entropy_url": shannon_entropy(url),
        "n_keywords_host": len(keyword_hits_host),
        "brand_in_subdomain": brand_imitation,
        "suspicious_tld": 1 if is_suspicious_tld else 0,
    }

def heuristic_scan(url: str) -> dict:
    f = extract_features(url)
    findings = []
    def add(name, detail, pts): findings.append({"indicator": name, "detail": detail, "points": pts})

    if f["is_ip_host"]: add("IP address host", "Legitimate sites rarely use a raw IP address.", 25)
    if f["has_at_symbol"]: add("'@' in URL", "Can hide the real destination.", 20)
    if f["is_shortener"]: add("URL shortener", "The final destination is hidden.", 15)
    if f["has_punycode"]: add("Punycode hostname", "May imitate another domain with look-alike characters.", 20)
    if not f["is_https"]: add("No HTTPS", "Connection is not encrypted (HTTPS alone does not prove safety).", 10)
    if f["num_subdomains"] >= 3: add("Many subdomains", f"{f['num_subdomains']} subdomain levels.", 15)
    if f["num_hyphens_host"] >= 3: add("Many hyphens in hostname", "Common in look-alike domains.", 10)
    if f["url_length"] > 100: add("Very long URL", f"{f['url_length']} characters.", 10)
    if f["num_digits_host"] >= 4: add("Many digits in hostname", "Unusual for brand domains.", 8)
    if f["has_port"]: add("Non-standard port", "Unusual for normal websites.", 8)
    if f["keyword_hits"]: add("Sensitive keywords", "Found: " + ", ".join(f["keyword_hits"]), min(5 * len(f["keyword_hits"]), 15))
    if f.get("brand_in_subdomain"): add("Brand name deception", "Known brand name appears outside registered root domain.", 20)
    if f.get("suspicious_tld"): add("High-abuse TLD", "Domain uses a top-level domain frequently associated with spam/phishing.", 15)
    if f.get("has_percent"): add("Percent-encoding obfuscation", "URL contains percent-encoded characters.", 10)

    score = min(sum(x["points"] for x in findings), 100)
    category = "Low" if score < 30 else "Suspicious" if score < 60 else "High"
    recs = [
        "Do not enter passwords or personal data unless you reached the site by typing the official address yourself.",
        "Verify the sender through a separate, trusted channel.",
        "Low score does NOT mean safe: these are indicators, not proof."
    ]
    if category != "Low":
        recs.insert(0, "Do not open this link. Report it to your IT/security team.")

    return {
        "score": score,
        "category": category,
        "mode": MODE,
        "features": f,
        "findings": findings,
        "recommendations": recs,
        "disclaimer": "Heuristic indicators only. This is an academic prototype, not an enterprise security product."
    }

FEATURE_ORDER = [
    # Baseline original features
    "url_length", "hostname_length", "num_dots", "num_subdomains", "is_ip_host",
    "has_at_symbol", "is_https", "is_shortener", "num_hyphens_host", "has_punycode",
    "num_digits_host", "n_keywords", "query_length", "path_depth", "has_port",
    # Advanced features
    "path_length", "num_dots_url", "num_hyphens_url", "num_underscores", "num_slashes",
    "num_digits_url", "ratio_digits_host", "ratio_digits_url", "has_tilde", "has_percent",
    "entropy_host", "entropy_url", "n_keywords_host", "brand_in_subdomain", "suspicious_tld"
]

def vector(url: str) -> list:
    """Numeric features used by BOTH training and prediction (keeps them consistent)."""
    f = extract_features(url)
    f["n_keywords"] = len(f["keyword_hits"])
    return [float(f[k]) for k in FEATURE_ORDER]
