"""Explainable URL analysis. Never contacts the URL. Output is a HEURISTIC assessment, not an ML prediction."""
import ipaddress, re
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
KEYWORDS = ["login", "verify", "update", "secure", "account", "bank", "confirm", "password", "signin", "wallet"]
MODE = "heuristic (rule-based, not a trained ML model)"

def validate_url(url: str) -> str:
    url = url.strip()
    if len(url) > 2048: raise ValueError("URL is too long (max 2048 characters)")
    if not re.match(r"^https?://", url, re.I): raise ValueError("URL must start with http:// or https://")
    p = urlparse(url)
    if not p.hostname or " " in url: raise ValueError("URL has no valid hostname")
    return url

def extract_features(url: str) -> dict:
    p = urlparse(url); host = (p.hostname or "").lower()
    try: ipaddress.ip_address(host); is_ip = True
    except ValueError: is_ip = False
    parts = host.split(".")
    try: port = p.port
    except ValueError: port = None
    return {
        "url_length": len(url), "hostname_length": len(host), "num_dots": host.count("."),
        "num_subdomains": max(len(parts) - 2, 0) if not is_ip else 0, "is_ip_host": is_ip,
        "has_at_symbol": "@" in url, "is_https": p.scheme.lower() == "https",
        "is_shortener": host in SHORTENERS, "num_hyphens_host": host.count("-"),
        "has_punycode": "xn--" in host, "num_digits_host": sum(c.isdigit() for c in host),
        "keyword_hits": [k for k in KEYWORDS if k in url.lower()],
        "query_length": len(p.query), "path_depth": p.path.count("/"),
        "has_port": port is not None and port not in (80, 443),
    }

def heuristic_scan(url: str) -> dict:
    f = extract_features(url); findings = []
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
    score = min(sum(x["points"] for x in findings), 100)
    category = "Low" if score < 30 else "Suspicious" if score < 60 else "High"
    recs = ["Do not enter passwords or personal data unless you reached the site by typing the official address yourself.",
            "Verify the sender through a separate, trusted channel.",
            "Low score does NOT mean safe: these are indicators, not proof."]
    if category != "Low": recs.insert(0, "Do not open this link. Report it to your IT/security team.")
    return {"score": score, "category": category, "mode": MODE, "features": f, "findings": findings,
            "recommendations": recs,
            "disclaimer": "Heuristic indicators only. This is an academic prototype, not an enterprise security product."}

FEATURE_ORDER = ["url_length", "hostname_length", "num_dots", "num_subdomains", "is_ip_host", "has_at_symbol", "is_https",
                 "is_shortener", "num_hyphens_host", "has_punycode", "num_digits_host", "n_keywords", "query_length",
                 "path_depth", "has_port"]

def vector(url: str) -> list:
    """Numeric features used by BOTH training and prediction (keeps them consistent)."""
    f = extract_features(url); f["n_keywords"] = len(f["keyword_hits"])
    return [float(f[k]) for k in FEATURE_ORDER]
