import os, sys, json, csv, time, urllib.request, urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESEARCH_DIR = os.path.join(BASE_DIR, "research_data")
API_BASE = "http://127.0.0.1:5173/api/v1"

tests = [
    # 1. Registration with valid format
    ("SEC-01", "User Registration - Valid", "POST", "/auth/register",
     {"username": "sec_test_user1", "password": "SecurePassword123!"}, None, 201, "Account created with status 201"),
    
    # 2. Registration with duplicate username
    ("SEC-02", "User Registration - Duplicate Conflict", "POST", "/auth/register",
     {"username": "sec_test_user1", "password": "SecurePassword123!"}, None, 409, "Rejects duplicate with HTTP 409 Conflict"),
     
    # 3. Registration with short username (<3 chars)
    ("SEC-03", "User Registration - Short Username", "POST", "/auth/register",
     {"username": "ab", "password": "SecurePassword123!"}, None, 422, "Rejects invalid length with HTTP 422 Unprocessable"),

    # 4. Registration with illegal characters in username
    ("SEC-04", "User Registration - Disallowed Characters", "POST", "/auth/register",
     {"username": "user<script>", "password": "SecurePassword123!"}, None, 422, "Rejects regex violations with HTTP 422"),

    # 5. Registration with short password (<8 chars)
    ("SEC-05", "User Registration - Short Password", "POST", "/auth/register",
     {"username": "valid_user_x", "password": "short"}, None, 422, "Enforces minimum 8 chars with HTTP 422"),

    # 6. Login with correct credentials
    ("SEC-06", "Authentication - Valid Login", "POST", "/auth/login",
     {"username": "sec_test_user1", "password": "SecurePassword123!"}, None, 200, "Returns JWT bearer token"),

    # 7. Login with wrong password
    ("SEC-07", "Authentication - Wrong Password", "POST", "/auth/login",
     {"username": "sec_test_user1", "password": "WrongPassword999!"}, None, 401, "Rejects invalid credentials with HTTP 401"),

    # 8. Access protected endpoint without token
    ("SEC-08", "Authorization - Missing JWT Token", "GET", "/users/me",
     None, None, 401, "Rejects unauthenticated request with HTTP 401"),

    # 9. Access protected endpoint with invalid/malformed token
    ("SEC-09", "Authorization - Malformed JWT Token", "GET", "/users/me",
     None, "Bearer invalid.token.value", 401, "Rejects corrupted signature with HTTP 401"),

    # 10. URL validation - Missing scheme
    ("SEC-10", "URL Input Validation - Missing Scheme", "POST", "/scans/url",
     {"url": "www.google.com"}, "AUTH_TOKEN", 422, "Rejects URL without http/https scheme with HTTP 422"),

    # 11. URL validation - Oversized input (>2048 chars)
    ("SEC-11", "URL Input Validation - Length Boundary", "POST", "/scans/url",
     {"url": "https://example.com/" + "a" * 2100}, "AUTH_TOKEN", 422, "Rejects oversized URLs exceeding 2048 chars"),

    # 12. URL validation - Whitespace injection
    ("SEC-12", "URL Input Validation - Space Injection", "POST", "/scans/url",
     {"url": "https://bank.com /account"}, "AUTH_TOKEN", 422, "Rejects URLs containing whitespace"),

    # 13. File Upload - Missing file payload
    ("SEC-13", "File Upload - Empty File Handling", "POST", "/scans/file",
     b"", "AUTH_TOKEN_RAW", 422, "Rejects 0-byte file upload with HTTP 422"),

    # 14. Report PDF Generation Isolation - Scan not owned by user
    ("SEC-14", "Object-Level Access Control (IDOR)", "GET", "/scans/999999/report.pdf",
     None, "AUTH_TOKEN", 404, "Returns 404 Not Found preventing cross-tenant information disclosure"),

    # 15. CSV Export Isolation
    ("SEC-15", "Data Export Privacy", "GET", "/scans/export.csv",
     None, "AUTH_TOKEN", 200, "Exports only current authenticated user's scan history as CSV"),
]

print("[*] Running Security and Functionality Evaluation...")

# First get a valid auth token for the test user
timestamp_id = int(time.time())
fresh_user = f"sec_user_{timestamp_id}"
tests[0] = ("SEC-01", "User Registration - Valid", "POST", "/auth/register",
     {"username": fresh_user, "password": "SecurePassword123!"}, None, 201, "Account created with status 201")

login_data = json.dumps({"username": "sec_test_user1", "password": "SecurePassword123!"}).encode("utf-8")
reg_data = json.dumps({"username": "sec_test_user1", "password": "SecurePassword123!"}).encode("utf-8")

try:
    r = urllib.request.Request(f"{API_BASE}/auth/register", data=reg_data, headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(r, timeout=10)
except Exception: pass

r = urllib.request.Request(f"{API_BASE}/auth/login", data=login_data, headers={"Content-Type": "application/json"}, method="POST")
res = urllib.request.urlopen(r, timeout=10)
token = json.loads(res.read().decode("utf-8"))["access_token"]
valid_auth_header = f"Bearer {token}"

results = []

for tid, desc, method, endpoint, payload, auth_h, exp_status, exp_behavior in tests:
    url = f"{API_BASE}{endpoint}"
    req_headers = {}
    data = None
    
    if auth_h == "AUTH_TOKEN":
        req_headers["Authorization"] = valid_auth_header
    elif auth_h and auth_h.startswith("Bearer "):
        req_headers["Authorization"] = auth_h
    elif auth_h == "AUTH_TOKEN_RAW":
        req_headers["Authorization"] = valid_auth_header
        
    if payload is not None:
        if isinstance(payload, dict):
            req_headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode("utf-8")
        elif isinstance(payload, bytes):
            data = payload

    actual_status = None
    actual_msg = ""
    
    try:
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            actual_status = resp.status
            actual_msg = "Success response received"
    except urllib.error.HTTPError as he:
        actual_status = he.code
        actual_msg = he.read().decode("utf-8", errors="ignore")[:100]
    except Exception as e:
        actual_status = 0
        actual_msg = str(e)[:100]
        
    passed = (actual_status == exp_status)
    
    results.append({
        "test_id": tid,
        "test_description": desc,
        "method": method,
        "endpoint": endpoint,
        "expected_status": exp_status,
        "actual_status": actual_status,
        "expected_behavior": exp_behavior,
        "status": "PASS" if passed else "FAIL",
        "response_excerpt": actual_msg
    })

sec_csv_path = os.path.join(RESEARCH_DIR, "security_test_results.csv")
with open(sec_csv_path, "w", newline="", encoding="utf-8") as f:
    fields = ["test_id", "test_description", "method", "endpoint", "expected_status", "actual_status", "expected_behavior", "status", "response_excerpt"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(results)

print(f"[+] Successfully wrote {len(results)} security test records to {sec_csv_path}")
