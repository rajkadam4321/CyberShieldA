import os, sys, json, csv, time, urllib.request, statistics

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESEARCH_DIR = os.path.join(BASE_DIR, "research_data")
API_BASE = "http://127.0.0.1:5173/api/v1"

# Login
auth_data = json.dumps({"username": "research_eval", "password": "ResearchPass123!"}).encode("utf-8")
login_req = urllib.request.Request(f"{API_BASE}/auth/login", data=auth_data, headers={"Content-Type": "application/json"}, method="POST")
login_res = urllib.request.urlopen(login_req, timeout=10)
token = json.loads(login_res.read().decode("utf-8"))["access_token"]
headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}

# Test workloads
endpoints = [
    ("Health Check (Public)", f"{API_BASE}/health", "GET", None),
    ("Dashboard Metrics (Auth)", f"{API_BASE}/dashboard", "GET", None),
    ("Scan History List (Auth)", f"{API_BASE}/scans?page=1&size=10", "GET", None),
    ("URL Heuristic Scan (Auth)", f"{API_BASE}/scans/url", "POST", json.dumps({"url": "https://secure-bank-verification.com/login"}).encode("utf-8"))
]

workload_levels = [10, 30, 50]  # Number of repetitions per level
perf_records = []

print("[*] Running API Performance and Response Time Evaluation...")

for ep_name, url, method, body in endpoints:
    for n_req in workload_levels:
        times = []
        errors = 0
        t_start = time.perf_counter()
        
        for _ in range(n_req):
            t0 = time.perf_counter()
            try:
                req_h = dict(headers) if "Auth" in ep_name else {}
                if body: req_h["Content-Type"] = "application/json"
                req = urllib.request.Request(url, data=body, headers=req_h, method=method)
                with urllib.request.urlopen(req, timeout=10) as res:
                    _ = res.read()
                    elapsed = (time.perf_counter() - t0) * 1000
                    times.append(elapsed)
            except Exception as e:
                errors += 1
                
        total_wall_time = time.perf_counter() - t_start
        rps = round(len(times) / total_wall_time, 2) if total_wall_time > 0 else 0
        
        if times:
            avg_ms = round(statistics.mean(times), 2)
            med_ms = round(statistics.median(times), 2)
            times_sorted = sorted(times)
            p95_ms = round(times_sorted[int(0.95 * len(times_sorted))], 2)
            p99_ms = round(times_sorted[int(0.99 * len(times_sorted))], 2)
            min_ms = round(min(times), 2)
            max_ms = round(max(times), 2)
        else:
            avg_ms = med_ms = p95_ms = p99_ms = min_ms = max_ms = 0
            
        success_rate = round(((n_req - errors) / n_req) * 100, 2)
        
        perf_records.append({
            "endpoint": ep_name,
            "workload_repetitions": n_req,
            "total_wall_time_sec": round(total_wall_time, 2),
            "requests_per_second": rps,
            "avg_latency_ms": avg_ms,
            "median_latency_ms": med_ms,
            "p95_latency_ms": p95_ms,
            "p99_latency_ms": p99_ms,
            "min_latency_ms": min_ms,
            "max_latency_ms": max_ms,
            "success_rate_pct": success_rate,
            "error_count": errors
        })

perf_csv_path = os.path.join(RESEARCH_DIR, "performance_results.csv")
with open(perf_csv_path, "w", newline="", encoding="utf-8") as f:
    fields = ["endpoint", "workload_repetitions", "total_wall_time_sec", "requests_per_second", "avg_latency_ms", "median_latency_ms", "p95_latency_ms", "p99_latency_ms", "min_latency_ms", "max_latency_ms", "success_rate_pct", "error_count"]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(perf_records)

print(f"[+] Successfully wrote {len(perf_records)} performance records to {perf_csv_path}")
