import csv, io, ipaddress, os, re, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

app = FastAPI(title="LJN NOC WiFi Collector", version="1.3.0")
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "8"))
WORKERS = int(os.getenv("MAX_WORKERS", "8"))
ALLOW_PUBLIC = os.getenv("ALLOW_PUBLIC_IPS", "false").lower() == "true"
results = []
jobs = {}
job_lock = threading.Lock()


def load_credentials():
    creds = []
    i = 1
    while True:
        u = os.getenv(f"COLLECTOR_USERNAME_{i}")
        p = os.getenv(f"COLLECTOR_PASSWORD_{i}")
        if u is None and p is None:
            break
        if u and p:
            creds.append((u, p))
        i += 1
    return creds

CREDS = load_credentials()

LABELS = {
    "ssid": ["ssid", "wifi name", "wireless name", "wlan ssid", "ssid name"],
    "wifi_password": ["wpa pre-shared key", "wpa psk", "wpa passphrase", "wifi password", "wireless password", "pre-shared key", "passphrase"],
    "pppoe_username": ["pppoe username", "pppoe user", "pppoe account", "internet username", "wan username"],
}


def log_event(job_id, ip, level, message):
    entry = {"time": time.strftime("%H:%M:%S"), "ip": ip, "level": level, "message": message}
    with job_lock:
        if job_id in jobs:
            jobs[job_id]["logs"].append(entry)


def parse_values(soup, keywords):
    values, seen = [], set()
    for tag in soup.find_all(["input", "textarea", "select"]):
        hay = " ".join(str(tag.get(a, "")) for a in ["name", "id", "class", "placeholder", "title"]).lower()
        if any(k in hay for k in keywords):
            value = tag.get("value", "")
            if not value and tag.name == "select":
                selected = tag.find("option", selected=True) or tag.find("option")
                value = selected.get_text(" ", strip=True) if selected else ""
            value = str(value).strip()
            if value and value not in seen:
                seen.add(value); values.append(value)
    return values


def detect_model(soup, headers=""):
    text = (soup.get_text(" ", strip=True) + " " + headers).lower()
    for name in ["zte", "huawei", "fiberhome", "tp-link", "mikrotik", "raisecom", "nokia", "d-link", "totolink"]:
        if name in text:
            return name.upper()
    return "Generic Web"


def allowed_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ALLOW_PUBLIC or ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def login_and_collect(ip, username, password, scheme, job_id, credential_no):
    log_event(job_id, ip, "INFO", f"Trying credential #{credential_no} ({username}) via {scheme.upper()}")
    s = requests.Session()
    s.headers.update({"User-Agent": "LJN-NOC-WifiCollector/1.3.0"})
    try:
        log_event(job_id, ip, "INFO", f"Loading {scheme.upper()} login page")
        r = s.get(f"{scheme}://{ip}/", timeout=TIMEOUT, verify=False, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            log_event(job_id, ip, "WARNING", "No login form detected")
            return None
        form = forms[0]
        action = urljoin(r.url, form.get("action") or r.url)
        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            typ = (inp.get("type") or "text").lower()
            if typ not in ["submit", "button", "reset", "file"]:
                data[name] = inp.get("value", "")
        user_key = next((k for k in data if any(x in k.lower() for x in ["user", "login", "name"])), None)
        pass_key = next((k for k in data if any(x in k.lower() for x in ["pass", "pwd", "password"])), None)
        if not user_key or not pass_key:
            log_event(job_id, ip, "WARNING", "Unable to identify username/password fields")
            return None
        data[user_key], data[pass_key] = username, password
        log_event(job_id, ip, "INFO", "Submitting login")
        rr = s.post(action, data=data, timeout=TIMEOUT, verify=False, allow_redirects=True)
        body = rr.text.lower()
        if rr.status_code >= 400 or any(x in body for x in ["incorrect password", "login failed", "invalid password", "wrong password"]):
            log_event(job_id, ip, "WARNING", f"Login failed with credential #{credential_no}")
            return None
        ps = BeautifulSoup(rr.text, "html.parser")
        log_event(job_id, ip, "SUCCESS", "Login success")
        model = detect_model(ps, str(rr.headers))
        log_event(job_id, ip, f"INFO", f"Detected model: {model}")
        log_event(job_id, ip, "INFO", "Checking SSID")
        ssids = parse_values(ps, LABELS["ssid"])
        if ssids:
            log_event(job_id, ip, "SUCCESS", f"Found {len(ssids)} SSID(s)")
        else:
            log_event(job_id, ip, "WARNING", "SSID not found in returned page")
        log_event(job_id, ip, "INFO", "Checking WiFi password")
        wifi_passwords = parse_values(ps, LABELS["wifi_password"])
        if wifi_passwords:
            log_event(job_id, ip, "SUCCESS", f"Found {len(wifi_passwords)} WiFi password field(s)")
        else:
            log_event(job_id, ip, "WARNING", "WiFi password not found in returned page")
        log_event(job_id, ip, "INFO", "Checking PPPoE username")
        pppoe = parse_values(ps, LABELS["pppoe_username"])
        if pppoe:
            log_event(job_id, ip, "SUCCESS", "PPPoE username found")
        else:
            log_event(job_id, ip, "INFO", "PPPoE username not found in returned page")
        if not any([ssids, wifi_passwords, pppoe]) and len(rr.text) < 2000:
            log_event(job_id, ip, "WARNING", "Login response contains no collectible fields")
            return None
        return {"login": f"{username}/***", "model": model, "ssid": " | ".join(ssids), "wifi_password": " | ".join(wifi_passwords), "pppoe_username": " | ".join(pppoe)}
    except requests.RequestException as exc:
        log_event(job_id, ip, "WARNING", f"Connection error: {type(exc).__name__}")
        return None


def collect(ip, job_id):
    row = {"ip": ip, "status": "FAILED", "login": "", "model": "", "ssid": "", "wifi_password": "", "pppoe_username": "", "note": ""}
    log_event(job_id, ip, "INFO", "Starting collection")
    if not allowed_ip(ip):
        row["note"] = "IP rejected by safety policy (private IPs only)"
        log_event(job_id, ip, "ERROR", row["note"])
        return row
    for scheme in ["http", "https"]:
        log_event(job_id, ip, "INFO", f"Checking {scheme.upper()} connectivity")
        try:
            r = requests.get(f"{scheme}://{ip}/", timeout=TIMEOUT, verify=False, allow_redirects=True)
            log_event(job_id, ip, "SUCCESS", f"{scheme.upper()} reachable (HTTP {r.status_code})")
        except requests.RequestException:
            log_event(job_id, ip, "INFO", f"{scheme.upper()} unavailable")
            continue
        for idx, (u, p) in enumerate(CREDS, 1):
            data = login_and_collect(ip, u, p, scheme, job_id, idx)
            if data:
                row.update(data); row["status"] = "OK"
                log_event(job_id, ip, "SUCCESS", "Collection completed")
                return row
    row["note"] = "All configured credentials failed or data not exposed"
    log_event(job_id, ip, "ERROR", row["note"])
    return row


@app.get("/health")
def health():
    return {"status": "ok", "service": "wifi-collector", "version": "1.3.0", "credentials_loaded": len(CREDS)}

@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", encoding="utf-8") as f:
        return f.read()

@app.post("/collect")
async def collect_ips(file: UploadFile = File(...)):
    global results
    raw = (await file.read()).decode("utf-8", errors="ignore")
    ips = []
    for line in raw.splitlines():
        parts = line.strip().split()
        if parts and parts[0] not in ips:
            ips.append(parts[0])
    job_id = uuid.uuid4().hex
    with job_lock:
        jobs[job_id] = {"logs": [], "done": False, "total": len(ips)}
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(collect, ip, job_id): ip for ip in ips}
        for f in as_completed(futures):
            results.append(f.result())
    results.sort(key=lambda x: x["ip"])
    with job_lock:
        jobs[job_id]["done"] = True
    return {"job_id": job_id, "total": len(results), "success": sum(x["status"] == "OK" for x in results), "failed": sum(x["status"] != "OK" for x in results), "results": results}

@app.get("/logs/{job_id}")
def get_logs(job_id: str):
    with job_lock:
        job = jobs.get(job_id)
        if not job:
            return {"logs": [], "done": True}
        return {"logs": list(job["logs"]), "done": job["done"]}

@app.get("/export.csv")
def export_csv():
    out = io.StringIO()
    fields = ["ip", "status", "login", "model", "ssid", "wifi_password", "pppoe_username", "note"]
    w = csv.DictWriter(out, fieldnames=fields); w.writeheader(); w.writerows(results)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=wifi-collector.csv"})
