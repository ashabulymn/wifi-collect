import csv, io, ipaddress, os, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse, StreamingResponse

app = FastAPI(title="LJN NOC WiFi Collector")
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "8"))
WORKERS = int(os.getenv("MAX_WORKERS", "8"))
ALLOW_PUBLIC = os.getenv("ALLOW_PUBLIC_IPS", "false").lower() == "true"
CREDS = [(os.getenv(f"COLLECTOR_USERNAME_{i}"), os.getenv(f"COLLECTOR_PASSWORD_{i}")) for i in range(1, 4)]
CREDS = [(u, p) for u, p in CREDS if u and p]
results = []
LABELS = {
    "ssid": ["ssid", "wifi name", "wireless name", "wlan ssid", "ssid name"],
    "wifi_password": ["wpa pre-shared key", "wpa psk", "wpa passphrase", "wifi password", "wireless password", "pre-shared key", "passphrase"],
    "pppoe_username": ["pppoe username", "pppoe user", "pppoe account", "internet username", "wan username"],
}

# Collect all matching values instead of returning only the first SSID/password.
def parse_values(soup, keywords):
    values = []
    seen = set()
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
    text = soup.get_text(" ", strip=True)
    for k in keywords:
        for m in re.finditer(re.escape(k) + r"\s*[:=]\s*([^|\n]{1,100})", text, re.I):
            value = m.group(1).strip()
            if value and value not in seen:
                seen.add(value); values.append(value)
    return values

def detect_model(soup, headers=""):
    text = (soup.get_text(" ", strip=True) + " " + headers).lower()
    for name in ["zte", "huawei", "fiberhome", "tp-link", "mikrotik", "raisecom", "nokia", "d-link"]:
        if name in text:
            return name.upper()
    return "Generic Web"

def login_and_collect(ip, username, password, scheme):
    s = requests.Session()
    s.headers.update({"User-Agent": "LJN-NOC-WifiCollector/1.1"})
    try:
        r = s.get(f"{scheme}://{ip}/", timeout=TIMEOUT, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
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
            return None
        data[user_key], data[pass_key] = username, password
        rr = s.post(action, data=data, timeout=TIMEOUT, verify=False, allow_redirects=True)
        body = rr.text.lower()
        if rr.status_code >= 400 or any(x in body for x in ["incorrect password", "login failed", "invalid password", "wrong password"]):
            return None
        ps = BeautifulSoup(rr.text, "html.parser")
        ssids = parse_values(ps, LABELS["ssid"])
        wifi_passwords = parse_values(ps, LABELS["wifi_password"])
        pppoe = parse_values(ps, LABELS["pppoe_username"])
        if not any([ssids, wifi_passwords, pppoe]) and len(rr.text) < 2000:
            return None
        return {
            "login": f"{username}/***",
            "model": detect_model(ps, str(rr.headers)),
            "ssid": " | ".join(ssids),
            "wifi_password": " | ".join(wifi_passwords),
            "pppoe_username": " | ".join(pppoe),
        }
    except requests.RequestException:
        return None

def collect(ip):
    row = {"ip": ip, "status": "FAILED", "login": "", "model": "", "ssid": "", "wifi_password": "", "pppoe_username": "", "note": ""}
    if not allowed_ip(ip):
        row["note"] = "IP rejected by safety policy (private IPs only)"
        return row
    for scheme in ["http", "https"]:
        try:
            requests.get(f"{scheme}://{ip}/", timeout=TIMEOUT, verify=False)
        except requests.RequestException:
            continue
        for u, p in CREDS:
            data = login_and_collect(ip, u, p, scheme)
            if data:
                row.update(data); row["status"] = "OK"; return row
    row["note"] = "All configured credentials failed or data not exposed"
    return row

def allowed_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ALLOW_PUBLIC or ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

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
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(collect, ip): ip for ip in ips}
        for f in as_completed(futures):
            results.append(f.result())
    results.sort(key=lambda x: x["ip"])
    return {"total": len(results), "success": sum(x["status"] == "OK" for x in results), "failed": sum(x["status"] != "OK" for x in results), "results": results}

@app.get("/export.csv")
def export_csv():
    out = io.StringIO()
    fields = ["ip", "status", "login", "model", "ssid", "wifi_password", "pppoe_username", "note"]
    w = csv.DictWriter(out, fieldnames=fields); w.writeheader(); w.writerows(results)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=wifi-collector.csv"})
