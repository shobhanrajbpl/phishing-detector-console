from flask import Flask, request, jsonify, render_template
import re
import pickle
import tldextract
import requests
import socket
from bs4 import BeautifulSoup
import os

app = Flask(__name__)

try:
    model = pickle.load(open("phishing_model.pkl", "rb"))
except Exception:
    model = None

@app.route("/")
def home():
    return render_template("index.html")

def has_ip_address(url):
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+", url))

def count_dots(url):
    return url.count(".")

def has_https(url):
    return url.startswith("https")

def suspicious_tld(suffix):
    return suffix in ["ru", "tk", "ml", "ga", "cf"]

trusted_brands = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "github",
    "instagram",
    "netflix",
    "bank"
]

def detect_brand_impersonation(domain, subdomain):
    for brand in trusted_brands:
        if brand in subdomain.lower() and domain.lower() != brand:
            return brand
    return None

def scan_webpage(url):
    findings = []
    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            findings.append("Website unreachable or blocked")
            return findings
        soup = BeautifulSoup(r.text, "html.parser")
        if soup.find("input", {"type": "password"}):
            findings.append("Password field detected")
        if len(soup.find_all("form")) > 1:
            findings.append("Multiple forms detected")
        keywords = ["verify", "account", "bank", "login", "password", "update", "secure", "confirm"]
        page = r.text.lower()
        for k in keywords:
            if k in page:
                findings.append(f"Keyword detected: {k}")
    except Exception:
        findings.append("Content scan blocked or failed")
    return findings

def get_ip_safe(url):
    try:
        hostname = url.split("//")[-1].split("/")[0]
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return "Unavailable"

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400
    url = data["url"]
    extracted = tldextract.extract(url)
    domain = extracted.domain
    subdomain = extracted.subdomain
    suffix = extracted.suffix
    score = 0
    reasons = []
    if has_ip_address(url):
        score += 3
        reasons.append("IP address used in URL")
    if not has_https(url):
        score += 2
        reasons.append("Non HTTPS connection")
    if count_dots(url) > 4:
        score += 1
        reasons.append("Too many subdomains detected")
    if suspicious_tld(suffix):
        score += 3
        reasons.append("Suspicious top-level domain")
    brand = detect_brand_impersonation(domain, subdomain)
    if brand:
        score += 5
        reasons.append(f"Brand impersonation detected: {brand}")
    web_findings = scan_webpage(url)
    if "Password field detected" in web_findings:
        score += 4
    threat = "LOW"
    if score >= 8:
        threat = "HIGH"
    elif score >= 4:
        threat = "MEDIUM"
    explanation = "System analysis based on structural URL signals, domain intelligence, and webpage behavior patterns."
    response = {
        "threat": threat,
        "score": score,
        "domain": domain,
        "subdomain": subdomain,
        "tld": suffix,
        "ip": get_ip_safe(url),
        "reasons": reasons,
        "web_findings": web_findings,
        "explanation": explanation
    }
    return jsonify(response)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

