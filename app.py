from flask import Flask, request, jsonify, render_template
import re
import pickle
import tldextract
import requests
import socket
from bs4 import BeautifulSoup

app = Flask(__name__)

model = pickle.load(open("phishing_model.pkl", "rb"))

@app.route("/")
def home():
    return render_template("index.html")

# ---------------- BASIC CHECKS ----------------

def has_ip_address(url):
    return bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))

def count_dots(url):
    return url.count(".")

def has_https(url):
    return url.startswith("https")

def suspicious_tld(suffix):
    return suffix in ["ru","tk","ml","ga","cf"]

# ---------------- BRAND IMPERSONATION ----------------

trusted_brands=["google","paypal","amazon","microsoft","apple","facebook","github"]

def detect_brand_impersonation(domain, subdomain):
    for brand in trusted_brands:
        if brand in subdomain.lower() and domain.lower()!=brand:
            return brand
    return None

# ---------------- WEBPAGE SCANNER ----------------

def scan_webpage(url):
    findings=[]
    try:
        r=requests.get(url,timeout=5,headers={"User-Agent":"Mozilla/5.0"})
        soup=BeautifulSoup(r.text,"html.parser")

        if soup.find("input",{"type":"password"}):
            findings.append("Password field detected")

        if len(soup.find_all("form"))>1:
            findings.append("Multiple forms detected")

        keywords=["verify","account","bank","login","password"]
        page=r.text.lower()

        for k in keywords:
            if k in page:
                findings.append(f"Keyword detected: {k}")

    except:
        findings.append("Content scan blocked")

    return findings

# ---------------- MAIN ANALYSIS ----------------

@app.route("/check",methods=["POST"])
def check():

    url=request.json["url"]

    extracted=tldextract.extract(url)
    domain=extracted.domain
    subdomain=extracted.subdomain
    suffix=extracted.suffix

    score=0
    reasons=[]

    if has_ip_address(url):
        score+=3
        reasons.append("IP address used")

    if not has_https(url):
        score+=2
        reasons.append("Non HTTPS")

    if count_dots(url)>4:
        score+=1
        reasons.append("Too many subdomains")

    if suspicious_tld(suffix):
        score+=3
        reasons.append("Suspicious TLD")

    # BRAND IMPERSONATION
    brand=detect_brand_impersonation(domain,subdomain)
    if brand:
        score+=5
        reasons.append(f"Brand impersonation detected: {brand}")

    # WEB SCAN
    web_findings=scan_webpage(url)

    if "Password field detected" in web_findings:
        score+=4

    # THREAT LEVEL
    threat="LOW"
    if score>=8:
        threat="HIGH"
    elif score>=4:
        threat="MEDIUM"

    explanation="System analysis based on structural URL signals and webpage behavior."

    return jsonify({
        "threat":threat,
        "score":score,
        "domain":domain,
        "ip":socket.gethostbyname(url.split("//")[-1].split("/")[0]),
        "reasons":reasons,
        "web_findings":web_findings,
        "explanation":explanation
    })

if __name__=="__main__":
    import os
port = int(os.environ.get("PORT", 5000))
app.run(host="0.0.0.0", port=port)

