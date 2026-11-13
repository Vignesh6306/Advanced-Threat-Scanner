"""
CYBER INTEL  -  Advanced Phishing Threat Intelligence  (v3 - final)
-------------------------------------------------------------------
Run locally :  pip install -r requirements.txt
               streamlit run app.py

Sections
  1. Config & theme        5. Reusable UI components
  2. Constants             6. Pages (Scanner, Batch, Analytics, History,
  3. Detection engine                Reports, Education, Settings)
  4. Database              7. Router
"""
import difflib
import html
import io
import ipaddress
import json
import math
import os
import re
import sqlite3
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# =============================================================================
# 1. CONFIG & THEME
# =============================================================================
APP_NAME = "CYBER INTEL"
APP_VERSION = "3.0"
DB_PATH = os.environ.get("CYBER_INTEL_DB", "cyber_intel_v3.db")
MAX_URL_LEN = 2048
MAX_BATCH = 200

st.set_page_config(
    page_title="Cyber Intel | Phishing Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

RISK_ORDER = ["LOW RISK", "MEDIUM RISK", "HIGH RISK", "CRITICAL"]
RISK_COLORS = {
    "LOW RISK": "#22c55e",
    "MEDIUM RISK": "#f59e0b",
    "HIGH RISK": "#f97316",
    "CRITICAL": "#ef4444",
}
RISK_ICONS = {"LOW RISK": "✅", "MEDIUM RISK": "⚠️", "HIGH RISK": "🚨", "CRITICAL": "⛔"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
:root{
  --bg:#070b14; --panel:#0f172a; --panel2:#111c33; --line:#1e2d4d;
  --txt:#e6f1ff; --mute:#8ea3c4; --cyan:#38bdf8; --blue:#2563eb;
  --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444;
}
html, body, [class*="css"]{ font-family:'Inter',sans-serif; }
.stApp{
  background:
    radial-gradient(900px 500px at 85% -10%, rgba(37,99,235,.20), transparent 60%),
    radial-gradient(700px 400px at -10% 10%, rgba(56,189,248,.12), transparent 60%),
    var(--bg);
}
#MainMenu, footer{ visibility:hidden; }
.block-container{ padding-top:2.2rem; max-width:1280px; }
section[data-testid="stSidebar"]{
  background:linear-gradient(180deg,#0d1730 0%,#0a1224 100%);
  border-right:1px solid var(--line);
}

/* ---------- hero ---------- */
.hero{
  position:relative; overflow:hidden; text-align:center; padding:34px 20px 28px;
  border:1px solid var(--line); border-radius:20px; margin-bottom:22px;
  background:linear-gradient(135deg, rgba(17,28,51,.9), rgba(10,18,36,.9));
}
.hero:before{
  content:""; position:absolute; inset:-60% -20% auto -20%; height:200%;
  background:conic-gradient(from 180deg, transparent, rgba(56,189,248,.14), transparent 40%);
  animation:spin 14s linear infinite;
}
@keyframes spin{ to{ transform:rotate(360deg);} }
.hero > *{ position:relative; z-index:1; }
.hero h1{
  margin:0; font-size:2.3rem; font-weight:800; letter-spacing:1.5px; text-transform:uppercase;
  background:linear-gradient(90deg,#e6f1ff,#38bdf8 55%,#818cf8);
  -webkit-background-clip:text; background-clip:text; color:transparent;
}
.hero p{ margin:.55rem 0 0; color:var(--mute); font-size:1rem; }
.pill{
  display:inline-block; padding:3px 12px; border-radius:999px; font-size:.72rem; font-weight:700;
  letter-spacing:1px; color:var(--cyan); border:1px solid rgba(56,189,248,.4);
  background:rgba(56,189,248,.08); margin-bottom:12px;
}

/* ---------- cards ---------- */
.kpi{
  position:relative; padding:18px 14px; text-align:center; border-radius:16px;
  border:1px solid var(--line); background:linear-gradient(160deg,var(--panel2),var(--panel));
  transition:transform .2s, border-color .2s, box-shadow .2s;
}
.kpi:hover{ transform:translateY(-3px); border-color:var(--accent); box-shadow:0 8px 26px -12px var(--accent); }
.kpi:before{
  content:""; position:absolute; left:16%; right:16%; top:0; height:3px; border-radius:0 0 6px 6px;
  background:var(--accent);
}
.kpi-icon{ font-size:1.3rem; }
.kpi-v{ font-size:2rem; font-weight:800; color:var(--accent); line-height:1.15; }
.kpi-l{ font-size:.7rem; color:var(--mute); text-transform:uppercase; letter-spacing:1.2px; margin-top:2px; }

.card{
  padding:18px 20px; border:1px solid var(--line); border-radius:16px; margin-bottom:12px;
  background:linear-gradient(160deg,var(--panel2),var(--panel));
}
.card h4{ margin:0 0 6px; color:var(--txt); font-size:1rem; }
.card p, .card li{ color:var(--mute); font-size:.92rem; line-height:1.55; }

.verdict-box{
  text-align:center; padding:14px 10px; border-radius:14px; border:1px solid var(--vc);
  background:linear-gradient(160deg, rgba(255,255,255,.03), rgba(255,255,255,0));
  box-shadow:0 0 28px -10px var(--vc);
}
.verdict-box .t{ font-size:1.7rem; font-weight:800; color:var(--vc); letter-spacing:1px; }
.verdict-box .s{ color:var(--mute); font-size:.85rem; margin-top:2px; }

/* ---------- check list ---------- */
.chk{
  display:flex; align-items:flex-start; gap:12px; padding:10px 14px; margin-bottom:7px;
  border-radius:12px; border:1px solid var(--line); background:rgba(15,23,42,.7);
}
.chk .dot{ width:10px; height:10px; border-radius:50%; margin-top:6px; flex:none; box-shadow:0 0 10px currentColor; }
.chk .dot.pass{ color:var(--ok); background:var(--ok); }
.chk .dot.warn{ color:var(--warn); background:var(--warn); }
.chk .dot.fail{ color:var(--bad); background:var(--bad); }
.chk .nm{ font-weight:600; color:var(--txt); font-size:.93rem; }
.chk .dt{ color:var(--mute); font-size:.82rem; }
.chk .st{ margin-left:auto; text-align:right; font-size:.78rem; font-weight:700; white-space:nowrap; }
.chk .st.pass{ color:var(--ok); } .chk .st.warn{ color:var(--warn); } .chk .st.fail{ color:var(--bad); }
.chk .pn{ display:block; color:var(--mute); font-weight:500; font-size:.72rem; }

/* ---------- misc ---------- */
.mono{ font-family:'JetBrains Mono',monospace; font-size:.85rem; color:var(--cyan); word-break:break-all; }
.anat{ font-family:'JetBrains Mono',monospace; font-size:1.05rem; word-break:break-all; padding:14px;
  border-radius:12px; border:1px dashed var(--line); background:rgba(7,11,20,.7); }
.anat .s{color:#a78bfa} .anat .sub{color:#fbbf24} .anat .d{color:#22c55e;font-weight:700}
.anat .t{color:#38bdf8} .anat .p{color:#e6f1ff} .anat .q{color:#f472b6}
.badge{ display:inline-block; padding:2px 10px; border-radius:999px; font-size:.72rem; font-weight:700;
  border:1px solid currentColor; }
.sidebar-logo{ text-align:center; padding:6px 0 4px; }
.sidebar-logo .l1{ font-size:1.35rem; font-weight:800; letter-spacing:2px; color:var(--cyan); }
.sidebar-logo .l2{ font-size:.7rem; color:var(--mute); letter-spacing:2px; }
.stButton>button, .stDownloadButton>button, .stFormSubmitButton>button{
  background:linear-gradient(90deg,#0ea5e9,#2563eb); color:#fff; border:0; border-radius:10px;
  font-weight:700; letter-spacing:.6px; padding:.55rem 1.2rem; transition:all .2s;
}
.stButton>button:hover, .stDownloadButton>button:hover, .stFormSubmitButton>button:hover{
  filter:brightness(1.15); transform:translateY(-1px); box-shadow:0 8px 20px -8px #2563eb;
}
.stButton>button:disabled{ filter:grayscale(.8); opacity:.5; }
div[data-testid="stTextInput"] input, textarea{ border-radius:10px !important; }
button[data-baseweb="tab"]{ font-weight:600; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# =============================================================================
# 2. CONSTANTS
# =============================================================================
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com", "googleapis.com", "youtube.com", "google.co.in"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "azure.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "github": {"github.com", "githubusercontent.com"},
    "linkedin": {"linkedin.com"},
    "whatsapp": {"whatsapp.com"},
    "twitter": {"twitter.com", "x.com"},
    "dropbox": {"dropbox.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "flipkart": {"flipkart.com"},
    "phonepe": {"phonepe.com"},
    "binance": {"binance.com"},
}
TRUSTED = set().union(*BRANDS.values()) | {
    "wikipedia.org", "stackoverflow.com", "python.org", "streamlit.io", "mozilla.org",
    "cloudflare.com", "openai.com", "anthropic.com", "reddit.com", "kaggle.com", "w3.org",
}
TRUSTED_SUFFIXES = (".gov.in", ".nic.in", ".gov", ".edu", ".ac.in", ".gov.uk", ".edu.au")
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "v.gd",
}
FREE_HOSTS = (
    "weebly.com", "blogspot.com", "wixsite.com", "000webhostapp.com", "glitch.me",
    "netlify.app", "pages.dev", "web.app", "firebaseapp.com", "herokuapp.com",
    "github.io", "vercel.app", "workers.dev", "duckdns.org", "ngrok.io",
)
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "zip", "work", "support",
    "country", "rest", "icu", "buzz", "loan", "mov", "cam", "monster", "sbs", "cyou",
}
RISKY_EXT = (".exe", ".apk", ".scr", ".msi", ".bat", ".cmd", ".jar", ".vbs", ".js", ".zip", ".rar", ".iso", ".dmg")
KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "account", "bank", "confirm",
    "password", "wallet", "free", "giveaway", "bonus", "prize", "suspend", "unlock",
    "billing", "invoice", "refund", "claim", "urgent", "otp", "kyc", "reward", "winner",
]
SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "gov.in", "ac.in",
    "nic.in", "co.jp", "com.br", "co.nz", "co.za", "com.sg", "edu.au", "net.in", "org.in",
}
SENSITIVITY = {"Lenient": 0.75, "Balanced": 1.0, "Strict": 1.3}

CHECK_CATALOG = [
    ("HTTPS Protocol", "Is the connection encrypted?", 15),
    ("IP Address in URL", "Raw or obfuscated IP instead of a domain name", 35),
    ("Credentials / '@' Trick", "Text before '@' hides the real host", 45),
    ("URL Shortener", "Real destination is hidden", 20),
    ("Suspicious Keywords", "login, verify, giveaway, kyc ...", 24),
    ("Brand Impersonation", "Brand name or typo of one on an unrelated domain", 30),
    ("Domain Extension (TLD)", "TLDs heavily abused by attackers", 15),
    ("Punycode / Homograph", "Look-alike international characters", 20),
    ("Free Hosting Service", "Throw-away hosting subdomains", 8),
    ("Risky File Download", "Executable or archive in the path", 20),
    ("URL Encoding", "Many %XX characters to hide content", 10),
    ("URL Length", "Very long URLs hide the real host", 10),
    ("Excessive Subdomains", "Many levels like a.b.c.d.example.com", 15),
    ("Hyphens / Digits / Entropy", "Machine-generated looking domain", 24),
    ("Non-standard Port", "Ports other than 80/443", 10),
    ("Custom Blocklist", "Domain you blocked in Settings", 100),
]

# =============================================================================
# 3. DETECTION ENGINE
# =============================================================================
def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def deleet(s: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
    return s.translate(table).replace("vv", "w").replace("rn", "m")


def normalize_url(raw: str):
    raw = (raw or "").strip()
    assumed = False
    if raw and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
        assumed = True
    return raw, assumed


def classify(score: int) -> str:
    if score >= 80:
        return "LOW RISK"
    if score >= 55:
        return "MEDIUM RISK"
    if score >= 30:
        return "HIGH RISK"
    return "CRITICAL"


def defang(url: str) -> str:
    """Make a URL safe to paste in chats / tickets (not clickable)."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def clean_domain(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"^[a-z]+://", "", text)
    return text.split("/")[0].split("?")[0].strip(".")


def _invalid(raw, detail):
    return {
        "url": (raw or "").strip(), "score": 0, "label": "CRITICAL", "host": "",
        "findings": [{"check": "Input", "status": "fail", "detail": detail, "penalty": 100}],
    }


def analyze_url(raw, sensitivity="Balanced", allow=None, block=None):
    """Return {url, score, label, host, findings[]} for one URL."""
    allow, block = set(allow or []), set(block or [])
    scale = SENSITIVITY.get(sensitivity, 1.0)
    raw = (raw or "").strip()
    if not raw:
        return _invalid(raw, "Empty input")
    if len(raw) > MAX_URL_LEN:
        return _invalid(raw, "URL is longer than 2048 characters")
    if raw.lower().startswith(("javascript:", "data:", "vbscript:", "file:")):
        return _invalid(raw, "Dangerous scheme (script / data / file)")

    url, assumed = normalize_url(raw)
    findings = []

    def add(check, status, detail, penalty=0):
        p = penalty if penalty >= 100 else round(penalty * scale)
        findings.append({"check": check, "status": status, "detail": detail, "penalty": p})

    try:
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError:
        return _invalid(raw, "Malformed URL")
    valid_host = re.fullmatch(r"[a-z0-9\-._\[\]:]+", host or "") and ("." in host or ":" in host)
    if re.search(r"\s", url) or not valid_host:
        return _invalid(raw, "Not a valid URL (spaces or invalid hostname)")

    full_lower = unquote(url).lower()
    path_q = unquote((p.path or "") + "?" + (p.query or "")).lower()
    reg = registered_domain(host)
    sld = reg.split(".")[0]
    tld = host.split(".")[-1]
    trusted = reg in TRUSTED or host.endswith(TRUSTED_SUFFIXES) or reg in allow or host in allow

    # 1 scheme -----------------------------------------------------------------
    if p.scheme == "https":
        add("HTTPS Protocol", "pass", "Encrypted connection")
    elif p.scheme == "http":
        add("HTTPS Protocol", "fail",
            "No HTTPS" + (" (scheme missing, http assumed)" if assumed else ""), 15)
    else:
        add("HTTPS Protocol", "fail", f"Unusual scheme '{p.scheme}'", 25)

    # 2 IP host ----------------------------------------------------------------
    is_ip = False
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        is_ip = True
        kind = "private " if (ip.is_private or ip.is_loopback) else ""
        add("IP Address in URL", "fail", f"Host is a {kind}IP address", 30)
    except ValueError:
        if re.fullmatch(r"\d{8,10}|0x[0-9a-f]+", host):
            is_ip = True
            add("IP Address in URL", "fail", "Obfuscated (decimal/hex) IP address", 35)
        else:
            add("IP Address in URL", "pass", "Domain name used")

    # 3 @ trick ----------------------------------------------------------------
    if p.username is not None or "@" in (p.netloc or ""):
        extra = 10 if re.search(r"\.[a-z]{2,}", (p.username or "").lower()) else 0
        add("Credentials / '@' Trick", "fail",
            f"Browsers ignore text before '@'. Real host: {host}", 35 + extra)
    else:
        add("Credentials / '@' Trick", "pass", "Not detected")

    # 4 shortener --------------------------------------------------------------
    if reg in SHORTENERS or host in SHORTENERS:
        add("URL Shortener", "fail", "Destination is hidden behind a shortener", 20)
    else:
        add("URL Shortener", "pass", "Not detected")

    # 5 keywords ---------------------------------------------------------------
    hits = sorted({k for k in KEYWORDS if k in full_lower})
    if hits and not trusted:
        add("Suspicious Keywords", "fail" if len(hits) >= 3 else "warn",
            "Found: " + ", ".join(hits), min(6 * len(hits), 24))
    else:
        add("Suspicious Keywords", "pass",
            "Not detected" if not hits else "Present, but domain is trusted")

    # 6 brand impersonation / typosquatting -----------------------------------
    imp = None
    if not trusted:
        space = host + " " + path_q + " " + (p.username or "").lower()
        tokens = set(re.split(r"[.\-_/?=&@:+]", space))
        for brand, domains in BRANDS.items():
            if reg in domains:
                continue
            if brand in tokens or (len(brand) >= 5 and brand in space):
                imp = f"'{brand}' appears, but the real domain is {reg}"
                break
            ratio = difflib.SequenceMatcher(None, deleet(sld), brand).ratio()
            if len(sld) >= 4 and sld != brand and (ratio >= 0.82 or deleet(sld) == brand):
                imp = f"'{sld}' looks like a typo of '{brand}'"
                break
    if imp:
        add("Brand Impersonation", "fail", imp, 30)
    else:
        add("Brand Impersonation", "pass", "Not detected")

    # 7 TLD --------------------------------------------------------------------
    if tld in SUSPICIOUS_TLDS and not is_ip:
        add("Domain Extension (TLD)", "warn", f".{tld} is frequently abused", 15)
    else:
        add("Domain Extension (TLD)", "pass", f".{tld}" if not is_ip else "n/a (IP host)")

    # 8 punycode ---------------------------------------------------------------
    if "xn--" in host:
        add("Punycode / Homograph", "fail", "International characters may mimic another site", 20)
    else:
        add("Punycode / Homograph", "pass", "Not detected")

    # 9 free hosting -----------------------------------------------------------
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTS) and reg not in allow:
        add("Free Hosting Service", "warn", "Hosted on a free / throw-away platform", 8)
    else:
        add("Free Hosting Service", "pass", "Not detected")

    # 10 risky file ------------------------------------------------------------
    if (p.path or "").lower().endswith(RISKY_EXT):
        add("Risky File Download", "fail", f"Path ends with {os.path.splitext(p.path)[1]}", 20)
    else:
        add("Risky File Download", "pass", "Not detected")

    # 11 encoding --------------------------------------------------------------
    enc = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    if enc >= 3:
        add("URL Encoding", "warn", f"{enc} encoded characters", 10)
    else:
        add("URL Encoding", "pass", "Not detected")

    # 12 length ----------------------------------------------------------------
    n = len(url)
    if n > 120:
        add("URL Length", "warn", f"{n} characters (very long)", 10)
    elif n > 75:
        add("URL Length", "warn", f"{n} characters (long)", 5)
    else:
        add("URL Length", "pass", f"{n} characters (normal)")

    # 13-14 structure ----------------------------------------------------------
    if not is_ip:
        subs = max(len(host.split(".")) - len(reg.split(".")), 0)
        if subs > 3:
            add("Excessive Subdomains", "warn", f"{subs} subdomain levels", 15 if subs > 5 else 10)
        else:
            add("Excessive Subdomains", "pass", f"{subs} level(s)")

        problems = []
        if host.count("-") >= 3:
            problems.append(f"{host.count('-')} hyphens")
        if len(sld) > 4 and sum(c.isdigit() for c in sld) / len(sld) > 0.3:
            problems.append("many digits")
        if len(sld) > 12 and entropy(sld) > 3.6:
            problems.append("random-looking")
        if problems:
            add("Hyphens / Digits / Entropy", "warn", ", ".join(problems), 8 * len(problems))
        else:
            add("Hyphens / Digits / Entropy", "pass", "Normal")

    # 15 port ------------------------------------------------------------------
    if port and port not in (80, 443):
        add("Non-standard Port", "warn", f"Port {port}", 10)
    else:
        add("Non-standard Port", "pass", "Default port")

    # 16 custom blocklist ------------------------------------------------------
    if reg in block or host in block:
        add("Custom Blocklist", "fail", "Domain is on YOUR blocklist", 100)

    score = max(0, 100 - sum(f["penalty"] for f in findings))
    return {"url": raw, "score": score, "label": classify(score), "findings": findings, "host": host}


def url_anatomy(url: str):
    """Colour-coded HTML breakdown of a URL."""
    full, _ = normalize_url(url)
    try:
        p = urlparse(full)
        host = (p.hostname or "")
    except ValueError:
        return html.escape(url)
    reg = registered_domain(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    parts = [f'<span class="s">{html.escape(p.scheme)}://</span>']
    if p.username:
        parts.append(f'<span class="q">{html.escape(p.username)}@</span>')
    if sub:
        parts.append(f'<span class="sub">{html.escape(sub)}.</span>')
    labels = reg.split(".")
    if len(labels) >= 2:
        parts.append(f'<span class="d">{html.escape(labels[0])}</span>')
        parts.append(f'<span class="t">.{html.escape(".".join(labels[1:]))}</span>')
    else:
        parts.append(f'<span class="d">{html.escape(reg)}</span>')
    if p.port:
        parts.append(f':{p.port}')
    tail = (p.path or "") + (("?" + p.query) if p.query else "")
    if tail:
        parts.append(f'<span class="p">{html.escape(tail)}</span>')
    return "".join(parts)


# =============================================================================
# 4. DATABASE
# =============================================================================
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL, score INTEGER NOT NULL, classification TEXT NOT NULL,
                findings TEXT, source TEXT DEFAULT 'scanner', timestamp TEXT NOT NULL)"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS lists(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL, domain TEXT NOT NULL, UNIQUE(kind, domain))"""
        )
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_scan(res, source="scanner"):
    with db() as c:
        c.execute(
            "INSERT INTO scans(url,score,classification,findings,source,timestamp) VALUES(?,?,?,?,?,?)",
            (res["url"], res["score"], res["label"], json.dumps(res["findings"]), source,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )


def load_history() -> pd.DataFrame:
    with db() as c:
        return pd.read_sql_query("SELECT * FROM scans ORDER BY id DESC", c)


def delete_ids(ids):
    with db() as c:
        c.executemany("DELETE FROM scans WHERE id=?", [(int(i),) for i in ids])


def clear_all():
    with db() as c:
        c.execute("DELETE FROM scans")


def get_list(kind):
    with db() as c:
        rows = c.execute("SELECT id, domain FROM lists WHERE kind=? ORDER BY domain", (kind,)).fetchall()
    return rows


def add_list(kind, domain):
    domain = clean_domain(domain)
    if not domain or "." not in domain:
        return False
    with db() as c:
        c.execute("INSERT OR IGNORE INTO lists(kind,domain) VALUES(?,?)", (kind, domain))
    return True


def remove_list(row_id):
    with db() as c:
        c.execute("DELETE FROM lists WHERE id=?", (int(row_id),))


def scan(raw, source="scanner"):
    """Analyse with the user's current settings + lists, and optionally save."""
    res = analyze_url(
        raw,
        sensitivity=st.session_state.get("sensitivity", "Balanced"),
        allow=[d for _, d in get_list("allow")],
        block=[d for _, d in get_list("block")],
    )
    if st.session_state.get("autosave", True):
        save_scan(res, source)
    return res


# =============================================================================
# 5. UI COMPONENTS
# =============================================================================
def hero(title, subtitle, pill="THREAT INTELLIGENCE"):
    st.markdown(
        f'<div class="hero"><div class="pill">{html.escape(pill)}</div>'
        f'<h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></div>',
        unsafe_allow_html=True,
    )


def kpi(col, value, label, icon="", accent="#38bdf8"):
    col.markdown(
        f'<div class="kpi" style="--accent:{accent}"><div class="kpi-icon">{icon}</div>'
        f'<div class="kpi-v">{value}</div><div class="kpi-l">{html.escape(label)}</div></div>',
        unsafe_allow_html=True,
    )


def card(title, body_html):
    st.markdown(f'<div class="card"><h4>{title}</h4>{body_html}</div>', unsafe_allow_html=True)


def badge(label):
    c = RISK_COLORS.get(label, "#38bdf8")
    return f'<span class="badge" style="color:{c}">{html.escape(label)}</span>'


def style_fig(fig, height=330):
    fig.update_layout(
        height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#e6f1ff", family="Inter"), margin=dict(t=30, b=20, l=10, r=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="#1e2d4d", zeroline=False)
    fig.update_yaxes(gridcolor="#1e2d4d", zeroline=False)
    return fig


def gauge(score, label):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        title={"text": "SAFETY SCORE", "font": {"color": "#8ea3c4", "size": 14}},
        number={"font": {"color": "#ffffff", "size": 60}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#8ea3c4"},
            "bar": {"color": RISK_COLORS[label], "thickness": 0.28},
            "bgcolor": "#0d1527", "borderwidth": 0,
            "steps": [
                {"range": [0, 30], "color": "rgba(239,68,68,.25)"},
                {"range": [30, 55], "color": "rgba(249,115,22,.22)"},
                {"range": [55, 80], "color": "rgba(245,158,11,.20)"},
                {"range": [80, 100], "color": "rgba(34,197,94,.22)"},
            ],
            "threshold": {"line": {"color": "#ffffff", "width": 3}, "thickness": 0.8, "value": score},
        },
    ))
    return style_fig(fig, 300)


def checks_html(findings):
    names = {"pass": "PASSED", "warn": "WARNING", "fail": "FAILED"}
    rows = []
    for f in findings:
        pen = f'<span class="pn">-{f["penalty"]} pts</span>' if f["penalty"] else ""
        rows.append(
            f'<div class="chk"><span class="dot {f["status"]}"></span>'
            f'<div><div class="nm">{html.escape(f["check"])}</div>'
            f'<div class="dt">{html.escape(f["detail"])}</div></div>'
            f'<div class="st {f["status"]}">{names[f["status"]]}{pen}</div></div>'
        )
    return "".join(rows)


ADVICE = {
    "LOW RISK": ("No strong phishing indicators were found.",
                 "Still check the sender and never share OTPs. No scanner is 100% certain."),
    "MEDIUM RISK": ("Some suspicious traits were detected.",
                    "Verify the sender and type the website address yourself instead of clicking."),
    "HIGH RISK": ("This link shows several phishing traits.",
                  "Do not log in or download anything. Report it to whoever sent it."),
    "CRITICAL": ("This link is very likely malicious or invalid.",
                 "Do not open it. Delete the message and report it (India: cybercrime.gov.in / 1930)."),
}


def render_result(res, key="r"):
    label, score = res["label"], res["score"]
    color = RISK_COLORS[label]
    head, tip = ADVICE[label]
    st.markdown(
        f'<div class="card"><div style="color:#8ea3c4;font-size:.75rem;letter-spacing:1px">SCANNED TARGET</div>'
        f'<div class="mono">{html.escape(res["url"])}</div>'
        f'<div style="color:#8ea3c4;font-size:.8rem;margin-top:6px">Safe to share: '
        f'<span class="mono">{html.escape(defang(res["url"]))}</span></div></div>',
        unsafe_allow_html=True,
    )
    left, right = st.columns([1, 1.35], gap="large")
    with left:
        st.plotly_chart(gauge(score, label), use_container_width=True, key=f"g_{key}")
        st.markdown(
            f'<div class="verdict-box" style="--vc:{color}"><div class="t">{RISK_ICONS[label]} {label}</div>'
            f'<div class="s">{html.escape(head)}</div></div>',
            unsafe_allow_html=True,
        )
        st.write("")
        (st.success if label == "LOW RISK" else st.warning if label == "MEDIUM RISK" else st.error)(tip)
    with right:
        st.markdown("#### 📋 Detailed URL Analysis")
        st.markdown(checks_html(res["findings"]), unsafe_allow_html=True)

    t1, t2, t3 = st.tabs(["🧬 URL anatomy", "📉 Score breakdown", "🧾 Raw data"])
    with t1:
        st.markdown(f'<div class="anat">{url_anatomy(res["url"])}</div>', unsafe_allow_html=True)
        st.caption("Legend: scheme · subdomain · **real domain** · extension · path. "
                   "The green domain is what truly matters.")
    with t2:
        pen = pd.DataFrame([f for f in res["findings"] if f["penalty"]])
        if pen.empty:
            st.success("No points were deducted.")
        else:
            fig = px.bar(pen, x="penalty", y="check", orientation="h", text="penalty",
                         color_discrete_sequence=["#f97316"])
            fig.update_layout(yaxis={"autorange": "reversed"}, xaxis_title="Points deducted", yaxis_title="")
            st.plotly_chart(style_fig(fig, 80 + 48 * len(pen)), use_container_width=True, key=f"b_{key}")
    with t3:
        st.json(res)
    st.download_button("⬇️ Download this result (JSON)", json.dumps(res, indent=2).encode(),
                       "scan_result.json", "application/json", key=f"dl_{key}")


def sample_chip(label, url):
    st.button(label, key=f"chip_{label}", use_container_width=True,
              on_click=lambda u=url: st.session_state.update(url_input=u))


def period_filter(df, choice):
    if df.empty or choice == "All time":
        return df
    ts = pd.to_datetime(df["timestamp"])
    days = {"Today": 0, "Last 7 days": 7, "Last 30 days": 30}[choice]
    start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days)
    return df[ts >= start]


# =============================================================================
# 6. PAGES
# =============================================================================
def page_scanner():
    hero("Advanced Phishing Threat Intelligence",
         "Paste any link. Get an instant, explainable safety verdict before you click.")
    st.markdown("**Try an example:**")
    c = st.columns(4)
    with c[0]:
        sample_chip("✅ Safe site", "https://colab.research.google.com/")
    with c[1]:
        sample_chip("🎭 '@' trick", "http://www.paypal.com@secure-update-account.xyz/verify")
    with c[2]:
        sample_chip("🎁 Giveaway", "http://bit.ly/free-iphone-giveaway")
    with c[3]:
        sample_chip("🔢 IP login", "http://192.168.1.1/login.php")

    with st.form("scan_form", clear_on_submit=False):
        st.text_input("TARGET URL:", key="url_input", placeholder="https://example.com/login")
        go_scan = st.form_submit_button("INITIATE DEEP SCAN 🚀")
    if go_scan:
        if not st.session_state.get("url_input", "").strip():
            st.warning("Please enter a URL first.")
        else:
            with st.spinner("Analysing URL structure, domain and reputation patterns..."):
                st.session_state["last"] = scan(st.session_state["url_input"])
    if "last" in st.session_state:
        st.divider()
        render_result(st.session_state["last"], "single")
    else:
        card("How it works",
             "<p>Your link is checked against 16 weighted rules: encryption, hidden hosts, "
             "look-alike brands, risky extensions and more. The scanner never opens the site, "
             "so it is safe to test dangerous links.</p>")


def parse_uploaded(file):
    raw = file.getvalue().decode("utf-8", errors="ignore")
    if file.name.lower().endswith(".csv"):
        try:
            df = pd.read_csv(io.StringIO(raw))
            col = next((c for c in df.columns if str(c).strip().lower() in ("url", "link", "target url")),
                       df.columns[0])
            return [str(u).strip() for u in df[col].dropna()]
        except Exception:
            pass
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def page_batch():
    hero("Batch URL Scanner", "Scan dozens of links at once. Paste them or upload a file.", "BULK ANALYSIS")
    tab1, tab2 = st.tabs(["📝 Paste URLs", "📁 Upload CSV / TXT"])
    urls = []
    with tab1:
        txt = st.text_area("URLs to scan (one per line):", height=170, key="batch_txt",
                           placeholder="https://example.com\nhttp://bit.ly/abc")
        run_paste = st.button("RUN BATCH SCAN 🚀", key="run_paste")
        if run_paste:
            urls = [u.strip() for u in txt.splitlines() if u.strip()]
    with tab2:
        up = st.file_uploader("Upload .csv (column 'url') or .txt (one per line)", type=["csv", "txt"])
        run_file = st.button("SCAN UPLOADED FILE 🚀", key="run_file", disabled=up is None)
        if run_file and up is not None:
            urls = parse_uploaded(up)

    if urls:
        urls = list(dict.fromkeys(urls))
        if len(urls) > MAX_BATCH:
            st.info(f"Only the first {MAX_BATCH} unique URLs are scanned.")
            urls = urls[:MAX_BATCH]
        bar, rows = st.progress(0.0, text="Scanning..."), []
        for i, u in enumerate(urls, 1):
            r = scan(u, "batch")
            flags = [f["check"] for f in r["findings"] if f["status"] != "pass"]
            rows.append({"URL": r["url"], "Score": r["score"], "Classification": r["label"],
                         "Flags": ", ".join(flags) or "-"})
            bar.progress(i / len(urls), text=f"Scanned {i} of {len(urls)}")
        bar.empty()
        st.session_state["batch_df"] = pd.DataFrame(rows)
    elif (run_paste or run_file):
        st.warning("No URLs found. Paste some links or upload a file first.")

    df = st.session_state.get("batch_df")
    if df is None or df.empty:
        return
    st.divider()
    k = st.columns(4)
    kpi(k[0], len(df), "Scanned", "🔎")
    kpi(k[1], int((df.Classification == "LOW RISK").sum()), "Low risk", "✅", "#22c55e")
    kpi(k[2], int(df.Classification.isin(["HIGH RISK", "CRITICAL"]).sum()), "High / critical", "🚨", "#ef4444")
    kpi(k[3], round(df.Score.mean(), 1), "Average score", "📈", "#818cf8")
    st.write("")
    a, b = st.columns([1.7, 1], gap="large")
    with a:
        st.dataframe(
            df.sort_values("Score"), use_container_width=True, hide_index=True, height=360,
            column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100)},
        )
    with b:
        cnt = df.Classification.value_counts().reindex(RISK_ORDER).dropna().reset_index()
        cnt.columns = ["Risk", "Count"]
        fig = px.pie(cnt, names="Risk", values="Count", hole=0.6, color="Risk",
                     color_discrete_map=RISK_COLORS)
        st.plotly_chart(style_fig(fig, 360), use_container_width=True, key="batch_pie")
    st.download_button("⬇️ Download batch results (CSV)", df.to_csv(index=False).encode(),
                       "batch_results.csv", "text/csv")


def host_of(u):
    try:
        return registered_domain((urlparse(normalize_url(u)[0]).hostname or "").lower())
    except ValueError:
        return ""


def page_analytics():
    hero("Global Threat Analytics", "Live statistics computed from your real scan history.", "ANALYTICS")
    all_df = load_history()
    if all_df.empty:
        card("No data yet", "<p>Run a few scans, then return here to see charts and trends.</p>")
        return
    period = st.radio("Period", ["All time", "Today", "Last 7 days", "Last 30 days"], horizontal=True)
    df = period_filter(all_df, period)
    if df.empty:
        st.info("No scans in this period.")
        return

    high = int(df.classification.isin(["HIGH RISK", "CRITICAL"]).sum())
    k = st.columns(5)
    kpi(k[0], len(df), "Total scans", "🔎")
    kpi(k[1], int((df.classification == "LOW RISK").sum()), "Safe URLs", "✅", "#22c55e")
    kpi(k[2], int((df.classification == "MEDIUM RISK").sum()), "Medium risk", "⚠️", "#f59e0b")
    kpi(k[3], high, "High / critical", "🚨", "#ef4444")
    kpi(k[4], round(df.score.mean(), 1), "Avg safety score", "📈", "#818cf8")
    st.divider()

    a, b = st.columns(2, gap="large")
    with a:
        st.markdown("#### 🍩 Threat Distribution")
        cnt = df.classification.value_counts().reindex(RISK_ORDER).dropna().reset_index()
        cnt.columns = ["Risk", "Count"]
        fig = px.pie(cnt, names="Risk", values="Count", hole=0.58, color="Risk",
                     color_discrete_map=RISK_COLORS)
        fig.update_traces(textinfo="percent+value")
        st.plotly_chart(style_fig(fig), use_container_width=True, key="an_pie")
    with b:
        st.markdown("#### 📊 Score Distribution")
        fig = px.histogram(df, x="score", nbins=10, range_x=[0, 100], color_discrete_sequence=["#38bdf8"])
        fig.update_layout(xaxis_title="Safety score", yaxis_title="Scans", bargap=0.08)
        st.plotly_chart(style_fig(fig), use_container_width=True, key="an_hist")

    a, b = st.columns(2, gap="large")
    with a:
        st.markdown("#### 📈 Scans Over Time")
        d = df.assign(day=pd.to_datetime(df.timestamp).dt.date, risk=df.classification)
        d = d.groupby(["day", "risk"]).size().reset_index(name="scans")
        fig = px.bar(d, x="day", y="scans", color="risk", color_discrete_map=RISK_COLORS,
                     category_orders={"risk": RISK_ORDER})
        fig.update_layout(xaxis_title="", yaxis_title="Scans")
        st.plotly_chart(style_fig(fig), use_container_width=True, key="an_time")
    with b:
        st.markdown("#### 🚩 Most Triggered Checks")
        cnt = Counter()
        for js in df.findings.dropna():
            try:
                for f in json.loads(js):
                    if f["status"] != "pass":
                        cnt[f["check"]] += 1
            except (ValueError, KeyError, TypeError):
                pass
        if cnt:
            t = pd.DataFrame(cnt.most_common(8), columns=["Check", "Times"])
            fig = px.bar(t, x="Times", y="Check", orientation="h", color_discrete_sequence=["#f59e0b"])
            fig.update_layout(yaxis={"autorange": "reversed"}, yaxis_title="")
            st.plotly_chart(style_fig(fig), use_container_width=True, key="an_checks")
        else:
            st.caption("No flags triggered yet.")

    a, b = st.columns(2, gap="large")
    df = df.assign(domain=df.url.map(host_of))
    with a:
        st.markdown("#### 🎯 Riskiest Domains")
        rk = (df.groupby("domain").agg(scans=("id", "count"), avg_score=("score", "mean"))
                .reset_index().sort_values("avg_score").head(8))
        rk["avg_score"] = rk.avg_score.round(1)
        st.dataframe(rk, hide_index=True, use_container_width=True,
                     column_config={"avg_score": st.column_config.ProgressColumn(
                         "Avg score", min_value=0, max_value=100)})
    with b:
        st.markdown("#### 🌐 Scan Sources")
        src = df.source.fillna("scanner").value_counts().reset_index()
        src.columns = ["Source", "Scans"]
        fig = px.bar(src, x="Source", y="Scans", color_discrete_sequence=["#818cf8"])
        st.plotly_chart(style_fig(fig, 260), use_container_width=True, key="an_src")
    st.caption("All numbers come from your own scans. Detection is rule-based, so no "
               "'AI accuracy' figure is claimed unless it is measured on a labelled dataset.")


def page_history():
    hero("Scan History Database", "Search, filter, inspect and manage every scan.", "RECORDS")
    df = load_history()
    if df.empty:
        card("Nothing saved yet", "<p>Scans appear here automatically (see Settings to toggle saving).</p>")
        return
    st.markdown("### 🔎 Search & Filter")
    c1, c2, c3 = st.columns([2, 1.3, 1.3])
    q = c1.text_input("Search URL:", key="h_q")
    cls = c2.multiselect("Classification", RISK_ORDER, key="h_cls")
    lo, hi = c3.slider("Score range", 0, 100, (0, 100), key="h_rng")
    view = df[(df.score >= lo) & (df.score <= hi)]
    if q:
        view = view[view.url.str.contains(q, case=False, regex=False)]
    if cls:
        view = view[view.classification.isin(cls)]
    show = view.drop(columns=["findings"]).rename(columns={
        "id": "ID", "url": "Target URL", "score": "Safety Score", "classification": "Classification",
        "source": "Source", "timestamp": "Timestamp"})
    st.dataframe(show, use_container_width=True, hide_index=True, height=340,
                 column_config={"Safety Score": st.column_config.ProgressColumn(
                     "Safety Score", min_value=0, max_value=100)})
    d1, d2 = st.columns([3, 1])
    d1.caption(f"{len(view)} of {len(df)} records shown")
    d2.download_button("⬇️ Export filtered", show.to_csv(index=False).encode(),
                       "filtered_history.csv", "text/csv", use_container_width=True)

    st.markdown("### 🔬 Inspect a Record")
    if view.empty:
        st.caption("No records match the filters.")
    else:
        pick = st.selectbox("Choose a record", view.id.tolist(),
                            format_func=lambda i: f"#{i}  -  {view[view.id == i].url.iloc[0][:70]}")
        row = view[view.id == pick].iloc[0]
        try:
            fnd = json.loads(row.findings or "[]")
        except ValueError:
            fnd = []
        st.markdown(f'{badge(row.classification)} &nbsp; score **{row.score}** &nbsp; · &nbsp; {row.timestamp}',
                    unsafe_allow_html=True)
        st.markdown(checks_html(fnd) or "_No stored details._", unsafe_allow_html=True)

    st.markdown("### 🗑️ Delete Records")
    ids = st.multiselect("Select record ID(s) to delete:", df.id.tolist(), key="h_del")
    if st.button("Delete Selected", disabled=not ids):
        delete_ids(ids)
        st.toast(f"Deleted {len(ids)} record(s).", icon="🗑️")
        st.rerun()
    st.write("")
    sure = st.checkbox("I understand this permanently deletes ALL history", key="h_sure")
    if st.button("🗑️ Clear Entire History", disabled=not sure):
        clear_all()
        st.toast("History cleared.", icon="🧹")
        st.rerun()


def build_html_report(df):
    low = int((df.classification == "LOW RISK").sum())
    risky = df[df.classification.isin(["HIGH RISK", "CRITICAL"])]
    rows = "".join(
        f"<tr><td>{r.id}</td><td>{html.escape(r.url)}</td><td>{r.score}</td>"
        f"<td style='color:{RISK_COLORS.get(r.classification, '#000')};font-weight:700'>{r.classification}</td>"
        f"<td>{r.timestamp}</td></tr>"
        for r in df.itertuples()
    )
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Cyber Intel Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px;color:#0f172a}}h1{{color:#2563eb}}
.k{{display:inline-block;margin:6px 10px 6px 0;padding:12px 20px;border:1px solid #cbd5e1;border-radius:10px}}
.k b{{display:block;font-size:24px}}table{{border-collapse:collapse;width:100%;margin-top:18px;font-size:13px}}
th,td{{border:1px solid #e2e8f0;padding:6px 10px;text-align:left}}th{{background:#f1f5f9}}</style></head><body>
<h1>Cyber Intel - Security Report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M}</p>
<div class="k"><b>{len(df)}</b>Total scans</div><div class="k"><b>{low}</b>Low risk</div>
<div class="k"><b>{len(risky)}</b>High / critical</div><div class="k"><b>{df.score.mean():.1f}</b>Avg score</div>
<table><tr><th>ID</th><th>URL</th><th>Score</th><th>Class</th><th>Time</th></tr>{rows}</table>
<p style="margin-top:20px;color:#64748b;font-size:12px">Rule-based screening. Not a guarantee of safety.</p>
</body></html>"""


def build_markdown_report(df):
    risky = df[df.classification.isin(["HIGH RISK", "CRITICAL"])]
    lines = [
        "# Cyber Intel Summary Report",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}", "",
        f"- Total scans: **{len(df)}**",
        f"- Average safety score: **{df.score.mean():.1f}**", "", "## Breakdown",
        *[f"- {k}: {int((df.classification == k).sum())}" for k in RISK_ORDER],
        "", "## High / Critical URLs",
        *([f"- `{defang(r.url)}` (score {r.score})" for r in risky.itertuples()] or ["- None"]),
    ]
    return "\n".join(lines)


def page_reports():
    hero("Security Report Generation", "Export your findings in the format your team needs.", "REPORTS")
    df = load_history()
    if df.empty:
        card("No data to export", "<p>Run some scans first.</p>")
        return
    k = st.columns(4)
    kpi(k[0], len(df), "Records", "🗂️")
    kpi(k[1], int((df.classification == "LOW RISK").sum()), "Low risk", "✅", "#22c55e")
    kpi(k[2], int(df.classification.isin(["HIGH RISK", "CRITICAL"]).sum()), "High / critical", "🚨", "#ef4444")
    kpi(k[3], f"{df.score.mean():.1f}", "Avg score", "📈", "#818cf8")
    st.write("")
    plain = df.drop(columns=["findings"])
    c = st.columns(4)
    c[0].download_button("📥 CSV Report", plain.to_csv(index=False).encode(),
                         "cyber_intel_report.csv", "text/csv", use_container_width=True)
    c[1].download_button("🧾 JSON (full)", df.to_json(orient="records", indent=2).encode(),
                         "cyber_intel_report.json", "application/json", use_container_width=True)
    c[2].download_button("🌐 HTML Report", build_html_report(df).encode(),
                         "cyber_intel_report.html", "text/html", use_container_width=True)
    c[3].download_button("📝 Markdown", build_markdown_report(df).encode(),
                         "cyber_intel_summary.md", "text/markdown", use_container_width=True)
    st.divider()
    st.subheader("Preview")
    st.markdown(build_markdown_report(df))


QUIZ = [
    ("Which link really goes to PayPal?",
     ["paypal.com.secure-login.xyz/verify", "www.paypal.com/signin", "paypa1.com/signin"], 1,
     "The real domain is the part right before the extension. Only www.paypal.com ends in paypal.com."),
    ("A text says 'Your account is suspended. Verify in 10 minutes!' What is the main red flag?",
     ["It mentions your account", "Artificial urgency", "It came by SMS"], 1,
     "Urgency is designed to stop you thinking. Real companies do not demand action in minutes."),
    ("What does http://google.com@evil.xyz open?",
     ["google.com", "evil.xyz", "Nothing"], 1,
     "Everything before '@' is treated as a username. The browser goes to evil.xyz."),
    ("You clicked a bad link and typed a password. First step?",
     ["Ignore it", "Change that password on the real site and enable 2FA", "Restart the phone"], 1,
     "Change the password immediately (and anywhere you reused it), then turn on two-factor authentication."),
    ("Which is the safest way to open your bank's site?",
     ["Click the link in an email", "Type the address or use the official app", "Search and click the first ad"], 1,
     "Typing the address or using the official app avoids look-alike links and sponsored fakes."),
]


def page_education():
    hero("Phishing Awareness Centre", "Learn to spot scams yourself. The best protection is a trained eye.", "EDUCATION")
    t1, t2, t3, t4, t5 = st.tabs(["🎣 Basics", "🚩 Red flags", "🧠 Quiz", "🆘 If you clicked", "⚙️ How scanning works"])
    with t1:
        card("What is phishing?",
             "<p>Phishing is a scam where attackers pretend to be a trusted brand or person to steal "
             "passwords, OTPs or card details, or to make you install malware. It arrives by email, SMS, "
             "WhatsApp, social media or even QR codes.</p>")
        card("Common types",
             "<ul><li><b>Email phishing</b> - mass fake notices.</li><li><b>Spear phishing</b> - targeted at you "
             "by name.</li><li><b>Smishing / Vishing</b> - SMS and phone calls.</li>"
             "<li><b>Clone sites</b> - pixel-perfect copies of login pages.</li></ul>")
    with t2:
        flags = [
            ("🎭", "Hidden host", "paypal.com@evil.xyz really opens evil.xyz."),
            ("🔤", "Look-alike spelling", "paypa1.com, g00gle.com, micros0ft.com."),
            ("⏰", "Urgency & threats", "Suspended, expires today, last warning."),
            ("🎁", "Too good to be true", "Free phones, prizes, lottery winners."),
            ("🔗", "Shortened links", "bit.ly hides where you will land."),
            ("📎", "Unexpected files", ".exe, .apk, .zip attachments or downloads."),
        ]
        cols = st.columns(3)
        for i, (ic, t, d) in enumerate(flags):
            with cols[i % 3]:
                card(f"{ic} {t}", f"<p>{d}</p>")
    with t3:
        st.write("Test yourself. Five quick questions.")
        with st.form("quiz"):
            answers = [st.radio(f"{i + 1}. {q}", opts, index=None, key=f"quiz_{i}")
                       for i, (q, opts, _, _) in enumerate(QUIZ)]
            done = st.form_submit_button("Check my answers")
        if done:
            if any(a is None for a in answers):
                st.warning("Please answer every question.")
            else:
                score = 0
                for i, (q, opts, correct, why) in enumerate(QUIZ):
                    ok = answers[i] == opts[correct]
                    score += ok
                    (st.success if ok else st.error)(f"Q{i + 1}: {'Correct' if ok else 'Not quite'}. {why}")
                st.markdown(f"### Your score: {score} / {len(QUIZ)}")
                if score == len(QUIZ):
                    st.balloons()
    with t4:
        card("Act in this order",
             "<ol><li>Disconnect: close the page, do not enter more data.</li>"
             "<li>Change the password on the <b>real</b> site, and anywhere it was reused.</li>"
             "<li>Turn on two-factor authentication.</li>"
             "<li>Call your bank if money or cards were involved.</li>"
             "<li>Scan the device for malware.</li>"
             "<li>Report: India - cybercrime.gov.in or call 1930.</li></ol>")
    with t5:
        st.write("Each check subtracts points from 100. Sensitivity in Settings scales the penalties.")
        cat = pd.DataFrame(CHECK_CATALOG, columns=["Check", "What it looks for", "Max penalty"])
        st.dataframe(cat, hide_index=True, use_container_width=True)
        card("Limits", "<p>The scanner does not open the site, so it cannot read page content, check "
             "domain age or query reputation databases. Treat it as a fast first screen.</p>")


def page_settings():
    hero("Settings & Lists", "Tune detection strictness and manage your own trusted / blocked domains.", "CONFIGURATION")
    st.markdown("### 🎚️ Detection sensitivity")
    st.radio("Sensitivity", list(SENSITIVITY), horizontal=True, key="sensitivity",
             help="Lenient x0.75, Balanced x1.0, Strict x1.3 on every penalty.")
    st.toggle("Save every scan to history", key="autosave")
    st.divider()

    a, b = st.columns(2, gap="large")
    for col, kind, title, icon in ((a, "allow", "Trusted domains (allowlist)", "✅"),
                                   (b, "block", "Blocked domains (blocklist)", "⛔")):
        with col:
            st.markdown(f"### {icon} {title}")
            with st.form(f"form_{kind}", clear_on_submit=True):
                new = st.text_input("Add domain", placeholder="example.com", key=f"new_{kind}")
                if st.form_submit_button("Add"):
                    if add_list(kind, new):
                        st.toast(f"Added {clean_domain(new)}", icon=icon)
                    else:
                        st.warning("Enter a valid domain such as example.com")
            rows = get_list(kind)
            if not rows:
                st.caption("Empty.")
            for rid, dom in rows:
                r1, r2 = st.columns([4, 1])
                r1.markdown(f'<span class="mono">{html.escape(dom)}</span>', unsafe_allow_html=True)
                r2.button("✖", key=f"rm_{kind}_{rid}", on_click=remove_list, args=(rid,))
    st.divider()
    st.markdown("### 🗄️ Database")
    df = load_history()
    st.caption(f"File: `{DB_PATH}`  ·  {len(df)} saved scans  ·  version {APP_VERSION}")
    st.info("On Streamlit Community Cloud the local SQLite file can reset when the app restarts. "
            "Use an external database for permanent history.")


# =============================================================================
# 7. ROUTER
# =============================================================================
PAGES = {
    "🔍 Scanner": page_scanner,
    "📦 Batch Scanner": page_batch,
    "📊 Global Analytics": page_analytics,
    "🕒 Scan History": page_history,
    "📄 Security Reports": page_reports,
    "ℹ️ Education": page_education,
    "⚙️ Settings": page_settings,
}

st.session_state.setdefault("sensitivity", "Balanced")
st.session_state.setdefault("autosave", True)
st.session_state.setdefault("nav", list(PAGES)[0])

with st.sidebar:
    st.markdown(
        f'<div class="sidebar-logo"><div class="l1">🛡️ {APP_NAME}</div>'
        f'<div class="l2">PHISHING DEFENCE v{APP_VERSION}</div></div>',
        unsafe_allow_html=True,
    )
    st.caption("NAVIGATION")
    choice = st.radio("Navigation", list(PAGES), key="nav", label_visibility="collapsed")
    st.divider()
    hist = load_history()
    s1, s2 = st.columns(2)
    s1.metric("Scans", len(hist))
    s2.metric("Avg score", f"{hist.score.mean():.0f}" if len(hist) else "-")
    st.caption(f"Sensitivity: **{st.session_state['sensitivity']}**")
    st.caption("Rule-based screening. Not a substitute for judgement.")

PAGES[choice]()
