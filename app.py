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
import unicodedata
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta
from urllib.parse import parse_qsl, unquote, urlparse

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# =============================================================================
# 1. CONFIG & THEME
# =============================================================================
APP_NAME = "CYBER INTEL"
APP_VERSION = "3.1"
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
    "github": {"github.com", "githubusercontent.com", "github.io"},
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
    "github.io", "vercel.app", "workers.dev", "duckdns.org", "ngrok.io", "appspot.com",
)
# Free hosts belong to a brand but anyone can publish there, so they are never auto-trusted.
TRUSTED -= set(FREE_HOSTS)
# Big-brand platforms where ANYONE can publish a page. A trusted name does not make the content trusted.
USER_CONTENT_HOSTS = (
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "onedrive.live.com", "1drv.ms", "sharepoint.com", "notion.site",
    "typeform.com", "canva.com", "s3.amazonaws.com", "blob.core.windows.net",
    "lovable.app", "lovableproject.com", "manus.space", "replit.app", "repl.co",  # AI / app-builder hosting
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
    "phishing", "malware",
]
SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "gov.in", "ac.in",
    "nic.in", "co.jp", "com.br", "co.nz", "co.za", "com.sg", "edu.au", "net.in", "org.in",
}
SENSITIVITY = {"Lenient": 0.75, "Balanced": 1.0, "Strict": 1.3}

CHECK_CATALOG = [
    ("HTTPS Protocol", "Is the connection encrypted? (HTTPS alone never proves a site is safe)", 15),
    ("IP Address in URL", "Raw or obfuscated IP instead of a domain name", 35),
    ("Credentials / '@' Trick", "Text before '@' hides the real host", 45),
    ("URL Shortener", "Real destination is hidden", 20),
    ("Suspicious Keywords", "login, verify, giveaway, kyc ...", 24),
    ("Brand Impersonation", "Brand name or typo of one on an unrelated domain", 30),
    ("Brand + Credential Lure", "Brand name combined with login / verify words", 15),
    ("Domain Extension (TLD)", "TLDs heavily abused by attackers", 15),
    ("Punycode / Homograph", "Look-alike international characters imitating a brand", 50),
    ("Free Hosting Service", "Throw-away hosting subdomains", 8),
    ("Risky File Download", "Executable or archive in the path", 20),
    ("URL Encoding", "Many %XX characters to hide content", 10),
    ("URL Length", "Very long URLs hide the real host", 10),
    ("Excessive Subdomains", "Many levels like a.b.c.d.example.com", 15),
    ("Hyphens / Digits / Entropy", "Machine-generated looking domain", 24),
    ("Non-standard Port", "Ports other than 80/443", 10),
    ("User-Content Platform", "Page hosted where anyone can publish (Google Sites, Forms, OneDrive ...)", 12),
    ("Open Redirect Pattern", "Query string forwards visitors to another site", 30),
    ("Dark-web (.onion) Address", "Tor hidden-service address", 45),
    ("Source Reputation", "Who runs the site: dark-web directory, piracy, community / opinion content, "
     "or an established source (caps the score)", 85),
    ("Blocklist / Threat Feed", "Domain is on your own blocklist or imported feed", 100),
]

# =============================================================================
# 3. DETECTION ENGINE
# =============================================================================
# --- Source reputation -------------------------------------------------------------------------
# Link checks only see the SHAPE of a URL. Reputation is a separate axis: who runs the site.
# A rating CAPS the final score, so a clean-looking address can still come out as Medium/High/Critical.
LEVEL_CAP = {"LOW RISK": 100, "MEDIUM RISK": 70, "HIGH RISK": 45, "CRITICAL": 15}
LEVEL_WORDS = {
    "LOW RISK": ("low", "safe", "trusted", "good"),
    "MEDIUM RISK": ("medium", "moderate", "caution", "verify"),
    "HIGH RISK": ("high", "danger", "unsafe"),
    "CRITICAL": ("critical", "highest", "severe", "extreme"),
}
# Starter ratings: (domain, level, category, note). Rated by CATEGORY (what the site is), never by politics.
# Edit or extend them in Settings > Source reputation, or with an optional reputation.csv next to app.py.
DEFAULT_REPUTATION = [
    ("reuters.com", "LOW RISK", "Established news agency", ""),
    ("apnews.com", "LOW RISK", "Established news agency", ""),
    ("bbc.com", "LOW RISK", "Public broadcaster", ""),
    ("bbc.co.uk", "LOW RISK", "Public broadcaster", ""),
    ("nih.gov", "LOW RISK", "Government research agency", ""),
    ("cdc.gov", "LOW RISK", "Government health agency", ""),
    ("who.int", "LOW RISK", "Intergovernmental health agency", ""),
    ("nature.com", "LOW RISK", "Peer-reviewed publisher", ""),
    ("science.org", "LOW RISK", "Peer-reviewed publisher", ""),
    ("thelancet.com", "LOW RISK", "Peer-reviewed publisher", ""),
    ("nejm.org", "LOW RISK", "Peer-reviewed publisher", ""),
    ("jstor.org", "LOW RISK", "Academic archive", ""),
    ("wikipedia.org", "LOW RISK", "Reference encyclopedia", "Community-edited; check the citations."),
    ("medium.com", "MEDIUM RISK", "Open publishing platform", "Anyone can publish; judge each author."),
    ("stackoverflow.com", "MEDIUM RISK", "Community Q&A", "Answers are user-written; verify before running code."),
    ("quora.com", "MEDIUM RISK", "Community Q&A", "Answers are user-written."),
    ("answers.com", "MEDIUM RISK", "Community Q&A", "Answers are user-written."),
    ("forbes.com", "MEDIUM RISK", "Mixed editorial and contributor content",
     "Staff reporting sits beside contributor and sponsored posts."),
    ("aa.com.tr", "MEDIUM RISK", "State-affiliated news agency", "Check who owns the source."),
    ("theamericanconservative.com", "MEDIUM RISK", "Opinion / advocacy publication",
     "Openly ideological; read as opinion."),
    ("alternet.org", "MEDIUM RISK", "Opinion / advocacy publication", "Openly ideological; read as opinion."),
    ("fmovies.to", "HIGH RISK", "Piracy streaming site", "Illegal streaming; known for malicious ads."),
    ("thepiratebay.org", "HIGH RISK", "Torrent / piracy index", "Illegal downloads; malware risk."),
    ("1337x.to", "HIGH RISK", "Torrent / piracy index", "Illegal downloads; malware risk."),
    ("thehiddenwiki.org", "CRITICAL", "Dark-web link directory", "Do not visit."),
    ("tor.taxi", "CRITICAL", "Dark-web link directory", "Do not visit."),
    ("dark.fail", "CRITICAL", "Dark-web link directory", "Do not visit."),
    ("darkfail.net", "CRITICAL", "Dark-web link directory or look-alike", "Do not visit."),
]


def normalize_level(text):
    """'low', 'Medium', 'HIGH RISK', 'critical' ... -> one of RISK_ORDER, or None."""
    t = str(text or "").strip().lower().replace(" risk", "")
    for level, words in LEVEL_WORDS.items():
        if t in words:
            return level
    return None


def reputation_for(host, table):
    """Longest-suffix match: 'www.reuters.com' -> reuters.com. Returns (domain, (level, category, note))."""
    labels = (host or "").split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in (table or {}):
            return cand, table[cand]
    return None


# Look-alike letters (Cyrillic / Greek) mapped to the Latin letter they imitate.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g", "ɑ": "a", "ο": "o", "ν": "v", "α": "a",
    "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "м": "m", "т": "t", "к": "k",
})
# Query parameters that commonly carry a "send the visitor here next" address.
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "redir", "next", "target", "dest",
    "destination", "goto", "return", "returnurl", "return_to", "continue", "link", "out", "u",
}


def decode_idna(host: str) -> str:
    """Punycode (xn--...) to readable Unicode; returns host unchanged if not decodable."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def skeleton(text: str) -> str:
    """Fold look-alike characters to plain Latin so 'аpple' (Cyrillic а) becomes 'apple'."""
    return unicodedata.normalize("NFKC", text).lower().translate(CONFUSABLES)


def scripts_in(label: str) -> set:
    return {unicodedata.name(ch, "UNKNOWN").split()[0] for ch in label if ch.isalpha()}


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


def analyze_url(raw, sensitivity="Balanced", allow=None, block=None, reputation=None):
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
    raw_unicode = bool(host) and not host.isascii()
    if raw_unicode:  # user typed an international name directly: convert to punycode first
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return _invalid(raw, "Invalid international hostname")
    valid_host = re.fullmatch(r"[a-z0-9\-._\[\]:]+", host or "") and ("." in host or ":" in host)
    if re.search(r"\s", url) or not valid_host:
        return _invalid(raw, "Not a valid URL (spaces or invalid hostname)")

    full_lower = unquote(url).lower()
    path_q = unquote((p.path or "") + "?" + (p.query or "")).lower()
    reg = registered_domain(host)
    sld = reg.split(".")[0]
    tld = host.split(".")[-1]
    allowed = reg in allow or host in allow
    ugc = any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS) and not allowed
    trusted = (reg in TRUSTED or host.endswith(TRUSTED_SUFFIXES) or allowed) and not ugc
    rep = reputation_for(host, reputation)
    if rep and rep[1][0] == "LOW RISK":
        trusted = True  # an established source: do not penalise ordinary words in its URLs

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
        tokens |= {deleet(t) for t in tokens if t and not t.startswith("xn--")}  # g00gle -> google
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
        if hits:  # HTTPS does not make "brand + login" on a foreign domain trustworthy
            add("Brand + Credential Lure", "fail",
                "Brand name combined with words like " + ", ".join(hits[:3]), 15)
    else:
        add("Brand Impersonation", "pass", "Not detected")

    # 7 TLD --------------------------------------------------------------------
    if tld in SUSPICIOUS_TLDS and not is_ip:
        add("Domain Extension (TLD)", "warn", f".{tld} is frequently abused", 15)
    else:
        add("Domain Extension (TLD)", "pass", f".{tld}" if not is_ip else "n/a (IP host)")

    # 8 punycode ---------------------------------------------------------------
    if tld == "onion":
        add("Dark-web (.onion) Address", "fail",
            "Tor hidden-service address. Do not open outside Tor and treat with extreme caution.", 45)
    decoded = decode_idna(host)
    if decoded != host or raw_unicode or "xn--" in host:
        dreg = registered_domain(decoded)
        sk = skeleton(dreg.split(".")[0])
        look = sk if (sk in BRANDS and reg not in BRANDS[sk]) else None
        mixed = any(len(scripts_in(lb)) > 1 for lb in decoded.split("."))
        bits = [f"Decodes to '{decoded}'"]
        if mixed:
            bits.append("mixes alphabets inside one name")
        if look:
            bits.append(f"visually imitates '{look}'")
        add("Punycode / Homograph", "fail", "; ".join(bits),
            20 + (10 if mixed else 0) + (20 if look else 0))
    else:
        add("Punycode / Homograph", "pass", "Not detected")

    # 9 free hosting -----------------------------------------------------------
    if any(host == h or host.endswith("." + h) for h in FREE_HOSTS) and reg not in allow:
        add("Free Hosting Service", "warn", "Hosted on a free / throw-away platform", 8)
    else:
        add("Free Hosting Service", "pass", "Not detected")

    # 9b user-content platforms (sites.google.com, forms.gle ...) ---------------
    if ugc:
        add("User-Content Platform", "warn",
            "Anyone can publish pages here; the trusted brand name does not vouch for this page", 12)
    else:
        add("User-Content Platform", "pass", "Not detected")

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
        plain = not sld.startswith("xn--")  # punycode labels naturally contain digits
        if plain and len(sld) > 4 and sum(c.isdigit() for c in sld) / len(sld) > 0.3:
            problems.append("many digits")
        if plain and len(sld) > 12 and entropy(sld) > 3.6:
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

    # 16 open redirect (static analysis only - the link is never opened) -------
    targets = []
    for k, v in parse_qsl(p.query or "", keep_blank_values=True):
        if k.lower() in REDIRECT_PARAMS and re.match(r"^(https?:)?//", v.strip(), re.I):
            targets.append(v.strip())
    m = re.search(r"/(https?://[^/?#]+)", p.path or "", re.I)
    if m and not targets:
        targets.append(m.group(1))
    if targets:
        t = targets[0]
        try:
            t_host = (urlparse(("http:" + t) if t.startswith("//") else t).hostname or "").lower()
        except ValueError:
            t_host = ""
        t_reg = registered_domain(t_host) if t_host else ""
        if t_reg and t_reg != reg and not (trusted and t_reg in TRUSTED):
            risky_t = t_host.split(".")[-1] in SUSPICIOUS_TLDS or bool(re.fullmatch(r"[\d.]+", t_host))
            add("Open Redirect Pattern", "fail",
                f"Forwards visitors to a different site: {t_host}", 20 + (10 if risky_t else 0))
        else:
            add("Open Redirect Pattern", "pass", "Redirect stays on the same or a trusted site")
    else:
        add("Open Redirect Pattern", "pass", "Not detected")

    # 17 blocklist / threat feed ----------------------------------------------
    if reg in block or host in block:
        add("Blocklist / Threat Feed", "fail", "Domain is on your blocklist", 100)
    else:
        add("Blocklist / Threat Feed", "pass", "Not on your blocklist")

    # 18 source reputation: caps the score so a clean-looking address cannot hide a bad site --------
    if rep:
        domain, (level, category, note) = rep
        base = max(0, 100 - sum(f["penalty"] for f in findings))
        extra = max(0, base - LEVEL_CAP[level])
        status = {"LOW RISK": "pass", "MEDIUM RISK": "warn"}.get(level, "fail")
        detail = f"{category} ({domain})" + (f". {note}" if note else "")
        findings.insert(0, {"check": "Source Reputation", "status": status, "detail": detail, "penalty": extra})
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
    """Yield a cursor. Uses PostgreSQL if reachable, else falls back to local SQLite (and says so)."""
    conn, on_pg = None, False
    if USE_PG and not st.session_state.get("_pg_down"):
        try:
            import psycopg2
            conn = psycopg2.connect(DATABASE_URL, connect_timeout=8)
            on_pg = True
        except Exception as exc:
            st.session_state["_pg_down"] = explain_db_error(exc)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        cur = conn.cursor()
        if not (on_pg and st.session_state.get("_schema_ok")):
            for stmt in _ddl():
                cur.execute(stmt)
            if on_pg:
                st.session_state["_schema_ok"] = True
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_scan(res, source="scanner"):
    with db() as cur:
        cur.execute(
            _sql("INSERT INTO scans(url,score,classification,findings,source,timestamp) VALUES(?,?,?,?,?,?)"),
            (res["url"], res["score"], res["label"], json.dumps(res["findings"]), source, now_str()),
        )


def load_history() -> pd.DataFrame:
    with db() as cur:
        cur.execute("SELECT id,url,score,classification,findings,source,timestamp FROM scans ORDER BY id DESC")
        rows = cur.fetchall()
    return pd.DataFrame(rows, columns=HISTORY_COLS)


def delete_ids(ids):
    with db() as cur:
        cur.executemany(_sql("DELETE FROM scans WHERE id=?"), [(int(i),) for i in ids])


def clear_all():
    with db() as cur:
        cur.execute("DELETE FROM scans")


def get_list(kind):
    with db() as cur:
        cur.execute(_sql("SELECT id, domain FROM lists WHERE kind=? ORDER BY domain"), (kind,))
        return list(cur.fetchall())


def add_list(kind, domain):
    domain = clean_domain(domain)
    if not valid_domain(domain):
        return False
    with db() as cur:
        cur.execute(_sql("INSERT INTO lists(kind,domain) VALUES(?,?) ON CONFLICT (kind, domain) DO NOTHING"),
                    (kind, domain))
    return True


def remove_list(row_id):
    with db() as cur:
        cur.execute(_sql("DELETE FROM lists WHERE id=?"), (int(row_id),))


def scan(raw, source="scanner"):
    """Analyse one link with the current settings, lists and reputation, and optionally save it."""
    res = analyze_with_rules(raw, load_rules())
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
        f'<span class="mono">{html.escape(defang(res["url"]))}</span></div>'
        f'<div style="color:#8ea3c4;font-size:.75rem;margin-top:6px">Engine v{APP_VERSION} · '
        f'{len(res["findings"])} checks evaluated · {html.escape(res.get("scanned_at", ""))}</div></div>',
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
        if not any(f["check"] == "Source Reputation" for f in res["findings"]):
            st.caption("ℹ️ This domain is not in the reputation list, so the verdict reflects the link's "
                       "structure only. Rate it under Settings > Source reputation.")
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
    st.button(label, key=f"chip_{label}", use_container_width=True, on_click=set_example, args=(url,))


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

    # The scanner reads the text box value DIRECTLY from the form. It is never copied through
    # session_state, so a stale value can never be scanned by mistake.
    with st.form("scan_form", clear_on_submit=False):
        typed = st.text_input("TARGET URL:", value=st.session_state.get("prefill", ""),
                              key=f"url_box_{st.session_state.get('url_nonce', 0)}",
                              placeholder="https://example.com/login")
        go_scan = st.form_submit_button("INITIATE DEEP SCAN 🚀")
    auto = st.session_state.pop("autoscan", False)  # set by "Scan this link" buttons
    if go_scan or auto:
        target = (typed if go_scan else st.session_state.get("prefill", "")).strip()
        if not target:
            st.warning("Please enter a URL first.")
        else:
            st.session_state["prefill"] = target
            with st.spinner("Analysing URL structure, domain and reputation patterns..."):
                st.session_state["last"] = scan(target)
    if "last" in st.session_state:
        st.divider()
        render_result(st.session_state["last"], "single")
    else:
        card("How it works",
             "<p>Two things decide the verdict. <b>Link structure</b>: encryption, hidden hosts, look-alike "
             "brands, open redirects, risky extensions. <b>Source reputation</b>: who runs the site "
             "(dark-web directory, piracy site, community or opinion content, established source). "
             "The scanner never opens the site, so it is safe to test dangerous links.</p>")
    st.write("")
    with st.expander("🧪 Verify the scanner is working (self-test)",
                     expanded=st.session_state.get("selftest_rows") is not None):
        st.caption("Runs known safe and dangerous-looking links through the engine. Every row should say PASS "
                   "and the verdicts must differ between links.")
        st.button("Run self-test", key="run_selftest",
                  on_click=lambda: st.session_state.update(selftest_rows=run_self_test()))
        rows = st.session_state.get("selftest_rows")
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
            passed = sum(r["Result"] == "PASS" for r in rows)
            (st.success if passed == len(rows) else st.error)(
                f"{passed} / {len(rows)} checks passed (engine v{APP_VERSION})")


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
    urls, dupes, run_paste, run_file = [], 0, False, False
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
        unique = list(dict.fromkeys(urls))
        dupes = len(urls) - len(unique)
        urls = unique
        if len(urls) > MAX_BATCH:
            st.info(f"Only the first {MAX_BATCH} unique URLs are scanned (limit protects the server).")
            urls = urls[:MAX_BATCH]
        bar, rows, results = st.progress(0.0, text="Scanning..."), [], []
        rules = load_rules()  # once for the whole batch
        for i, u in enumerate(urls, 1):
            r = analyze_with_rules(u, rules)
            results.append(r)
            flags = [f["check"] for f in r["findings"] if f["status"] != "pass"]
            rows.append({"URL": r["url"], "Score": r["score"], "Classification": r["label"],
                         "Flags": ", ".join(flags) or "-"})
            bar.progress(i / len(urls), text=f"Scanned {i} of {len(urls)}")
        bar.empty()
        if st.session_state.get("autosave", True):
            save_scans(results, "batch")
        st.session_state["batch_df"] = pd.DataFrame(rows)
        st.session_state["batch_dupes"] = dupes
    elif run_paste or run_file:
        st.warning("No URLs found. Paste some links or upload a file first.")

    df = st.session_state.get("batch_df")
    if df is None or df.empty:
        return
    st.divider()
    bd = breakdown(df, "Classification")
    k = st.columns(6)
    kpi(k[0], len(df), "Scanned", "🔎")
    kpi(k[1], bd["LOW RISK"], "Low risk", "✅", RISK_COLORS["LOW RISK"])
    kpi(k[2], bd["MEDIUM RISK"], "Medium risk", "⚠️", RISK_COLORS["MEDIUM RISK"])
    kpi(k[3], bd["HIGH RISK"], "High risk", "🚨", RISK_COLORS["HIGH RISK"])
    kpi(k[4], bd["CRITICAL"], "Critical", "⛔", RISK_COLORS["CRITICAL"])
    kpi(k[5], round(df.Score.mean(), 1), "Average score", "📈", "#818cf8")
    note = f"{bd['LOW RISK']} + {bd['MEDIUM RISK']} + {bd['HIGH RISK']} + {bd['CRITICAL']} = {len(df)} URLs."
    if st.session_state.get("batch_dupes"):
        note += f" {st.session_state['batch_dupes']} duplicate line(s) were removed before scanning."
    st.caption(note)
    st.write("")
    a, b = st.columns([1.7, 1], gap="large")
    with a:
        st.dataframe(
            df.sort_values("Score"), use_container_width=True, hide_index=True, height=360,
            column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100)},
        )
    with b:
        cnt = pd.DataFrame({"Risk": RISK_ORDER, "Count": [bd[k] for k in RISK_ORDER]})
        cnt = cnt[cnt.Count > 0]
        fig = px.pie(cnt, names="Risk", values="Count", hole=0.6, color="Risk",
                     color_discrete_map=RISK_COLORS)
        st.plotly_chart(style_fig(fig, 360), use_container_width=True, key="batch_pie")
    st.download_button("⬇️ Download batch results (CSV)", csv_safe(df).to_csv(index=False).encode(),
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

    bd = breakdown(df)
    k = st.columns(6)
    kpi(k[0], len(df), "Total scans", "🔎")
    kpi(k[1], bd["LOW RISK"], "Low risk", "✅", RISK_COLORS["LOW RISK"])
    kpi(k[2], bd["MEDIUM RISK"], "Medium risk", "⚠️", RISK_COLORS["MEDIUM RISK"])
    kpi(k[3], bd["HIGH RISK"], "High risk", "🚨", RISK_COLORS["HIGH RISK"])
    kpi(k[4], bd["CRITICAL"], "Critical", "⛔", RISK_COLORS["CRITICAL"])
    kpi(k[5], round(df.score.mean(), 1), "Avg safety score", "📈", "#818cf8")
    st.caption(f"{bd['LOW RISK']} + {bd['MEDIUM RISK']} + {bd['HIGH RISK']} + {bd['CRITICAL']} "
               f"= {sum(bd.values())} scans (matches the table and charts below).")
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
    d2.download_button("⬇️ Export filtered", csv_safe(show).to_csv(index=False).encode(),
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
    esc, b, n = html.escape, breakdown(df), len(df)
    top = triggered_checks(df).most_common(8)
    shown = df.head(MAX_REPORT_ROWS)
    p = [f"<!doctype html><html><head><meta charset='utf-8'><title>Cyber Intel Report</title>"
         f"<style>{REPORT_CSS}</style></head><body>",
         "<h1>Cyber Intel - Security Report</h1>",
         f"<p class='small'>Generated {datetime.now():%Y-%m-%d %H:%M} &middot; app v{APP_VERSION} &middot; "
         f"sensitivity: {esc(st.session_state.get('sensitivity', 'Balanced'))}</p>",
         "<h2>1. Overall security summary</h2>", f"<p>{esc(posture_text(df))}</p>"]
    for label, val in (("Total scans", n), ("Average score", f"{df.score.mean():.1f}")):
        p.append(f"<div class='k'><b>{val}</b>{label}</div>")
    p.append("<h2>2. Risk distribution</h2><table><tr><th>Level</th><th>Count</th><th>Share</th></tr>")
    for k in RISK_ORDER:
        share = 100 * b[k] / n if n else 0
        p.append(f"<tr><td>{k}</td><td>{b[k]}</td><td><span class='bar' style='width:{share * 3:.0f}px;"
                 f"background:{RISK_COLORS[k]}'></span> {share:.0f}%</td></tr>")
    p.append("</table><h2>3. Most frequent detection reasons</h2>")
    if top:
        p.append("<table><tr><th>Check</th><th>Times triggered</th></tr>")
        p += [f"<tr><td>{esc(c)}</td><td>{t}</td></tr>" for c, t in top]
        p.append("</table>")
    else:
        p.append("<p>No rules were triggered.</p>")
    p.append(f"<h2>4. Detection methodology</h2><p>{esc(SCORING_TEXT)}</p>"
             "<table><tr><th>Rule</th><th>What it looks for</th><th>Max penalty</th></tr>")
    p += [f"<tr><td>{esc(a)}</td><td>{esc(d)}</td><td>{m}</td></tr>" for a, d, m in CHECK_CATALOG]
    p.append("</table>")
    p.append(f"<h2>5. Individual URL analysis</h2><p class='small'>URLs are defanged (hxxp, [.]) so they "
             f"cannot be clicked by accident. Showing the latest {len(shown)} of {n} scans.</p>"
             "<table><tr><th>ID</th><th>URL</th><th>Score</th><th>Verdict</th><th>Scanned at</th>"
             "<th>Detection reasons</th></tr>")
    for r in shown.itertuples():
        reasons = reasons_of(r.findings)
        li = "".join(f"<li>{esc(x)}</li>" for x in reasons) or "No issues found"
        p.append(f"<tr><td>{r.id}</td><td>{esc(defang(r.url))}</td><td>{r.score}</td>"
                 f"<td style='color:{RISK_COLORS.get(r.classification, '#000')};font-weight:700'>"
                 f"{esc(r.classification)}</td><td>{esc(str(r.timestamp))}</td><td><ul>{li}</ul></td></tr>")
    p.append(f"</table><h2>6. Limitations</h2><p>{esc(LIMITS_TEXT)}</p></body></html>")
    return "".join(p)


def build_markdown_report(df):
    n, b = len(df), breakdown(df)
    risky = df[df.classification.isin(["HIGH RISK", "CRITICAL"])]

    def md(text):
        return str(text).replace("`", "'")
    lines = [
        "# Cyber Intel - Security Report",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M} | app v{APP_VERSION} | "
        f"sensitivity: {st.session_state.get('sensitivity', 'Balanced')}", "",
        "## 1. Overall security summary", posture_text(df), "",
        f"- Total scans: **{n}**", f"- Average safety score: **{df.score.mean():.1f}**", "",
        "## 2. Risk distribution",
        *[f"- {k}: **{b[k]}** ({(100 * b[k] / n if n else 0):.0f}%)" for k in RISK_ORDER], "",
        "## 3. Most frequent detection reasons",
        *([f"- {md(c)}: {t}" for c, t in triggered_checks(df).most_common(8)] or ["- None"]), "",
        "## 4. Detection methodology", SCORING_TEXT, "",
        "## 5. High / critical URLs (defanged)",
    ]
    if risky.empty:
        lines.append("- None")
    for r in risky.head(50).itertuples():
        lines.append(f"- `{md(defang(r.url))}` - score {r.score} ({r.classification}, {r.timestamp})")
        lines += [f"    - {md(x)}" for x in reasons_of(r.findings)]
    lines += ["", "## 6. Limitations", LIMITS_TEXT]
    return "\n".join(lines)


def page_reports():
    hero("Security Report Generation", "Export findings, reasons and methodology in the format you need.", "REPORTS")
    df = load_history()
    if df.empty:
        card("No data to export", "<p>Run some scans first.</p>")
        return
    bd = breakdown(df)
    k = st.columns(6)
    kpi(k[0], len(df), "Records", "🗂️")
    kpi(k[1], bd["LOW RISK"], "Low risk", "✅", RISK_COLORS["LOW RISK"])
    kpi(k[2], bd["MEDIUM RISK"], "Medium risk", "⚠️", RISK_COLORS["MEDIUM RISK"])
    kpi(k[3], bd["HIGH RISK"], "High risk", "🚨", RISK_COLORS["HIGH RISK"])
    kpi(k[4], bd["CRITICAL"], "Critical", "⛔", RISK_COLORS["CRITICAL"])
    kpi(k[5], f"{df.score.mean():.1f}", "Avg score", "📈", "#818cf8")
    st.write("")
    c = st.columns(4)
    c[0].download_button("📥 CSV (with reasons)", csv_safe(report_frame(df)).to_csv(index=False).encode(),
                         "cyber_intel_report.csv", "text/csv", use_container_width=True)
    c[1].download_button("🧾 JSON (full findings)", export_json(df).encode(),
                         "cyber_intel_report.json", "application/json", use_container_width=True)
    c[2].download_button("🌐 HTML report", build_html_report(df).encode(),
                         "cyber_intel_report.html", "text/html", use_container_width=True)
    c[3].download_button("📝 Markdown", build_markdown_report(df).encode(),
                         "cyber_intel_summary.md", "text/markdown", use_container_width=True)
    st.caption("Reports contain: timestamps, overall summary, risk distribution, detection reasons, "
               "per-URL analysis, methodology and limitations. URLs are defanged in HTML / Markdown.")
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
    ("The link is https://paypal-secure-login.example.com . It uses HTTPS (padlock), so it is safe.",
     ["True", "False - HTTPS only encrypts the connection, it does not prove who owns the site"], 1,
     "Attackers get HTTPS certificates too. The real domain here is example.com, not paypal.com."),
    ("You clicked a bad link and typed a password. First step?",
     ["Ignore it", "Change that password on the real site and enable 2FA", "Restart the phone"], 1,
     "Change the password immediately (and anywhere you reused it), then turn on two-factor authentication."),
    ("Which is the safest way to open your bank's site?",
     ["Click the link in an email", "Type the address or use the official app", "Search and click the first ad"], 1,
     "Typing the address or using the official app avoids look-alike links and sponsored fakes."),
    ("Which address is most likely phishing?",
     ["https://www.amazon.in/gp/css/order-history", "https://amazon-india.account-verify.click/login",
      "https://aws.amazon.com/console"], 1,
     "The real domain is account-verify.click. 'amazon' appears only as a decoy."),
    ("Someone shares a bit.ly link and says 'You won a phone!'. What should you do?",
     ["Open it quickly before it expires", "Do not open it; shorteners hide the destination and prizes are a lure",
      "Forward it to friends"], 1,
     "Unexpected prizes plus a shortened link are a classic combination."),
    ("Why can a domain like 'аpple.com' (with a Cyrillic 'а') be dangerous?",
     ["It is blocked by browsers", "It looks identical to apple.com but is a different site",
      "It is just a font difference"], 1,
     "Homograph attacks use look-alike letters from other alphabets. Always check the real domain."),
    ("Where should you report cyber fraud in India?",
     ["Only to the sender", "cybercrime.gov.in or helpline 1930", "Nowhere"], 1,
     "Report quickly: cybercrime.gov.in or call 1930. Fast reporting can help freeze money transfers."),
]


def page_education():
    hero("Phishing Awareness Centre", "Learn to spot scams yourself. The best protection is a trained eye.", "EDUCATION")
    tabs = st.tabs(["🎣 Basics", "📰 Real examples", "🚩 Red flags", "🧠 Quiz", "📈 My progress",
                    "🆘 If you clicked", "⚙️ How scanning works"])
    with tabs[0]:
        card("What is phishing?",
             "<p>Phishing is a scam where attackers pretend to be a trusted brand or person to steal "
             "passwords, OTPs or card details, or to make you install malware. It arrives by email, SMS, "
             "WhatsApp, social media or even QR codes.</p>")
        card("Common types",
             "<ul><li><b>Email phishing</b> - mass fake notices.</li><li><b>Spear phishing</b> - targeted at you "
             "by name.</li><li><b>Smishing / Vishing</b> - SMS and phone calls.</li>"
             "<li><b>Clone sites</b> - pixel-perfect copies of login pages.</li></ul>")
        card("HTTPS is not a trust badge",
             "<p>The padlock only means the connection is encrypted. Criminals use HTTPS too, so always check "
             "the <b>domain name</b>, not the padlock.</p>")
    with tabs[1]:
        st.write("Typical scam messages, rewritten as safe illustrations (made-up domains). "
                 "Press **Scan this link** to see what the scanner finds.")
        for i, (ic, title_, channel, msg, link, flags) in enumerate(REAL_EXAMPLES):
            with st.expander(f"{ic} {title_}  ·  {channel}"):
                st.markdown(f'<div class="card"><p>“{html.escape(msg)}”</p>'
                            f'<div class="mono">{html.escape(defang(link))}</div></div>', unsafe_allow_html=True)
                st.markdown("**Red flags:**\n" + "\n".join(f"- {f}" for f in flags))
                st.button("🔍 Scan this link", key=f"ex_{i}",
                          on_click=open_in_scanner, args=(link,))
    with tabs[2]:
        flags = [
            ("🎭", "Hidden host", "paypal.com@evil.xyz really opens evil.xyz."),
            ("🔤", "Look-alike spelling", "paypa1.com, g00gle.com, micros0ft.com."),
            ("🈯", "Look-alike alphabets", "Cyrillic 'а' that looks like Latin 'a'."),
            ("⏰", "Urgency & threats", "Suspended, expires today, last warning."),
            ("🎁", "Too good to be true", "Free phones, prizes, lottery winners."),
            ("🔗", "Shortened links", "bit.ly hides where you will land."),
            ("↪️", "Redirect links", "?url=http://other-site forwards you elsewhere."),
            ("📎", "Unexpected files", ".exe, .apk, .zip attachments or downloads."),
            ("🔒", "Padlock trust", "HTTPS does not mean the site is honest."),
        ]
        cols = st.columns(3)
        for i, (ic, t, d) in enumerate(flags):
            with cols[i % 3]:
                card(f"{ic} {t}", f"<p>{d}</p>")
    with tabs[3]:
        st.write(f"Test yourself. {len(QUIZ)} questions. Your score is saved so you can track progress.")
        with st.form("quiz"):
            answers = [st.radio(f"{i + 1}. {q}", opts, index=None, key=f"quiz_{i}")
                       for i, (q, opts, _, _) in enumerate(QUIZ)]
            done = st.form_submit_button("Check my answers")
        if done:
            if any(a is None for a in answers):
                st.warning("Please answer every question.")
            else:
                detail = [answers[i] == opts[c] for i, (q, opts, c, _) in enumerate(QUIZ)]
                score = sum(detail)
                for i, (q, opts, c, why) in enumerate(QUIZ):
                    if detail[i]:
                        st.success(f"Q{i + 1}: Correct. {why}")
                    else:
                        st.error(f"Q{i + 1}: Not quite. Correct answer: **{opts[c]}**. {why}")
                st.markdown(f"### Your score: {score} / {len(QUIZ)}")
                save_quiz(score, len(QUIZ), detail)
                if score == len(QUIZ):
                    st.balloons()
    with tabs[4]:
        qr = load_quiz()
        if qr.empty:
            card("No quiz attempts yet", "<p>Take the quiz to start tracking your progress.</p>")
        else:
            qr["pct"] = (100 * qr.score / qr.total).round(0)
            best, latest, avg = qr.pct.max(), qr.pct.iloc[-1], qr.pct.mean()
            level = "Phishing-savvy 🛡️" if best >= 80 else "Aware 👀" if best >= 50 else "Beginner 🌱"
            k = st.columns(4)
            kpi(k[0], len(qr), "Attempts", "📝")
            kpi(k[1], f"{best:.0f}%", "Best score", "🏆", "#22c55e")
            kpi(k[2], f"{latest:.0f}%", "Latest", "🕒", "#f59e0b")
            kpi(k[3], f"{avg:.0f}%", "Average", "📊", "#818cf8")
            st.write("")
            st.markdown(f"**Level: {level}**")
            st.progress(min(best / 100, 1.0))
            fig = px.line(qr, x="id", y="pct", markers=True, color_discrete_sequence=["#38bdf8"])
            fig.update_layout(xaxis_title="Attempt", yaxis_title="Score %", yaxis_range=[0, 100])
            st.plotly_chart(style_fig(fig, 280), use_container_width=True, key="quiz_trend")
            missed = Counter()
            for js in qr.detail.dropna():
                try:
                    for i, ok in enumerate(json.loads(js)):
                        if not ok and i < len(QUIZ):
                            missed[i] += 1
                except ValueError:
                    pass
            if missed:
                st.markdown("#### Questions you miss most")
                st.dataframe(pd.DataFrame(
                    [{"Question": QUIZ[i][0], "Times missed": t, "Attempts": len(qr)}
                     for i, t in missed.most_common(3)]), hide_index=True, use_container_width=True)
            st.button("Reset my progress", key="reset_quiz", on_click=clear_quiz)
    with tabs[5]:
        card("Act in this order",
             "<ol><li>Disconnect: close the page, do not enter more data.</li>"
             "<li>Change the password on the <b>real</b> site, and anywhere it was reused.</li>"
             "<li>Turn on two-factor authentication.</li>"
             "<li>Call your bank if money or cards were involved.</li>"
             "<li>Scan the device for malware.</li>"
             "<li>Report: India - cybercrime.gov.in or call 1930.</li></ol>")
    with tabs[6]:
        st.write("Each check subtracts points from 100. Sensitivity in Settings scales the penalties.")
        cat = pd.DataFrame(CHECK_CATALOG, columns=["Check", "What it looks for", "Max penalty"])
        st.dataframe(cat, hide_index=True, use_container_width=True)
        card("Safe by design",
             "<p>The scanner analyses the <b>text</b> of a URL. It never connects to the address, never follows "
             "redirects and never downloads anything, so scanning a dangerous link cannot harm this server "
             "(no server-side request forgery).</p>")
        card("Limits", f"<p>{html.escape(LIMITS_TEXT)}</p>")


def page_settings():
    hero("Settings & Lists", "Tune detection strictness and manage your own trusted / blocked domains.", "CONFIGURATION")
    st.markdown("### 🎚️ Detection sensitivity")
    # The real settings live in plain session keys ('sensitivity', 'autosave') which Streamlit never
    # deletes. The widgets only copy their value into them through a callback.
    opts = list(SENSITIVITY)
    current = st.session_state.get("sensitivity", "Balanced")
    st.radio("Sensitivity", opts, index=opts.index(current) if current in opts else 1, horizontal=True,
             key="w_sensitivity", help="Lenient x0.75, Balanced x1.0, Strict x1.3 on every penalty.",
             on_change=lambda: st.session_state.update(sensitivity=st.session_state["w_sensitivity"]))
    st.toggle("Save every scan to history", value=st.session_state.get("autosave", True), key="w_autosave",
              on_change=lambda: st.session_state.update(autosave=st.session_state["w_autosave"]))
    st.divider()

    a, b = st.columns(2, gap="large")
    for col, kind, title_, icon in ((a, "allow", "Trusted domains (allowlist)", "✅"),
                                    (b, "block", "Blocked domains / threat feed", "⛔")):
        with col:
            st.markdown(f"### {icon} {title_}")
            with st.form(f"form_{kind}", clear_on_submit=True):
                new = st.text_input("Add domain", placeholder="example.com", key=f"new_{kind}")
                if st.form_submit_button("Add"):
                    if add_list(kind, new):
                        st.toast(f"Added {clean_domain(new)}", icon=icon)
                    else:
                        st.warning("Enter a valid domain such as example.com")
            up = st.file_uploader("Bulk import (.txt / .csv, one domain per line)", type=["txt", "csv"],
                                  key=f"imp_{kind}")
            if st.button("Import file", key=f"impbtn_{kind}", disabled=up is None):
                text = up.getvalue().decode("utf-8", errors="ignore")
                st.toast(f"Imported {bulk_add_list(kind, parse_domains(text))} valid domain(s)", icon=icon)
            rows = get_list(kind)
            if rows:
                st.download_button("Export list", "\n".join(d for _, d in rows).encode(),
                                   f"{kind}list.txt", "text/plain", key=f"exp_{kind}")
            else:
                st.caption("Empty.")
            for rid, dom in rows[:50]:
                r1, r2 = st.columns([4, 1])
                r1.markdown(f'<span class="mono">{html.escape(dom)}</span>', unsafe_allow_html=True)
                r2.button("✖", key=f"rm_{kind}_{rid}", on_click=remove_list, args=(rid,))
            if len(rows) > 50:
                st.caption(f"Showing 50 of {len(rows)} entries.")
    st.divider()

    settings_reputation()
    st.divider()

    st.markdown("### 🗄️ Storage")
    try:
        total, _, _ = sidebar_summary()
    except Exception as exc:
        total = None
        st.error(f"Database error ({type(exc).__name__}).")
    st.caption(f"Backend: **{backend_label()}**  ·  saved scans: {total if total is not None else '?'}  ·  v{APP_VERSION}")
    if pg_active():
        st.success("Connected to PostgreSQL. History and scan counts survive restarts and redeployments.")
    elif USE_PG:
        st.error(f"DATABASE_URL is set but the database is not reachable. {st.session_state.get('_pg_down', '')} "
                 "Temporary storage is used meanwhile.")
    else:
        st.warning("History is stored in a temporary file. Streamlit Cloud wipes it whenever the app restarts, "
                   "sleeps or is redeployed (every GitHub push), so scans reset to zero. "
                   "Follow the steps below to make it permanent.")
    if USE_PG and st.button("🔌 Test database connection", key="test_db"):
        st.session_state.pop("_pg_down", None)
        st.session_state.pop("_schema_ok", None)
        try:
            sidebar_summary()
        except Exception as exc:
            st.session_state["_pg_down"] = explain_db_error(exc)
        st.rerun()
    with st.expander("How to make history permanent (free Supabase PostgreSQL)", expanded=not USE_PG):
        st.markdown(
            "1. Create a free project at **supabase.com**. Choose a database password with letters and "
            "numbers only.\n"
            "2. Click **Connect** and copy the **Session pooler** connection string (not 'Direct connection'; "
            "that one needs IPv6 and fails on Streamlit Cloud). Replace `[YOUR-PASSWORD]` with your password.\n"
            "3. In Streamlit Cloud open your app: **Manage app > Settings > Secrets** and paste:")
        st.code('DATABASE_URL = "postgresql://postgres.PROJECTREF:PASSWORD@aws-0-REGION.pooler.supabase.com:5432/postgres"',
                language="toml")
        st.markdown("4. Save. The app restarts. Return here and press **Test database connection**.\n\n"
                    "Never put this URL in GitHub. Free Supabase projects pause after a week of no use; "
                    "your data is kept and the project can be restored from the Supabase dashboard.")
    st.divider()
    card("🛡️ Security design",
         "<ul><li>URLs are analysed as text. The app <b>never opens them</b>, so there is no SSRF, "
         "no redirect following and no downloading.</li>"
         f"<li>Input limits: {MAX_URL_LEN} characters per URL, {MAX_BATCH} URLs per batch, 5000 imported domains.</li>"
         "<li>All user-supplied text is HTML-escaped before display.</li>"
         "<li>CSV exports neutralise spreadsheet formulas (CSV injection).</li>"
         "<li>Reports show defanged links (hxxp, [.]).</li>"
         "<li>Database credentials come from secrets / environment variables, never from the code.</li></ul>")


def _database_url():
    url = ""
    try:
        url = str(st.secrets.get("DATABASE_URL", "") or "")
    except Exception:  # no secrets file configured
        url = ""
    return (url or os.environ.get("DATABASE_URL", "")).strip()


DATABASE_URL = _database_url()


USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))




HISTORY_COLS = ["id", "url", "score", "classification", "findings", "source", "timestamp"]


DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+(xn--[a-z0-9]+|[a-z]{2,24})$")


def _sql(sql):
    return sql.replace("?", "%s") if pg_active() else sql


def _ddl():
    pk = "SERIAL PRIMARY KEY" if pg_active() else "INTEGER PRIMARY KEY AUTOINCREMENT"
    return [
        f"CREATE TABLE IF NOT EXISTS scans(id {pk}, url TEXT NOT NULL, score INTEGER NOT NULL, "
        "classification TEXT NOT NULL, findings TEXT, source TEXT DEFAULT 'scanner', timestamp TEXT NOT NULL)",
        f"CREATE TABLE IF NOT EXISTS lists(id {pk}, kind TEXT NOT NULL, domain TEXT NOT NULL, "
        "UNIQUE(kind, domain))",
        f"CREATE TABLE IF NOT EXISTS quiz_results(id {pk}, taken_at TEXT NOT NULL, "
        "score INTEGER NOT NULL, total INTEGER NOT NULL, detail TEXT)",
        f"CREATE TABLE IF NOT EXISTS reputation(id {pk}, domain TEXT NOT NULL UNIQUE, "
        "risk_level TEXT NOT NULL, category TEXT, note TEXT)",
    ]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def scan_totals():
    with db() as cur:
        cur.execute("SELECT COUNT(*), AVG(score) FROM scans")
        n, avg = cur.fetchone()
    return int(n or 0), (float(avg) if avg is not None else None)


def scan_counts():
    with db() as cur:
        cur.execute("SELECT classification, COUNT(*) FROM scans GROUP BY classification")
        return {k: int(v) for k, v in cur.fetchall()}


def valid_domain(d):
    return bool(DOMAIN_RE.match(d or ""))


def parse_domains(text):
    """One domain per line (extra columns / # comments ignored)."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(re.split(r"[,\s;]", line)[0])
    return out


def bulk_add_list(kind, domains, cap=5000):
    """Import many domains at once (threat feed). Returns how many valid domains were submitted."""
    cleaned = []
    for d in domains:
        d = clean_domain(d)
        if valid_domain(d):
            cleaned.append(d)
        if len(cleaned) >= cap:
            break
    cleaned = list(dict.fromkeys(cleaned))
    if cleaned:
        with db() as cur:
            cur.executemany(
                _sql("INSERT INTO lists(kind,domain) VALUES(?,?) ON CONFLICT (kind, domain) DO NOTHING"),
                [(kind, d) for d in cleaned])
    return len(cleaned)


def save_quiz(score, total, detail):
    with db() as cur:
        cur.execute(_sql("INSERT INTO quiz_results(taken_at,score,total,detail) VALUES(?,?,?,?)"),
                    (now_str(), int(score), int(total), json.dumps(detail)))


def load_quiz() -> pd.DataFrame:
    with db() as cur:
        cur.execute("SELECT id,taken_at,score,total,detail FROM quiz_results ORDER BY id")
        rows = cur.fetchall()
    return pd.DataFrame(rows, columns=["id", "taken_at", "score", "total", "detail"])


def clear_quiz():
    with db() as cur:
        cur.execute("DELETE FROM quiz_results")


def csv_safe(df):
    """Neutralise spreadsheet-formula injection: a cell starting with = + - @ is prefixed with '."""
    out = df.copy()
    for c in out.columns:
        if not pd.api.types.is_numeric_dtype(out[c]):
            out[c] = out[c].map(
                lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
    return out


def breakdown(df, col="classification"):
    """Counts for ALL four risk levels, so totals always add up."""
    if df is None or len(df) == 0:
        return {k: 0 for k in RISK_ORDER}
    vc = df[col].value_counts()
    return {k: int(vc.get(k, 0)) for k in RISK_ORDER}


def reasons_of(findings_json):
    try:
        fnd = json.loads(findings_json or "[]")
    except ValueError:
        return []
    return [f"{f.get('check', '?')}: {f.get('detail', '')} (-{f.get('penalty', 0)})"
            for f in fnd if f.get("status") != "pass"]


def triggered_checks(df):
    cnt = Counter()
    for js in df["findings"].dropna():
        try:
            for f in json.loads(js):
                if f.get("status") != "pass":
                    cnt[f["check"]] += 1
        except (ValueError, KeyError, TypeError):
            pass
    return cnt


def report_frame(df):
    out = df.copy()
    out["reasons"] = out["findings"].map(lambda js: " | ".join(reasons_of(js)) or "No issues found")
    out = out.drop(columns=["findings"])
    return out.rename(columns={"id": "ID", "url": "URL", "score": "Score", "classification": "Classification",
                               "source": "Source", "timestamp": "Timestamp", "reasons": "Detection reasons"})


def posture_text(df):
    n, b = len(df), breakdown(df)
    risky = b["HIGH RISK"] + b["CRITICAL"]

    def pct(v):
        return f"{(100 * v / n):.0f}%" if n else "0%"
    text = (f"Between {df.timestamp.min()} and {df.timestamp.max()}, {n} URL scan(s) were recorded: "
            f"{b['LOW RISK']} low risk ({pct(b['LOW RISK'])}), {b['MEDIUM RISK']} medium ({pct(b['MEDIUM RISK'])}), "
            f"{b['HIGH RISK']} high ({pct(b['HIGH RISK'])}) and {b['CRITICAL']} critical ({pct(b['CRITICAL'])}). ")
    text += (f"{risky} link(s) should not be opened." if risky else "No high-risk links were recorded.")
    return text + " Scores come from rule-based analysis of the URL text; the sites were never visited."


BENCHMARK = [
    ("https://www.google.com/search?q=weather", 0),
    ("https://mail.google.com/mail/u/0/#inbox", 0),
    ("https://github.com/anthropics/claude-code", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://www.amazon.in/gp/your-account/order-history", 0),
    ("https://www.paypal.com/signin", 0),
    ("https://login.microsoftonline.com/common/oauth2/authorize", 0),
    ("https://accounts.google.com/signin/v2/identifier", 0),
    ("https://www.netflix.com/login", 0),
    ("https://www.linkedin.com/feed/", 0),
    ("https://docs.python.org/3/library/urllib.html", 0),
    ("https://www.india.gov.in/", 0),
    ("https://www.irctc.co.in/nget/train-search", 0),
    ("https://www.hdfcbank.com/personal/pay/cards", 0),
    ("https://www.onlinesbi.sbi/", 0),
    ("https://www.bbc.com/news/technology", 0),
    ("https://www.mozilla.org/en-US/firefox/new/", 0),
    ("https://streamlit.io/gallery", 0),
    ("https://www.reddit.com/r/programming/", 0),
    ("https://www.coursera.org/learn/python", 0),
    ("https://medium.com/@someone/how-to-learn-security-3f2a", 0),
    ("https://www.zomato.com/bangalore/restaurants", 0),
    ("https://small-bakery.in/", 0),
    ("http://example.org/", 0),
    ("https://shop.localstore.in/account/login", 0),
    ("https://myportfolio.github.io/", 0),
    ("http://192.168.0.1/", 0),  # hard: a home-router page is legitimate but looks like an IP login
    ("http://www.paypal.com@secure-update-account.xyz/verify", 1),
    ("https://paypal-secure-login.example.com", 1),
    ("http://paypa1-secure.top/login", 1),
    ("http://bit.ly/free-iphone-giveaway", 1),
    ("http://185.203.116.77/login.php", 1),
    ("http://45.33.12.9/bank/verify.html", 1),
    ("https://secure-sbi-kyc-update.top/netbanking", 1),
    ("https://hdfc-bank-reward-claim.xyz/redeem", 1),
    ("http://amazon-account-suspended.click/verify?id=88123", 1),
    ("https://microsoft-office365-password-reset.support/login", 1),
    ("https://netflix-billing-update.work/payment", 1),
    ("https://faceb00k-login.cf/", 1),
    ("https://g00gle-drive-share.icu/view", 1),
    ("https://xn--pple-43d.com/signin", 1),
    ("http://www.icicibank.com.secure-login.xyz/netbanking", 1),
    ("https://login.microsoftonline.com.auth-check.top/common/oauth2", 1),
    ("https://example.com/redirect?url=http://evil.xyz/login", 1),
    ("http://dhl-parcel-tracking.work/track?id=44281", 1),
    ("https://amaz0n-prize-winner.buzz/claim", 1),
    ("http://free-fire-diamonds-generator.top/claim?user=1", 1),
    ("https://whatsapp-gold-update.download/app.apk", 1),
    ("http://kyc-update-pan-card.icu/submit", 1),
    ("https://www.sbi.co.in.verify-account.top/home", 1),
    ("http://tinyurl.com/y3k9login", 1),
    ("https://a.b.c.d.e.secure-bank-login.com/auth", 1),
    ("http://login-appleid-apple.com-secure.tk/", 1),
    ("https://delivery-notice-center.com/in/92831", 1),  # hard: nothing suspicious in the text
    ("https://customer-help-desk.online/tickets/12", 1),  # hard
    ("https://globalbank.cc/portal", 1),  # hard
    ("https://my-parcel-redelivery.shop/pay", 1),  # hard
]


POS_LABELS = {"1", "phishing", "phish", "malicious", "bad", "true", "fraud", "spam"}


NEG_LABELS = {"0", "legitimate", "legit", "benign", "safe", "good", "false", "ham", "clean"}


def parse_labelled(file):
    """Read a CSV with 'url' and 'label' columns. Returns (rows, skipped)."""
    df = pd.read_csv(io.BytesIO(file.getvalue()))
    cols = {str(c).strip().lower(): c for c in df.columns}
    ucol = cols.get("url") or cols.get("link")
    lcol = cols.get("label") or cols.get("class") or cols.get("type")
    if ucol is None or lcol is None:
        raise ValueError("the CSV needs 'url' and 'label' columns")
    rows, skipped = [], 0
    for u, lab in zip(df[ucol], df[lcol]):
        key = str(lab).strip().lower()
        if key in POS_LABELS:
            rows.append((str(u).strip(), 1))
        elif key in NEG_LABELS:
            rows.append((str(u).strip(), 0))
        else:
            skipped += 1
    return rows[:2000], skipped


def safe_div(a, b):
    return a / b if b else 0.0


def evaluate(rows, cutoff_label="MEDIUM RISK"):
    """Run the engine on labelled rows. 'Phishing' prediction = verdict at or above cutoff."""
    cutoff = RISK_ORDER.index(cutoff_label)
    tp = fp = fn = tn = 0
    wrong = []
    for url, truth in rows:
        res = analyze_url(url)
        pred = int(RISK_ORDER.index(res["label"]) >= cutoff)
        if truth and pred:
            tp += 1
        elif truth:
            fn += 1
            wrong.append({"URL": defang(url), "Truth": "phishing", "Verdict": res["label"],
                          "Score": res["score"], "Error": "Missed phishing (false negative)"})
        elif pred:
            fp += 1
            wrong.append({"URL": defang(url), "Truth": "legitimate", "Verdict": res["label"],
                          "Score": res["score"], "Error": "Legitimate flagged (false positive)"})
        else:
            tn += 1
    precision, recall = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": len(rows),
            "accuracy": safe_div(tp + tn, len(rows)), "precision": precision, "recall": recall,
            "f1": safe_div(2 * precision * recall, precision + recall), "fpr": safe_div(fp, fp + tn),
            "wrong": wrong}


def page_evaluation():
    hero("Detection Evaluation",
         "Measure how the rule engine really performs with labelled URLs, instead of claiming an accuracy.",
         "VALIDATION")
    st.warning("The built-in set is a small, hand-written **sanity benchmark** (synthetic URLs). It shows the "
               "engine behaves sensibly, but it is **not** real-world accuracy. For a meaningful figure, "
               "upload a labelled CSV (e.g. a public phishing feed plus a list of legitimate sites).")
    src = st.radio("Dataset", ["Built-in sanity benchmark", "Upload labelled CSV"], horizontal=True)
    rows, skipped = BENCHMARK, 0
    if src.startswith("Upload"):
        up = st.file_uploader("CSV with columns: url, label (phishing / legitimate, or 1 / 0)", type=["csv"])
        if up is None:
            st.info("Upload a file to evaluate it.")
            return
        try:
            rows, skipped = parse_labelled(up)
        except Exception as exc:
            st.error(f"Could not read the file: {exc}")
            return
        if not rows:
            st.error("No usable rows found. Labels must be phishing/legitimate or 1/0.")
            return
        if skipped:
            st.caption(f"{skipped} row(s) skipped because the label was not recognised.")
    n_pos = sum(1 for _, t in rows if t)
    st.caption(f"{len(rows)} URLs: {n_pos} phishing, {len(rows) - n_pos} legitimate. "
               "Evaluation uses Balanced sensitivity and ignores your custom lists so it is reproducible.")
    cutoff = st.selectbox("Count a URL as 'phishing' when the verdict is at least:", ["MEDIUM RISK", "HIGH RISK"])
    m = evaluate(rows, cutoff)

    k = st.columns(5)
    kpi(k[0], f"{m['accuracy'] * 100:.1f}%", "Accuracy", "🎯")
    kpi(k[1], f"{m['precision'] * 100:.1f}%", "Precision", "🔬", "#22c55e")
    kpi(k[2], f"{m['recall'] * 100:.1f}%", "Recall", "🧲", "#f59e0b")
    kpi(k[3], f"{m['f1'] * 100:.1f}%", "F1-score", "⚖️", "#818cf8")
    kpi(k[4], f"{m['fpr'] * 100:.1f}%", "False-positive rate", "🚫", "#ef4444")
    st.write("")
    a, b = st.columns([1, 1.2], gap="large")
    with a:
        st.markdown("#### 🧮 Confusion matrix")
        fig = go.Figure(go.Heatmap(
            z=[[m["tn"], m["fp"]], [m["fn"], m["tp"]]],
            x=["Predicted legitimate", "Predicted phishing"], y=["Actually legitimate", "Actually phishing"],
            text=[[m["tn"], m["fp"]], [m["fn"], m["tp"]]], texttemplate="%{text}",
            colorscale="Blues", showscale=False))
        fig.update_layout(yaxis={"autorange": "reversed"})
        st.plotly_chart(style_fig(fig, 300), use_container_width=True, key="eval_cm")
    with b:
        st.markdown("#### 🎚️ Effect of the threshold")
        sweep = []
        for c in ("MEDIUM RISK", "HIGH RISK"):
            r = evaluate(rows, c)
            sweep.append({"Flag as phishing at": f"{c} or worse", "Accuracy": f"{r['accuracy'] * 100:.1f}%",
                          "Precision": f"{r['precision'] * 100:.1f}%", "Recall": f"{r['recall'] * 100:.1f}%",
                          "F1": f"{r['f1'] * 100:.1f}%", "Missed": r["fn"], "False alarms": r["fp"]})
        st.dataframe(pd.DataFrame(sweep), hide_index=True, use_container_width=True)
        st.caption("A stricter threshold gives fewer false alarms but misses more phishing. "
                   "Pick the trade-off that suits your use case.")
    st.markdown("#### ❌ Misclassified URLs")
    if m["wrong"]:
        st.dataframe(pd.DataFrame(m["wrong"]), hide_index=True, use_container_width=True)
    else:
        st.success("No misclassifications on this dataset.")
    with st.expander("What do these metrics mean?"):
        st.markdown(
            "- **Accuracy**: share of all URLs classified correctly (misleading if classes are unbalanced).\n"
            "- **Precision**: of the links flagged as phishing, how many really were.\n"
            "- **Recall**: of all real phishing links, how many were caught.\n"
            "- **F1-score**: balance of precision and recall.\n"
            "- **False-positive rate**: legitimate links wrongly flagged.\n\n"
            "Rule-based detection is **not** machine learning, so it is reported here by its measured "
            "performance and never as 'AI accuracy'.")


MAX_REPORT_ROWS = 300


REPORT_CSS = (
    "body{font-family:Arial,Helvetica,sans-serif;margin:32px;color:#0f172a;line-height:1.5}"
    "h1{color:#2563eb;margin-bottom:0}h2{border-bottom:2px solid #e2e8f0;padding-bottom:4px;margin-top:30px}"
    ".k{display:inline-block;margin:6px 10px 6px 0;padding:12px 20px;border:1px solid #cbd5e1;"
    "border-radius:10px;min-width:110px}.k b{display:block;font-size:24px}"
    ".bar{height:14px;border-radius:7px;display:inline-block;vertical-align:middle}"
    "table{border-collapse:collapse;width:100%;margin-top:10px;font-size:13px}"
    "th,td{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;vertical-align:top}"
    "th{background:#f1f5f9}.small{color:#64748b;font-size:12px}ul{margin:4px 0 0 18px;padding:0}"
)


SCORING_TEXT = ("Every URL starts at 100 points. Each triggered rule subtracts points. "
                "80-100 = LOW RISK, 55-79 = MEDIUM RISK, 30-54 = HIGH RISK, 0-29 = CRITICAL. "
                "The sensitivity setting multiplies every penalty (Lenient x0.75, Balanced x1.0, Strict x1.3).")


LIMITS_TEXT = ("The scanner analyses the text of the URL only. It does not visit the site, read page content, "
               "check domain age or query live reputation services, so it can produce false positives and "
               "false negatives. Treat the result as a first-line screening aid, not proof of safety.")


def export_json(df):
    recs = df.to_dict("records")
    for r in recs:
        try:
            r["findings"] = json.loads(r["findings"] or "[]")
        except ValueError:
            r["findings"] = []
    return json.dumps({"generated": now_str(), "version": APP_VERSION, "records": recs},
                      indent=2, default=str)


REAL_EXAMPLES = [
    ("📦", "Courier 'redelivery fee' SMS", "SMS",
     "Your parcel could not be delivered. Pay Rs 25 redelivery fee within 12 hours or it will be returned.",
     "http://parcel-redelivery-fee.top/pay?id=7731",
     ["Artificial urgency (12 hours)", "Tiny fee used to capture card details", "No courier domain, .top extension"]),
    ("🏦", "Bank KYC expiry SMS", "SMS / WhatsApp",
     "Dear customer, your SBI YONO account will be blocked today. Update your KYC immediately.",
     "http://sbi-kyc-update-now.xyz/login",
     ["Threat of blocking", "Bank name inside a foreign domain", "Not HTTPS, .xyz extension"]),
    ("💸", "Fake refund / UPI 'claim'", "SMS",
     "Refund of Rs 4,999 approved! Claim here before it expires.",
     "http://refund-claim-gpay.click/verify?ref=2231",
     ["Unexpected money", "Brand look-alike words", "Asks you to 'verify'"]),
    ("🔐", "Account security email", "Email",
     "Microsoft 365: unusual sign-in detected. Verify your account to keep access.",
     "https://login.microsoftonline.com.verify-session.top/auth",
     ["Real brand name appears first, real domain is verify-session.top", "HTTPS does not prove trust"]),
    ("💼", "Work-from-home job offer", "WhatsApp",
     "Earn Rs 5,000 per day from home! Join our group now.",
     "http://bit.ly/work-from-home-jobs",
     ["Too good to be true", "Shortened link hides the destination"]),
    ("🎭", "The '@' trick", "Email",
     "Your Amazon order needs attention. Cancel it here.",
     "http://www.amazon.in@order-update.work/cancel",
     ["Everything before '@' is ignored by browsers", "Real host is order-update.work"]),
]


def render_sidebar_stats():
    try:
        total, avg, counts = sidebar_summary()
    except Exception:
        st.caption("Statistics unavailable")
        return
    c1, c2 = st.columns(2)
    c1.metric("Scans", total)
    c2.metric("Avg score", f"{avg:.0f}" if avg is not None else "-")
    st.caption("  ".join(f"{RISK_ICONS[k]} {counts.get(k, 0)}" for k in RISK_ORDER))
    st.caption(f"Sensitivity: **{st.session_state.get('sensitivity', 'Balanced')}**")
    if pg_active():
        st.caption("🟢 Permanent storage (PostgreSQL)")
    elif USE_PG:
        st.warning("Database unreachable: using temporary storage. See Settings > Storage.")
    else:
        st.warning("Temporary storage: history and scan counts reset when the app restarts. "
                   "See Settings > Storage to make them permanent.")


def set_example(url):
    """Put a link into the text box. A fresh widget key makes the box show it."""
    st.session_state["prefill"] = url
    st.session_state["url_nonce"] = st.session_state.get("url_nonce", 0) + 1


def open_in_scanner(url):
    set_example(url)
    st.session_state["autoscan"] = True
    st.session_state["nav"] = "🔍 Scanner"


SELF_TEST = [
    ("https://www.google.com", {"LOW RISK"}),
    ("https://github.com/anthropics/claude-code", {"LOW RISK"}),
    ("http://bit.ly/free-iphone-giveaway", {"HIGH RISK", "CRITICAL"}),
    ("http://www.paypal.com@secure-update-account.xyz/verify", {"CRITICAL"}),
    ("https://paypal-secure-login.example.com", {"HIGH RISK", "CRITICAL"}),
    ("http://192.168.1.1/login.php", {"HIGH RISK", "CRITICAL"}),
    ("https://xn--pple-43d.com/signin", {"HIGH RISK", "CRITICAL"}),
    ("https://sites.google.com/view/account-verify-now", {"MEDIUM RISK", "HIGH RISK", "CRITICAL"}),
]


def run_self_test():
    rows = []
    for url, expected in SELF_TEST:
        res = analyze_url(url)
        rows.append({"URL": defang(url), "Expected": " / ".join(sorted(expected, key=RISK_ORDER.index)),
                     "Got": res["label"], "Score": res["score"],
                     "Result": "PASS" if res["label"] in expected else "FAIL"})
    return rows


def pg_active():
    return USE_PG and not st.session_state.get("_pg_down")


def backend_label():
    if pg_active():
        return "PostgreSQL (persistent)"
    return "SQLite (temporary - database unreachable)" if USE_PG else "SQLite (temporary file)"


def explain_db_error(exc):
    """Human hint for a failed connection WITHOUT leaking host names or passwords."""
    msg = str(exc).lower()
    if isinstance(exc, ImportError):
        return "psycopg2-binary is missing from requirements.txt."
    if "password authentication" in msg or "authentication failed" in msg:
        return "Wrong user name or password (special characters in the password must be URL-encoded)."
    if "network is unreachable" in msg or "cannot assign requested address" in msg:
        return ("The app cannot reach that host (usually IPv6). In Supabase use the 'Session pooler' "
                "connection string, not the 'Direct connection'.")
    if "could not translate host name" in msg or "name or service not known" in msg:
        return "Host name not found. Copy the connection string again."
    if "timeout" in msg or "timed out" in msg:
        return "Connection timed out. Check host and port, and that the project is not paused."
    if "does not exist" in msg:
        return "The database or user does not exist."
    if "ssl" in msg:
        return "SSL problem. Add ?sslmode=require to the URL."
    return f"Connection failed ({type(exc).__name__})."


def sidebar_summary():
    """Total, average score and per-level counts using ONE connection."""
    with db() as cur:
        cur.execute("SELECT classification, COUNT(*), AVG(score) FROM scans GROUP BY classification")
        rows = cur.fetchall()
    counts = {k: int(n) for k, n, _ in rows}
    total = sum(counts.values())
    avg = (sum(float(a) * int(n) for _, n, a in rows) / total) if total else None
    return total, avg, counts


REPUTATION_FILE = os.path.join(os.path.dirname(os.path.abspath(globals().get("__file__", "app.py"))),
                               "reputation.csv")


def parse_reputation_csv(df):
    """Rows of (domain, level, category, note) from a DataFrame with domain + level [+ category, note]."""
    cols = {str(c).strip().lower(): c for c in df.columns}
    dcol = cols.get("domain") or cols.get("url")
    lcol = cols.get("level") or cols.get("risk") or cols.get("rating")
    if dcol is None or lcol is None:
        raise ValueError("the CSV needs 'domain' and 'level' columns")
    ccol, ncol = cols.get("category"), cols.get("note") or cols.get("notes")
    rows, skipped = [], 0
    for _, r in df.iterrows():
        dom, lvl = clean_domain(str(r[dcol])), normalize_level(r[lcol])
        if not valid_domain(dom) or lvl is None:
            skipped += 1
            continue
        cat = str(r[ccol]).strip() if ccol is not None and pd.notna(r[ccol]) else "Custom rating"
        note = str(r[ncol]).strip() if ncol is not None and pd.notna(r[ncol]) else ""
        rows.append((dom, lvl, cat[:80], note[:200]))
    return rows[:5000], skipped


def base_reputation():
    """Built-in ratings, optionally extended by a reputation.csv placed next to app.py."""
    table = {d: (lvl, cat, note) for d, lvl, cat, note in DEFAULT_REPUTATION}
    if os.path.exists(REPUTATION_FILE):
        try:
            rows, _ = parse_reputation_csv(pd.read_csv(REPUTATION_FILE))
            table.update({d: (lvl, cat, note) for d, lvl, cat, note in rows})
        except Exception:
            pass  # a broken optional file must never break scanning
    return table


def save_reputation(rows):
    """Insert or update ratings. rows = [(domain, level, category, note)]."""
    if not rows:
        return 0
    with db() as cur:
        cur.executemany(
            _sql("INSERT INTO reputation(domain,risk_level,category,note) VALUES(?,?,?,?) "
                 "ON CONFLICT (domain) DO UPDATE SET risk_level=EXCLUDED.risk_level, "
                 "category=EXCLUDED.category, note=EXCLUDED.note"), rows)
    return len(rows)


def get_my_reputation():
    with db() as cur:
        cur.execute("SELECT id, domain, risk_level, category, note FROM reputation ORDER BY domain")
        return list(cur.fetchall())


def remove_reputation(row_id):
    with db() as cur:
        cur.execute(_sql("DELETE FROM reputation WHERE id=?"), (int(row_id),))


def load_rules():
    """Allowlist, blocklist and reputation table in ONE database connection."""
    with db() as cur:
        cur.execute("SELECT kind, domain FROM lists")
        lists = cur.fetchall()
        cur.execute("SELECT domain, risk_level, category, note FROM reputation")
        mine = cur.fetchall()
    table = base_reputation()
    for d, lvl, cat, note in mine:
        if lvl in LEVEL_CAP:
            table[d] = (lvl, cat or "Custom rating", note or "")
    return [d for k, d in lists if k == "allow"], [d for k, d in lists if k == "block"], table


def analyze_with_rules(raw, rules):
    allow, block, table = rules
    res = analyze_url(raw, sensitivity=st.session_state.get("sensitivity", "Balanced"),
                      allow=allow, block=block, reputation=table)
    res["scanned_at"] = now_str()
    return res


def save_scans(results, source="scanner"):
    """Save many results through one connection."""
    if not results:
        return
    stamp = now_str()
    with db() as cur:
        cur.executemany(
            _sql("INSERT INTO scans(url,score,classification,findings,source,timestamp) VALUES(?,?,?,?,?,?)"),
            [(r["url"], r["score"], r["label"], json.dumps(r["findings"]), source, stamp) for r in results])


def settings_reputation():
    st.markdown("### 🏷️ Source reputation")
    st.caption("Link checks look at the *shape* of a link. Reputation looks at *who runs the site*. A clean "
               "address can still belong to a piracy site, a dark-web directory or content you should verify, "
               "so those are rated here and cap the score. Ratings are by category, not by politics. "
               "Change them to match your own policy.")
    base, mine = base_reputation(), get_my_reputation()
    merged = {d: (*v, "built-in") for d, v in base.items()}
    for _, d, lvl, cat, note in mine:
        merged[d] = (lvl, cat or "Custom rating", note or "", "yours")
    df = pd.DataFrame([(d, *v) for d, v in merged.items()], columns=["Domain", "Rating", "Category", "Note", "Source"])
    df["_o"] = df.Rating.map(RISK_ORDER.index)
    df = df.sort_values(["_o", "Domain"]).drop(columns="_o")
    st.dataframe(df, hide_index=True, use_container_width=True, height=260)
    st.caption(f"{len(df)} rated domains ({len(mine)} added or changed by you). "
               "Unrated domains are judged by link structure only.")
    with st.form("form_rep", clear_on_submit=True):
        c1, c2 = st.columns(2)
        dom = c1.text_input("Domain", placeholder="example.com")
        lvl = c2.selectbox("Rating", RISK_ORDER)
        cat = c1.text_input("Category", placeholder="e.g. Opinion publication")
        note = c2.text_input("Note (optional)")
        if st.form_submit_button("Save rating"):
            d = clean_domain(dom)
            if valid_domain(d):
                save_reputation([(d, lvl, cat.strip()[:80] or "Custom rating", note.strip()[:200])])
                st.toast(f"Saved {d} as {lvl}", icon="🏷️")
            else:
                st.warning("Enter a valid domain such as example.com")
    up = st.file_uploader("Import ratings (.csv with columns: domain, level, category, note)", type=["csv"],
                          key="imp_rep")
    if st.button("Import ratings", key="impbtn_rep", disabled=up is None):
        try:
            rows, skipped = parse_reputation_csv(pd.read_csv(io.BytesIO(up.getvalue())))
            st.toast(f"Imported {save_reputation(rows)} rating(s), skipped {skipped}", icon="🏷️")
        except Exception as exc:
            st.error(f"Could not read the file: {exc}")
    for rid, d, lvl, cat, note in mine[:50]:
        r1, r2, r3 = st.columns([3, 2, 1])
        r1.markdown(f'<span class="mono">{html.escape(d)}</span>', unsafe_allow_html=True)
        r2.markdown(badge(lvl), unsafe_allow_html=True)
        r3.button("✖", key=f"rmrep_{rid}", on_click=remove_reputation, args=(rid,))
    st.download_button("Export all ratings (CSV)", csv_safe(df).to_csv(index=False).encode(),
                       "reputation.csv", "text/csv", key="exp_rep")


# =============================================================================
# 7. ROUTER
# =============================================================================
PAGES = {
    "🔍 Scanner": page_scanner,
    "📦 Batch Scanner": page_batch,
    "📊 Global Analytics": page_analytics,
    "🧪 Detection Evaluation": page_evaluation,
    "🕒 Scan History": page_history,
    "📄 Security Reports": page_reports,
    "ℹ️ Education": page_education,
    "⚙️ Settings": page_settings,
}

# Settings live in plain session keys (never tied to a widget), so they survive page changes.
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
    stats_box = st.empty()  # filled AFTER the page runs so it always reflects the latest scans
    st.caption("Rule-based screening. Not a substitute for judgement.")

try:
    PAGES[choice]()
except Exception as exc:  # keep the app usable and never leak connection details
    st.error(f"Something went wrong ({type(exc).__name__}). Try again or check Settings > Storage.")

with stats_box.container():
    render_sidebar_stats()
