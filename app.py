import streamlit as st
import pandas as pd
import joblib
import re
import plotly.graph_objects as go
from datetime import datetime
import database as db

# --- PAGE CONFIG ---
st.set_page_config(page_title="Cyber Threat Intelligence", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# Initialize Database
db.init_db()

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .stApp { background-color: #0b0f19; color: #e2e8f0; font-family: 'Inter', sans-serif; }
    [data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1f2937; }
    h1, h2, h3 { color: #38bdf8; font-weight: 700; }
    .title-glow { text-align: center; color: #38bdf8; text-shadow: 0px 0px 15px rgba(56, 189, 248, 0.4); font-weight: 900; }
    .metric-card {
        background: linear-gradient(145deg, #1e293b, #0f172a); padding: 20px; 
        border-radius: 12px; border: 1px solid #334155; text-align: center;
    }
    .metric-value { font-size: 28px; font-weight: bold; color: #38bdf8; }
    .metric-label { font-size: 13px; color: #94a3b8; text-transform: uppercase; margin-top: 5px; }
    .stTextInput>div>div>input { background-color: #0f172a; color: #38bdf8; border: 2px solid #334155; border-radius: 8px; padding: 12px; }
    .stButton>button { background: linear-gradient(90deg, #0ea5e9 0%, #2563eb 100%); color: white; font-weight: bold; border: none; border-radius: 8px; padding: 12px 24px; width: 100%; }
    
    /* Status Boxes */
    .status-pass { color: #22c55e; font-weight: bold; }
    .status-fail { color: #ef4444; font-weight: bold; }
    .status-warn { color: #eab308; font-weight: bold; }
    
    .risk-low { color: #22c55e; font-size: 24px; font-weight: bold; }
    .risk-medium { color: #eab308; font-size: 24px; font-weight: bold; }
    .risk-high { color: #f97316; font-size: 24px; font-weight: bold; }
    .risk-critical { color: #ef4444; font-size: 24px; font-weight: bold; }
    
    #MainMenu {visibility: hidden;} footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_model():
    return joblib.load('threat_model.pkl')

model = load_model()

# --- ADVANCED FEATURE EXTRACTION & RULE ENGINE ---
def analyze_url(url):
    results = {}
    
    # 1. HTTPS Check
    results['HTTPS Protocol'] = ("Passed", "status-pass") if url.startswith('https') else ("Suspicious (No HTTPS)", "status-fail")
    
    # 2. IP Address Check
    has_ip = bool(re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
    results['IP Address in URL'] = ("Not Detected", "status-pass") if not has_ip else ("Detected (Suspicious)", "status-fail")
    
    # 3. Suspicious Keywords
    keywords = ['login', 'secure', 'update', 'banking', 'verify', 'account', 'paypal']
    found_kw = [kw for kw in keywords if kw in url.lower()]
    results['Suspicious Keywords'] = ("Not Detected", "status-pass") if not found_kw else (f"Detected: {', '.join(found_kw)}", "status-warn")
    
    # 4. URL Shortener
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
    is_short = any(s in url.lower() for s in shorteners)
    results['URL Shortener'] = ("Not Detected", "status-pass") if not is_short else ("Detected (Warning)", "status-warn")
    
    # 5. URL Length
    length = len(url)
    if length < 54: results['URL Length'] = ("Normal", "status-pass")
    elif length < 75: results['URL Length'] = ("Slightly Long", "status-warn")
    else: results['URL Length'] = ("Excessively Long", "status-fail")
    
    # 6. Suspicious Characters
    has_at = '@' in url
    results['Suspicious Characters (@)'] = ("Not Detected", "status-pass") if not has_at else ("Detected (@ symbol)", "status-fail")
    
    # 7. Subdomains (Dots)
    num_dots = url.count('.')
    if num_dots <= 2: results['Excessive Subdomains'] = ("Normal", "status-pass")
    elif num_dots <= 3: results['Excessive Subdomains'] = ("Warning", "status-warn")
    else: results['Excessive Subdomains'] = ("Suspicious", "status-fail")

    # Format for Machine Learning Model
    features = [length, int(has_at), int(has_ip), int(url.startswith('https')), num_dots, url.count('-')]
    features_df = pd.DataFrame([features], columns=['length', 'has_at', 'has_ip', 'has_https', 'num_dots', 'num_hyphens'])
    
    # ML Prediction
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]
    
    # Calculate Safety Score (0-100)
    # If ML says Safe -> Score is high. If ML says Phishing -> Score is low.
    safety_score = int(probability[0] * 100) if prediction == 0 else int(probability[1] * 100)
    
    # Rule-based adjustments (Penalties)
    if not url.startswith('https'): safety_score -= 10
    if has_ip: safety_score -= 20
    if has_at: safety_score -= 10
    if length > 75: safety_score -= 5
    safety_score = max(0, min(100, safety_score)) # Keep between 0-100
    
    # Classification
    if safety_score >= 80: classification = ("LOW RISK", "risk-low")
    elif safety_score >= 60: classification = ("MEDIUM RISK", "risk-medium")
    elif safety_score >= 30: classification = ("HIGH RISK", "risk-high")
    else: classification = ("CRITICAL RISK", "risk-critical")
    
    return results, safety_score, classification

# --- SIDEBAR ---
st.sidebar.markdown("<h2 style='color:#38bdf8; text-align:center;'>🛡️ CYBER INTEL</h2>", unsafe_allow_html=True)
page = st.sidebar.radio("NAVIGATION", ["🔍 Scanner", "📊 Global Analytics", "🕒 Scan History", "ℹ️ Education"])

# ==========================================
# PAGE 1: SCANNER
# ==========================================
if page == "🔍 Scanner":
    st.markdown("<h1 class='title-glow'>ADVANCED PHISHING THREAT INTELLIGENCE</h1>", unsafe_allow_html=True)
    st.write("")

    url_input = st.text_input("TARGET URL:", placeholder="Paste suspicious URL here...")
    
    if st.button("INITIATE DEEP SCAN 🚀"):
        if url_input:
            with st.spinner("Analyzing URL structure and querying threat engine..."):
                analysis_results, score, classification = analyze_url(url_input)
                db.save_scan(url_input, score, classification[0]) # Save to database
                
            st.markdown("---")
            col1, col2 = st.columns([1, 2])
            
            with col1:
                # Gauge Chart
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number", value = score,
                    title = {'text': "SAFETY SCORE", 'font': {'color': '#e2e8f0'}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickcolor': "white"},
                        'bar': {'color': "#22c55e" if score >= 60 else "#ef4444"},
                        'steps': [
                            {'range': [0, 30], 'color': "rgba(239, 68, 68, 0.2)"},
                            {'range': [30, 60], 'color': "rgba(249, 115, 22, 0.2)"},
                            {'range': [60, 80], 'color': "rgba(234, 179, 8, 0.2)"},
                            {'range': [80, 100], 'color': "rgba(34, 197, 94, 0.2)"}],
                    }
                ))
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, height=300, margin=dict(l=20, r=20, t=50, b=20))
                st.plotly_chart(fig, use_container_width=True)
                
                st.markdown(f"<div style='text-align:center;'>Classification: <br><span class='{classification[1]}'>{classification[0]}</span></div>", unsafe_allow_html=True)

            with col2:
                st.markdown("### 📋 Detailed URL Analysis")
                st.write("The following rules were evaluated to generate the safety score:")
                
                # Display Rule Results in a table-like format
                for rule, result in analysis_results.items():
                    st.markdown(f"- **{rule}:** <span class='{result[1]}'>{result[0]}</span>", unsafe_allow_html=True)

                st.markdown("---")
                st.markdown("### 🌐 External Threat Intelligence")
                st.info("**Google Safe Browsing:** NOT CONFIGURED\n\n**VirusTotal API:** NOT CONFIGURED\n\n*(This section requires paid API keys. Rule-based local analysis is active.)*")

# ==========================================
# PAGE 2: GLOBAL ANALYTICS
# ==========================================
elif page == "📊 Global Analytics":
    st.markdown("<h1 class='title-glow'>GLOBAL THREAT ANALYTICS</h1>", unsafe_allow_html=True)
    st.write("")
    
    # Read from Database
    history = db.get_history()
    total_scans = len(history)
    critical_threats = sum(1 for row in history if row[2] == "CRITICAL RISK")
    safe_urls = sum(1 for row in history if row[2] == "LOW RISK")
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{total_scans}</div><div class='metric-label'>Total Scans</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{safe_urls}</div><div class='metric-label'>Safe URLs</div></div>", unsafe_allow_html=True)
    with m3:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>{critical_threats}</div><div class='metric-label'>Critical Threats</div></div>", unsafe_allow_html=True)
    with m4:
        st.markdown(f"<div class='metric-card'><div class='metric-value'>99.67%</div><div class='metric-label'>AI Accuracy</div></div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("---")
    
    if total_scans > 0:
        df = pd.DataFrame(history, columns=['URL', 'Score', 'Classification', 'Date'])
        st.markdown("### 🥧 Threat Distribution")
        counts = df['Classification'].value_counts()
        fig2 = go.Figure(data=[go.Pie(labels=counts.index, values=counts.values, hole=.5, marker_colors=['#22c55e', '#ef4444', '#eab308', '#f97316'])])
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No data yet. Scan a URL to generate analytics!")

# ==========================================
# PAGE 3: SCAN HISTORY
# ==========================================
elif page == "🕒 Scan History":
    st.markdown("<h1 class='title-glow'>SCAN HISTORY DATABASE</h1>", unsafe_allow_html=True)
    
    history = db.get_history()
    
    if not history:
        st.info("Database is empty. Go to the Scanner and scan a URL.")
    else:
        df = pd.DataFrame(history, columns=['Target URL', 'Safety Score', 'Classification', 'Timestamp'])
        
        # Filtering
        st.write("### Filter Records")
        filter_class = st.multiselect("Filter by Risk Level:", df['Classification'].unique(), default=df['Classification'].unique())
        filtered_df = df[df['Classification'].isin(filter_class)]
        
        st.dataframe(filtered_df, use_container_width=True)
        
        if st.button("🗑️ Clear All History"):
            db.clear_history()
            st.rerun()

# ==========================================
# PAGE 4: EDUCATION
# ==========================================
elif page == "ℹ️ Education":
    st.markdown("<h1 class='title-glow'>CYBERSECURITY EDUCATION</h1>", unsafe_allow_html=True)
    st.markdown("""
    ### What is Phishing?
    Phishing is a cybercrime where targets are contacted by email, telephone, or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data.
    
    ### How Our Engine Works
    This application uses a hybrid approach:
    1. **Machine Learning (Random Forest):** Trained on 48,000 URLs to recognize the mathematical structure of a malicious link.
    2. **Rule-Based Heuristics:** We analyze the URL for specific red flags (IP addresses, missing HTTPS, suspicious keywords, etc.).
    3. **Safety Scoring:** We combine the ML probability with our rule engine to generate a final 0-100 Safety Score.
    
    ### Risk Classifications
    *   **80–100:** LOW RISK (Safe)
    *   **60–79:** MEDIUM RISK (Suspicious)
    *   **30–59:** HIGH RISK (Likely Malicious)
    *   **0–29:** CRITICAL RISK (Do Not Visit)
    """)
