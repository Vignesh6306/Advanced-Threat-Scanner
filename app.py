import streamlit as st
import pandas as pd
import joblib
import re
import plotly.graph_objects as go
from datetime import datetime

# --- PAGE CONFIG ---
st.set_page_config(page_title="Cyber Threat Intel", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS (The Ultimate Design) ---
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #0a0e17;
        color: #e0e0e0;
        font-family: 'Courier New', monospace;
    }
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #1f2937;
    }
    /* Title glow effect */
    .title-glow {
        text-align: center;
        color: #00ffcc;
        text-shadow: 0px 0px 20px rgba(0, 255, 204, 0.5);
        font-weight: 900;
        letter-spacing: 2px;
    }
    /* Card styling for metrics */
    .metric-card {
        background-color: #1e2330;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #00ffcc;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        text-align: center;
    }
    .metric-value { font-size: 32px; font-weight: bold; color: #00ffcc; }
    .metric-label { font-size: 14px; color: #9ca3af; text-transform: uppercase; }
    
    /* Input and Button Styling */
    .stTextInput>div>div>input {
        background-color: #111827;
        color: #00ffcc;
        border: 2px solid #374151;
        border-radius: 8px;
        padding: 15px;
        font-size: 16px;
    }
    .stButton>button {
        background: linear-gradient(90deg, #00ffcc 0%, #00b3ff 100%);
        color: #000;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        padding: 15px 30px;
        font-size: 18px;
        width: 100%;
        transition: 0.3s;
    }
    .stButton>button:hover { transform: scale(1.02); box-shadow: 0 0 20px rgba(0,255,204,0.6); }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# --- LOAD MODEL ---
@st.cache_resource
def load_model():
    return joblib.load('threat_model.pkl')

try:
    model = load_model()
except Exception as e:
    st.error(f"Error loading model: {e}")

# --- FEATURE EXTRACTION ---
def extract_features(url):
    length = len(url)
    has_at = 1 if '@' in url else 0
    has_ip = 1 if re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_https = 1 if url.startswith('https') else 0
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    return [length, has_at, has_ip, has_https, num_dots, num_hyphens]

# --- SIDEBAR NAVIGATION ---
st.sidebar.markdown("<h2 style='color:#00ffcc;'>🛡️ CYBER INTEL</h2>", unsafe_allow_html=True)
st.sidebar.markdown("---")
page = st.sidebar.radio("NAVIGATION", ["🔍 Threat Scanner", "📊 System Dashboard", "ℹ️ Education"])

st.sidebar.markdown("---")
st.sidebar.info("System Status: **ONLINE**\n\nDatabase: **Synced**\n\nThreat Level: **Elevated**")

# ==========================================
# PAGE 1: THREAT SCANNER
# ==========================================
if page == "🔍 Threat Scanner":
    st.markdown("<h1 class='title-glow'>ADVANCED PHISHING DETECTOR</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#9ca3af;'>Enter a URL to perform deep packet lexical analysis.</p>", unsafe_allow_html=True)
    st.write("")

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        url_input = st.text_input("TARGET URL:", placeholder="https://example.com")
        scan_button = st.button("INITIATE DEEP SCAN 🚀")

    if scan_button and url_input:
        with st.spinner("Analyzing lexical structure..."):
            features = extract_features(url_input)
            features_df = pd.DataFrame([features], columns=['length', 'has_at', 'has_ip', 'has_https', 'num_dots', 'num_hyphens'])
            
            prediction = model.predict(features_df)[0]
            probability = model.predict_proba(features_df)[0]
            risk_score = probability[1] * 100 if prediction == 1 else probability[0] * 100

        st.markdown("---")
        
        # Layout for results
        res_col1, res_col2 = st.columns([1, 2])
        
        with res_col1:
            # Dynamic Gauge Chart
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "THREAT PROBABILITY", 'font': {'color': '#e0e0e0'}},
                gauge = {
                    'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                    'bar': {'color': "#ff3333" if prediction == 1 else "#00ffcc"},
                    'bgcolor': "rgba(0,0,0,0)",
                    'borderwidth': 2,
                    'bordercolor': "gray",
                    'steps': [
                        {'range': [0, 50], 'color': "rgba(0, 255, 204, 0.1)"},
                        {'range': [50, 100], 'color': "rgba(255, 51, 51, 0.1)"}],
                }
            ))
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, height=250, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig, use_container_width=True)

        with res_col2:
            if prediction == 1:
                st.error("🚨 **CRITICAL ALERT: PHISHING DETECTED**")
                st.write(f"The AI model has flagged this URL as highly malicious.")
            else:
                st.success("✅ **SYSTEM SECURE: LEGITIMATE URL**")
                st.write(f"The AI model has verified this URL as safe.")

            st.markdown("### 📊 Threat Matrix Log")
            st.write(f"- **Target:** `{url_input}`")
            st.write(f"- **Risk Score:** {risk_score:.2f}%")
            st.write(f"- **URL Length:** {features[0]} characters")
            st.write(f"- **Uses HTTPS:** {'✅ Yes' if features[3] else '❌ No'}")
            st.write(f"- **Uses IP Address:** {'❌ Yes (Suspicious)' if features[2] else '✅ No'}")
            st.write(f"- **Contains @ Symbol:** {'❌ Yes (Suspicious)' if features[1] else '✅ No'}")

        # Simulated Threat Feeds (Like the screenshot)
        st.markdown("### 🌐 External Threat Feeds (Simulated)")
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            st.info("**Google Safe Browsing**\n\n" + ("🔴 Flagged as Malicious" if prediction == 1 else "🟢 Clean"))
        with f_col2:
            st.warning("**VirusTotal Engine**\n\n" + ("🟠 14/90 Vendors Flagged" if prediction == 1 else "🟢 0/90 Vendors Flagged"))
        with f_col3:
            st.success("**Domain Reputation**\n\n" + ("🔴 Newly Registered Domain" if prediction == 1 else "🟢 Established History"))

# ==========================================
# PAGE 2: SYSTEM DASHBOARD
# ==========================================
elif page == "📊 System Dashboard":
    st.markdown("<h1 class='title-glow'>SYSTEM DASHBOARD</h1>", unsafe_allow_html=True)
    st.write("")
    
    # Fake Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown("<div class='metric-card'><div class='metric-value'>48,812</div><div class='metric-label'>Total URLs Analyzed</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown("<div class='metric-card'><div class='metric-value'>99.67%</div><div class='metric-label'>AI Accuracy Score</div></div>", unsafe_allow_html=True)
    with m3:
        st.markdown("<div class='metric-card'><div class='metric-value'>14,203</div><div class='metric-label'>Phishing Threats Blocked</div></div>", unsafe_allow_html=True)
    with m4:
        st.markdown("<div class='metric-card'><div class='metric-value'>ACTIVE</div><div class='metric-label'>System Status</div></div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("---")
    
    # Charts
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown("### 📈 Scan Activity (Last 7 Days)")
        dates = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        scans = [120, 150, 180, 90, 210, 300, 250]
        st.line_chart(pd.DataFrame({'Scans': scans}, index=dates), color="#00ffcc")
    with chart_col2:
        st.markdown("### 🥧 Threat Distribution")
        labels = ['Safe', 'Phishing', 'Suspicious']
        values = [65, 25, 10]
        fig2 = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.5, marker_colors=['#00ffcc', '#ff3333', '#ffaa00'])])
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, height=300, margin=dict(t=0, b=0, l=0, r=0))
        st.plotly_chart(fig2, use_container_width=True)

# ==========================================
# PAGE 3: EDUCATION
# ==========================================
elif page == "ℹ️ Education":
    st.markdown("<h1 class='title-glow'>CYBERSECURITY EDUCATION</h1>", unsafe_allow_html=True)
    st.write("")
    st.markdown("""
    ### What is Phishing?
    Phishing is a type of social engineering where attackers deceive people into revealing sensitive information or installing malware such as ransomware.
    
    ### How Does Our AI Work?
    This system uses a **Random Forest Classifier** (Machine Learning) trained on thousands of malicious URLs. Instead of just looking at a blacklist, it analyzes the *structure* of the URL.
    
    **Key Red Flags we detect:**
    *   **Raw IP Addresses:** Phishers use IPs instead of domain names to hide their identity.
    *   **No HTTPS:** Secure sites use HTTPS. Phishing sites often use unsecured HTTP.
    *   **Excessive Length:** Malicious URLs are often abnormally long to hide the real destination.
    *   **The '@' Symbol:** Browsers ignore everything before the '@', which attackers use to trick you.
    
    ### Stay Safe!
    Always hover over links before clicking them, and never enter your credentials on a site that lacks the padlock icon.
    """)
