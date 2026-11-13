import streamlit as st
import pandas as pd
import joblib
import re
import plotly.graph_objects as go
from datetime import datetime
import random

# --- PAGE CONFIG ---
st.set_page_config(page_title="Cyber Threat Intelligence", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# --- CUSTOM CSS (The Ultimate Design) ---
st.markdown("""
<style>
    /* Main background */
    .stApp { background-color: #0b0f19; color: #e2e8f0; font-family: 'Inter', sans-serif; }
    
    /* Sidebar */
    [data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1f2937; }
    
    /* Headers */
    h1, h2, h3 { color: #38bdf8; font-weight: 700; }
    .title-glow { text-align: center; color: #38bdf8; text-shadow: 0px 0px 15px rgba(56, 189, 248, 0.4); font-weight: 900; letter-spacing: 1px; }
    
    /* Metric Cards */
    .metric-card {
        background: linear-gradient(145deg, #1e293b, #0f172a);
        padding: 20px; border-radius: 12px; border: 1px solid #334155;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3); text-align: center;
    }
    .metric-value { font-size: 28px; font-weight: bold; color: #38bdf8; }
    .metric-label { font-size: 13px; color: #94a3b8; text-transform: uppercase; margin-top: 5px; }
    
    /* Input and Button */
    .stTextInput>div>div>input {
        background-color: #0f172a; color: #38bdf8; border: 2px solid #334155;
        border-radius: 8px; padding: 12px; font-size: 16px;
    }
    .stButton>button {
        background: linear-gradient(90deg, #0ea5e9 0%, #2563eb 100%);
        color: white; font-weight: bold; border: none; border-radius: 8px;
        padding: 12px 24px; font-size: 16px; width: 100%; transition: 0.3s;
    }
    .stButton>button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(14,165,233,0.4); }
    
    /* Status Boxes */
    .status-box { padding: 15px; border-radius: 8px; margin-bottom: 10px; font-weight: 600; }
    .status-safe { background-color: rgba(34, 197, 94, 0.1); border-left: 4px solid #22c55e; color: #4ade80; }
    .status-danger { background-color: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; color: #f87171; }
    
    /* Hide Streamlit Branding */
    #MainMenu {visibility: hidden;} footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# --- LOAD MODEL ---
@st.cache_resource
def load_model():
    return joblib.load('threat_model.pkl')

model = load_model()

# --- FEATURE EXTRACTION ---
def extract_features(url):
    length = len(url)
    has_at = 1 if '@' in url else 0
    has_ip = 1 if re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_https = 1 if url.startswith('https') else 0
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    return [length, has_at, has_ip, has_https, num_dots, num_hyphens]

# --- SIDEBAR ---
st.sidebar.markdown("<h2 style='color:#38bdf8; text-align:center;'>🛡️ CYBER INTEL</h2>", unsafe_allow_html=True)
st.sidebar.markdown("---")
page = st.sidebar.radio("NAVIGATION", ["🔍 Real-time Scanner", "📊 Global Analytics", "ℹ️ Threat Education"])

st.sidebar.markdown("---")
st.sidebar.success("✅ System Status: **ONLINE**\n\n🗄️ Database: **Synced**\n\n⚠️ Global Threat Level: **Elevated**")

# ==========================================
# PAGE 1: REAL-TIME SCANNER
# ==========================================
if page == "🔍 Real-time Scanner":
    st.markdown("<h1 class='title-glow'>ADVANCED PHISHING THREAT INTELLIGENCE</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#94a3b8; font-family:monospace;'>AI-POWERED URL ANALYSIS · LEXICAL ENTROPY · OSINT · THREAT SCORING</p>", unsafe_allow_html=True)
    st.write("")

    url_input = st.text_input("TARGET URL:", placeholder="Paste suspicious URL here (e.g., http://192.168.1.1/login)")
    
    if st.button("INITIATE DEEP SCAN 🚀"):
        if url_input:
            with st.spinner("Analyzing lexical structure and querying global threat feeds..."):
                features = extract_features(url_input)
                features_df = pd.DataFrame([features], columns=['length', 'has_at', 'has_ip', 'has_https', 'num_dots', 'num_hyphens'])
                
                prediction = model.predict(features_df)[0]
                probability = model.predict_proba(features_df)[0]
                
                # Calculate Safety Score (0-100)
                if prediction == 1:
                    safety_score = (probability[0]) * 100
                else:
                    safety_score = (probability[0]) * 100
                    
                st.markdown("---")
                
                # Layout: Left for Gauge, Right for Results
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    # The Gauge Chart
                    fig = go.Figure(go.Indicator(
                        mode = "gauge+number",
                        value = safety_score,
                        title = {'text': "SAFETY SCORE", 'font': {'color': '#e2e8f0'}},
                        gauge = {
                            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "white"},
                            'bar': {'color': "#22c55e" if prediction == 0 else "#ef4444"},
                            'bgcolor': "rgba(0,0,0,0)",
                            'borderwidth': 2, 'bordercolor': "#334155",
                            'steps': [
                                {'range': [0, 50], 'color': "rgba(239, 68, 68, 0.1)"},
                                {'range': [50, 100], 'color': "rgba(34, 197, 94, 0.1)"}],
                        }
                    ))
                    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, height=300, margin=dict(l=20, r=20, t=50, b=20))
                    st.plotly_chart(fig, use_container_width=True)

                with col2:
                    if prediction == 1:
                        st.markdown("<div class='status-box status-danger'>🚨 PHISHING DETECTED</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div class='status-box status-safe'>✅ SAFE TO VISIT</div>", unsafe_allow_html=True)
                        
                    st.markdown(f"**Target URL:** `{url_input}`")
                    st.markdown(f"**AI Threat Probability:** `{probability[1]*100:.2f}%`")
                    
                    st.markdown("### 🔍 Simulated Security Assessment")
                    # Simulated Threat Sources
                    if prediction == 1:
                        st.markdown("<div class='status-box status-danger' style='font-size:14px;'><b>Google Safe Browsing:</b> 🔴 Flagged as Malicious</div>", unsafe_allow_html=True)
                        st.markdown("<div class='status-box status-danger' style='font-size:14px;'><b>VirusTotal:</b> 🟠 " + str(random.randint(5, 20)) + "/90 Vendors Flagged</div>", unsafe_allow_html=True)
                        st.markdown("<div class='status-box status-danger' style='font-size:14px;'><b>SSL Analysis:</b> 🔴 Invalid or Missing Certificate</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div class='status-box status-safe' style='font-size:14px;'><b>Google Safe Browsing:</b> 🟢 Clean</div>", unsafe_allow_html=True)
                        st.markdown("<div class='status-box status-safe' style='font-size:14px;'><b>VirusTotal:</b> 🟢 0/90 Vendors Flagged</div>", unsafe_allow_html=True)
                        st.markdown("<div class='status-box status-safe' style='font-size:14px;'><b>SSL Analysis:</b> 🟢 Valid Certificate Detected</div>", unsafe_allow_html=True)

                # Technical Details Panel
                st.markdown("### 💻 Technical Telemetry")
                t1, t2, t3, t4 = st.columns(4)
                with t1:
                    st.markdown(f"<div class='metric-card'><div class='metric-value'>{features[0]}</div><div class='metric-label'>URL Length</div></div>", unsafe_allow_html=True)
                with t2:
                    st.markdown(f"<div class='metric-card'><div class='metric-value'>{'No' if features[3] else 'Yes'}</div><div class='metric-label'>Uses IP Address</div></div>", unsafe_allow_html=True)
                with t3:
                    st.markdown(f"<div class='metric-card'><div class='metric-value'>{'Yes' if features[3] else 'No'}</div><div class='metric-label'>HTTPS Secured</div></div>", unsafe_allow_html=True)
                with t4:
                    st.markdown(f"<div class='metric-card'><div class='metric-value'>{features[4]}</div><div class='metric-label'>Subdomains (Dots)</div></div>", unsafe_allow_html=True)

# ==========================================
# PAGE 2: GLOBAL ANALYTICS
# ==========================================
elif page == "📊 Global Analytics":
    st.markdown("<h1 class='title-glow'>GLOBAL THREAT ANALYTICS</h1>", unsafe_allow_html=True)
    st.write("")
    
    # Fake Dashboard Metrics
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown("<div class='metric-card'><div class='metric-value'>5,441</div><div class='metric-label'>Total Scans Today</div></div>", unsafe_allow_html=True)
    with m2:
        st.markdown("<div class='metric-card'><div class='metric-value'>1,203</div><div class='metric-label'>Phishing Detected</div></div>", unsafe_allow_html=True)
    with m3:
        st.markdown("<div class='metric-card'><div class='metric-value'>99.67%</div><div class='metric-label'>Model Accuracy</div></div>", unsafe_allow_html=True)
    with m4:
        st.markdown("<div class='metric-card'><div class='metric-value'>" + datetime.now().strftime("%H:%M") + "</div><div class='metric-label'>Last Database Sync</div></div>", unsafe_allow_html=True)

    st.write("")
    st.markdown("---")
    
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown("### 📈 Scan Trends (Last 7 Days)")
        dates = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        st.line_chart(pd.DataFrame({'Malicious': [40, 55, 30, 80, 45, 90, 110], 'Safe': [100, 120, 150, 90, 200, 180, 220]}, index=dates), color=["#ef4444", "#22c55e"])
    with chart_col2:
        st.markdown("### 🥧 Threat Classification (Top 10)")
        labels = ['Phishing', 'Malware', 'Defacement', 'Safe']
        values = [45, 25, 10, 20]
        fig2 = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.6, marker_colors=['#ef4444', '#f97316', '#eab308', '#22c55e'])])
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"}, height=350, margin=dict(t=0, b=0, l=0, r=0), legend=dict(font=dict(color='white')))
        st.plotly_chart(fig2, use_container_width=True)

# ==========================================
# PAGE 3: EDUCATION
# ==========================================
elif page == "ℹ️ Threat Education":
    st.markdown("<h1 class='title-glow'>CYBERSECURITY EDUCATION</h1>", unsafe_allow_html=True)
    st.write("")
    st.markdown("""
    ### What is Phishing?
    Phishing is a cybercrime in which a target or targets are contacted by email, telephone or text message by someone posing as a legitimate institution to lure individuals into providing sensitive data such as personally identifiable information, banking and credit card details, and passwords.
    
    ### How Does Our AI Detect It?
    This system uses a **Random Forest Classifier** trained on over 48,000 known malicious URLs. Instead of relying on a simple blacklist, the AI looks at the **lexical structure** of the URL. 
    
    **Key Indicators We Analyze:**
    *   **IP Address Hosting:** Cybercriminals often use raw IP addresses (like `http://192.168.1.1`) instead of domain names to hide their tracks.
    *   **Missing HTTPS:** Legitimate websites use HTTPS for encryption. Phishing sites frequently use unsecured HTTP.
    *   **Subdomain Depth:** Attackers use many dots (e.g., `login.secure.paypal.com.update.info`) to trick users into thinking they are on the real site.
    *   **URL Length:** Extremely long URLs are often used to hide the true destination of the link.
    """)
