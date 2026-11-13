import streamlit as st
import pandas as pd
import joblib
import re

# 1. Load the model we saved to your Google Drive
# Note: We use the permanent path so it always finds it
model = joblib.load('threat_model.pkl')

# 2. The feature extractor
def extract_features(url):
    length = len(url)
    has_at = 1 if '@' in url else 0
    has_ip = 1 if re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_https = 1 if url.startswith('https') else 0
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    return [length, has_at, has_ip, has_https, num_dots, num_hyphens]

# 3. Page Config
st.set_page_config(page_title="Threat Scanner", page_icon="🛡️", layout="centered")

# 4. CUSTOM CSS (The Magic Design)
st.markdown("""
<style>
    /* Dark background */
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    /* Input box styling */
    .stTextInput>div>div>input {
        color: #00FFAA;
        background-color: #1E232F;
        border: 1px solid #00FFAA;
        border-radius: 8px;
        padding: 12px;
        font-family: 'Courier New', monospace;
    }
    /* Button styling */
    .stButton>button {
        background-color: #00FFAA;
        color: #0E1117;
        border: none;
        border-radius: 8px;
        font-weight: bold;
        width: 100%;
        padding: 12px;
        transition: 0.3s;
        font-size: 18px;
    }
    .stButton>button:hover {
        background-color: #00CC88;
        box-shadow: 0 0 20px #00FFAA;
        color: #0E1117;
    }
    /* Typography */
    h1, h3, p {
        font-family: 'Courier New', monospace;
    }
    .title-text {
        text-align: center;
        color: #00FFAA;
        text-shadow: 0 0 10px #00FFAA;
        font-weight: bold;
    }
    .sub-text {
        text-align: center; 
        color: #888;
        font-size: 14px;
        margin-bottom: 30px;
    }
</style>
""", unsafe_allow_html=True)

# 5. THE INTERFACE
st.markdown("<h1 class='title-text'>🛡️ ADVANCED PHISHING DETECTOR</h1>", unsafe_allow_html=True)
st.markdown("<p class='sub-text'>AI-Powered URL Analysis · Threat Scoring</p>", unsafe_allow_html=True)

url_input = st.text_input("ENTER TARGET URL:", placeholder="http://example.com")

if st.button("INITIATE SCAN 🚀"):
    if url_input:
        features = extract_features(url_input)
        features_df = pd.DataFrame([features], columns=['length', 'has_at', 'has_ip', 'has_https', 'num_dots', 'num_hyphens'])
        
        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]
        
        st.write("---")
        
        # DISPLAY RESULTS
        if prediction == 1:
            st.error(f"🚨 **PHISHING DETECTED**")
            st.write(f"**Threat Probability:** {probability[1] * 100:.2f}%")
        else:
            st.success(f"✅ **SYSTEM SECURE: Legitimate URL**")
            st.write(f"**Safety Probability:** {probability[0] * 100:.2f}%")
            
        # TELEMETRY LOG (Like the screenshots)
        st.markdown("### 📊 Threat Matrix Log")
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**URL Length:** {features[0]}")
            st.info(f"**Uses HTTPS:** {'Yes' if features[3] else 'No'}")
        with col2:
            st.info(f"**Uses IP Address:** {'Yes' if features[2] else 'No'}")
            st.info(f"**Number of Hyphens:** {features[5]}")
    else:
        st.warning("Please enter a URL to scan.")
