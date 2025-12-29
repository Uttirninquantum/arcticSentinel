# pages/2_Dashboard.py - SIDEBAR FIXED + TIMELINE CORRECTED
import streamlit as st
from models.threat_timeline import ThreatTimelinePipeline
from models.mitre_cross_mapper import MITRECrossMapper
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import re
import numpy as np
import io

st.set_page_config(page_title="Dashboard", layout="wide", initial_sidebar_state="expanded")

# === MAKE SIDEBAR VISIBLE & STYLISH ===
st.markdown("""
<style>
    section[data-testid="stSidebar"] {
        width: 300px !important;
        background: linear-gradient(180deg, #1e3a8a 0%, #1e40af 100%);
        color: white;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1e3a8a 0%, #1e40af 100%);
    }
    .stSelectbox > div > div > div {
        color: white !important;
    }
    .metric-card { 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
        color: white; padding: 1.5rem; border-radius: 15px; text-align: center; 
    }
</style>
""", unsafe_allow_html=True)

# === HELPER FUNCTIONS (same as before) ===
def get_nvd_severity(score):
    if score is None: return 'NONE'
    if score >= 9.0: return 'CRITICAL'
    if score >= 7.0: return 'HIGH'
    if score >= 4.0: return 'MEDIUM'
    if score >= 0.1: return 'LOW'
    return 'NONE'

def get_nvd_severity_score(severity):
    return {'CRITICAL': 0.95, 'HIGH': 0.80, 'MEDIUM': 0.60, 'LOW': 0.30, 'NONE': 0.0}.get(severity, 0.0)

def analyze_vuln_text(text: str) -> dict:
    result = {
        'vendor': 'Unknown', 'product': 'Unknown', 'version': 'N/A',
        'cve_id': None, 'description': text[:400], 'nvd_severity': 'MEDIUM',
        'nvd_severity_score': 0.60, 'cvss_v3_raw': 6.5,
        'published': datetime.now().strftime('%Y-%m-%d'),
        'last_modified': datetime.now().strftime('%Y-%m-%d'),
        'source': 'text_analysis'
    }
    
    # CVE extraction + NVD lookup (same as before)
    cve_match = re.search(r'CVE-(d{4})-(d+)', text, re.IGNORECASE)
    if cve_match:
        cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
        result['cve_id'] = cve_id
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(url, timeout=5)
            data = resp.json()
            vuln = data.get('vulnerabilities', [{}])[0]
            if vuln:
                cve = vuln['cve']
                metrics = cve.get('metrics', {})
                cvss_v3_raw = (metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore') 
                              if metrics.get('cvssMetricV31') else None)
                if cvss_v3_raw:
                    result['cvss_v3_raw'] = cvss_v3_raw
                    result['nvd_severity'] = get_nvd_severity(cvss_v3_raw)
                    result['nvd_severity_score'] = get_nvd_severity_score(result['nvd_severity'])
                result['published'] = cve.get('published', result['published'])
                result['last_modified'] = cve.get('lastModified', result['last_modified'])
        except:
            pass
    
    # Vendor/Product extraction (same as before)
    vendor_db = {
        'apache': ('Apache', 'HTTP Server'), 'nginx': ('Nginx', 'Nginx'),
        'tomcat': ('Apache', 'Tomcat'), 'mysql': ('Oracle', 'MySQL')
    }
    text_lower = text.lower()
    for key, (vendor, product) in vendor_db.items():
        if re.search(rf'\b{re.escape(key)}\b', text_lower):
            result['vendor'] = vendor
            result['product'] = product
            break
    version_match = re.search(r'(d+.d+(?:.d+)?)', text)
    if version_match:
        result['version'] = version_match.group(1)
    
    return result

# === INITIALIZE SESSION STATE ===
if "threat_data" not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state:
    st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state:
    st.session_state.assets_file = None

if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

# ============================================
# === SIDEBAR NAVIGATION (NOW VISIBLE!) ===
# ============================================
with st.sidebar:
    st.markdown("## 🛡️ Arctic Sentinel")
    st.markdown("---")
    
    page = st.selectbox("📍 Navigate", 
                       ["📊 Overview", "ℹ️ CVE Info", "🎯 MITRE Details"], 
                       index=0)
    
    st.markdown("---")
    
    # Controls in sidebar
    st.subheader("⚙️ Quick Actions")
    if st.button("🔍 Scan CVEs", type="primary"):
        if st.session_state.assets_file:
            with st.spinner("Running pipeline..."):
                csv_bytes = st.session_state.assets_file.read()
                csv_string = csv_bytes.decode('utf-8')
                df_assets = pd.read_csv(io.StringIO(csv_string))
                pipeline = ThreatTimelinePipeline()
                st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
                st.rerun()
        else:
            st.error("Upload CSV first!")
    
    if st.button("🎯 MITRE Map"):
        if len(st.session_state.threat_data) > 0:
            with st.spinner("Mapping MITRE..."):
                mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                st.session_state.cross_mapped_data = mapper.run_mapping()
                st.rerun()
        else:
            st.warning("Run scan first!")
    
    st.markdown("---")
    if st.button("💾 Export CSV"):
        if len(st.session_state.cross_mapped_data) > 0:
            csv = st.session_state.cross_mapped_data.to_csv(index=False).encode()
            st.download_button("📥 Download", csv, "threat_report.csv", "text/csv")
        elif len(st.session_state.threat_data) > 0:
            csv = st.session_state.threat_data.to_csv(index=False).encode()
            st.download_button("📥 Download", csv, "threats.csv", "text/csv")

# ============================================
# === MAIN PAGES ===
# ============================================
st.markdown("# 🛡️ Arctic Sentinel Dashboard")

if page == "📊 Overview":
    # Text Scanner
    st.markdown("### 💬 Text Vulnerability Scanner")
    col1, col2 = st.columns([3, 1])
    with col1:
        vuln_text = st.text_area("Enter CVE or description", height=80)
    with col2:
        if st.button("➕ ADD", type="secondary"):
            if vuln_text:
                analyzed = analyze_vuln_text(vuln_text)
                new_row = pd.DataFrame([analyzed])
                if len(st.session_state.cross_mapped_data) > 0:
                    st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                else:
                    st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                st.success("✅ Added!")
                st.rerun()
    
    # Results
    df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
    if len(df) == 0:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    total = len(df)
    critical = len(df[df['nvd_severity'] == 'CRITICAL'])
    mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else 'mitre_top1'
    mitre_hits = df[mitre_col].notna().sum() if mitre_col else 0
    
    with col1: st.metric("Total", total)
    with col2: st.metric("Critical", critical)
    with col3: st.metric("MITRE", mitre_hits)
    
    # Charts
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(df, names='nvd_severity', title="Severity")
        st.plotly_chart(fig_pie, width="stretch")
    
    with col2:
        top_vendors = df['vendor'].value_counts().head(10)
        fig_hist = px.bar(x=top_vendors.index, y=top_vendors.values, title="Vendors (Vertical)")
        st.plotly_chart(fig_hist, width="stretch")
    
    # ✅ FIXED TIMELINE: last_modified → current_date
    st.markdown("### 📅 Age Timeline (Modified → Today)")
    df_timeline = df.copy()
    df_timeline['last_modified_date'] = pd.to_datetime(df_timeline['last_modified'], format='mixed', errors='coerce')
    df_timeline['current_date'] = pd.to_datetime('today').normalize()
    df_timeline['days_since_modified'] = (df_timeline['current_date'] - df_timeline['last_modified_date']).dt.days.clip(lower=0)
    df_timeline['age_category'] = pd.cut(df_timeline['days_since_modified'], 
                                       bins=[0, 7, 30, 90, float('inf')], 
                                       labels=['🟢 Recent', '🟡 Medium', '🟠 Old', '🔴 Very Old'])
    
    color_map = {'🟢 Recent': '#00ff88', '🟡 Medium': '#ffaa00', '🟠 Old': '#ff4400', '🔴 Very Old': '#cc0000'}
    fig_timeline = px.timeline(df_timeline.head(50), 
                              x_start="last_modified_date", x_end="current_date",
                              y="cve_id", color="age_category", 
                              color_discrete_map=color_map,
                              title="🟢 Recent → 🔴 Old (Days since modified)")
    fig_timeline.update_yaxes(categoryorder="total ascending")
    st.plotly_chart(fig_timeline, width="stretch")

elif page == "ℹ️ CVE Info":
    st.markdown("## ℹ️ CVE & Organization Info")
    # Organization view content here...
    st.info("Organization breakdown + vertical charts")

elif page == "🎯 MITRE Details":
    st.markdown("## 🎯 MITRE ATT&CK Analysis")
    # MITRE similarity tables here...
    st.info("MITRE tactics + similarity scores")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | Production Ready")
