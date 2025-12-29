# pages/2_Dashboard.py - COMPLETE CODE WITH ADVANCED SEARCH + BETTER CHARTS
import streamlit as st
from models.threat_timeline import ThreatTimelinePipeline
from models.mitre_cross_mapper import MITRECrossMapper
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import requests
import re
import numpy as np
import io
import torch

st.set_page_config(page_title="Dashboard", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    section[data-testid="stSidebar"] {
        width: 320px !important;
        background: linear-gradient(180deg, #1e3a8a 0%, #1e40af 100%);
        color: white;
    }
    .metric-card { 
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
        color: white; padding: 1.5rem; border-radius: 15px; text-align: center; 
    }
</style>
""", unsafe_allow_html=True)

# === HELPER FUNCTIONS ===
def get_nvd_severity(score):
    if score is None: return 'NONE'
    if score >= 9.0: return 'CRITICAL'
    if score >= 7.0: return 'HIGH'
    if score >= 4.0: return 'MEDIUM'
    if score >= 0.1: return 'LOW'
    return 'NONE'

def get_nvd_severity_score(severity):
    return {'CRITICAL': 0.95, 'HIGH': 0.80, 'MEDIUM': 0.60, 'LOW': 0.30, 'NONE': 0.0}.get(severity, 0.0)

def analyze_vuln_text_nlp(text: str) -> dict:
    """Advanced NLP-powered vulnerability analysis"""
    result = {
        'vendor': 'Unknown', 'product': 'Unknown', 'version': 'N/A',
        'cve_id': None, 'description': text[:400], 'nvd_severity': 'MEDIUM',
        'nvd_severity_score': 0.60, 'cvss_v3_raw': 6.5,
        'published': datetime.now().strftime('%Y-%m-%d'),
        'last_modified': datetime.now().strftime('%Y-%m-%d'),
        'source': 'nlp_analysis'
    }
    
    # 1. CVE Extraction + NVD Lookup
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
    
    # 2. NLP Vendor/Product Classification
    vendor_patterns = {
        'Apache': ['apache', 'httpd', 'tomcat'],
        'Nginx': ['nginx'],
        'Oracle': ['oracle', 'mysql'],
        'Google': ['google', 'chrome'],
        'Microsoft': ['microsoft', 'windows', 'iis'],
        'PostgreSQL': ['postgres', 'postgresql']
    }
    
    text_lower = text.lower()
    for vendor, patterns in vendor_patterns.items():
        for pattern in patterns:
            if pattern in text_lower:
                result['vendor'] = vendor
                break
        if result['vendor'] != 'Unknown':
            break
    
    product_map = {
        'Apache': 'HTTP Server', 'Nginx': 'Nginx', 'Oracle': 'MySQL',
        'Google': 'Chrome', 'Microsoft': 'Windows Server', 'PostgreSQL': 'PostgreSQL'
    }
    if result['vendor'] in product_map:
        result['product'] = product_map[result['vendor']]
    
    version_match = re.search(r'(d+.d+(?:.d+)?)', text)
    if version_match:
        result['version'] = version_match.group(1)
    
    # 3. NLP Severity Classification
    severity_keywords = {
        'CRITICAL': ['rce', 'remote code', 'root', 'privilege escalation', 'arbitrary'],
        'HIGH': ['sql injection', 'xss', 'command injection', 'auth bypass'],
        'MEDIUM': ['csrf', 'information disclosure', 'dos', 'denial'],
        'LOW': ['minor', 'information', 'log', 'configuration']
    }
    
    for sev, keywords in severity_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            result['nvd_severity'] = sev
            result['cvss_v3_raw'] = {'CRITICAL': 9.5, 'HIGH': 8.2, 'MEDIUM': 6.8, 'LOW': 4.2}[sev]
            break
    
    return result

def advanced_search(df, search_term: str):
    """Multi-field advanced search"""
    if not search_term:
        return df
    
    search_lower = search_term.lower()
    conditions = [
        df['cve_id'].astype(str).str.contains(search_lower, case=False, na=False),
        df['description'].astype(str).str.contains(search_lower, case=False, na=False),
        df['vendor'].astype(str).str.contains(search_lower, case=False, na=False),
        df['product'].astype(str).str.contains(search_lower, case=False, na=False)
    ]
    
    mitre_cols = [col for col in df.columns if 'mitre_top' in col and ('id' in col or col.endswith('_id'))]
    for col in mitre_cols:
        conditions.append(df[col].astype(str).str.contains(search_lower, case=False, na=False))
    
    filtered_df = df[pd.concat(conditions, axis=1).any(axis=1)]
    return filtered_df

# === SESSION STATE ===
if "threat_data" not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state:
    st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state:
    st.session_state.assets_file = None

if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("## 🛡️ Arctic Sentinel")
    page = st.selectbox("📍 Navigate", ["📊 Overview", "ℹ️ CVE Info", "🎯 MITRE Details", "📄 Export"])
    
    st.markdown("---")
    st.subheader("⚙️ Controls")
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
    if st.button("📄 Export PDF"):
        st.switch_page("pages/3_Export.py")

# === GET ACTIVE DATA ===
df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
has_data = len(df) > 0

# ============================================
# PAGE 1: OVERVIEW
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    
    if not has_data:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # === ADVANCED SEARCH ===
    st.markdown("### 🔍 Advanced Search")
    search_col1, search_col2 = st.columns([3, 1])
    with search_col1:
        search_term = st.text_input("Search CVEs/MITRE/Vendors...", placeholder="CVE-2023-25690, T1190, Apache")
    with search_col2:
        search_type = st.selectbox("Type:", ["All", "CVE", "MITRE", "Vendor", "Severity"])
    
    filtered_df = advanced_search(df, search_term) if search_term else df
    
    if search_term:
        st.success(f"✅ Found **{len(filtered_df)}** matches")
        st.dataframe(filtered_df[['cve_id', 'vendor', 'product', 'nvd_severity']].head(10), use_container_width=True)
    
    # === NLP TEXT SCANNER ===
    st.markdown("### 🤖 NLP Vulnerability Scanner")
    col1, col2 = st.columns([3, 1])
    with col1:
        vuln_text = st.text_area("Enter description...", height=80, placeholder="Apache 2.4.57 RCE")
    with col2:
        if st.button("🤖 Analyze NLP", type="primary"):
            if vuln_text:
                analyzed = analyze_vuln_text_nlp(vuln_text)
                col_a1, col_a2, col_a3 = st.columns(3)
                with col_a1: st.metric("Vendor", analyzed['vendor'])
                with col_a2: st.metric("Severity", analyzed['nvd_severity'])
                with col_a3: st.metric("CVSS", f"{analyzed['cvss_v3_raw']:.1f}")
                
                if st.button("➕ ADD", key="add_nlp"):
                    new_row = pd.DataFrame([analyzed])
                    if len(st.session_state.cross_mapped_data) > 0:
                        st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                    else:
                        st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                    st.success("✅ Added!")
                    st.rerun()
    
    # Metrics & Charts
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Total", len(filtered_df))
    with col2: st.metric("Critical", len(filtered_df[filtered_df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("High", len(filtered_df[filtered_df['nvd_severity']=='HIGH']))
    with col4: st.metric("Avg CVSS", f"{filtered_df['cvss_v3_raw'].mean():.1f}")
    
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(filtered_df, names='nvd_severity', hole=0.4, title="Severity")
        st.plotly_chart(fig_pie, use_container_width=True)
    with col2:
        fig_vendors = px.bar(filtered_df['vendor'].value_counts().head(10), title="Top Vendors")
        st.plotly_chart(fig_vendors, use_container_width=True)
    
    # Timeline
    df_timeline = filtered_df.copy()
    df_timeline['last_modified_date'] = pd.to_datetime(df_timeline['last_modified'], format='mixed', errors='coerce')
    df_timeline['current_date'] = pd.to_datetime('today').normalize()
    df_timeline['days_since'] = (df_timeline['current_date'] - df_timeline['last_modified_date']).dt.days.clip(lower=0)
    df_timeline['age'] = pd.cut(df_timeline['days_since'], bins=[0,7,30,90,float('inf')], 
                               labels=['🟢<7d', '🟡<30d', '🟠<90d', '🔴>90d'])
    
    color_map = {'🟢<7d': '#00ff88', '🟡<30d': '#ffaa00', '🟠<90d': '#ff4400', '🔴>90d': '#cc0000'}
    fig_timeline = px.timeline(df_timeline.head(50), x_start="last_modified_date", x_end="current_date",
                              y="cve_id", color="age", color_discrete_map=color_map)
    st.plotly_chart(fig_timeline, use_container_width=True)

# ============================================
# PAGE 2: CVE INFO - ENHANCED VISUALIZATIONS
# ============================================
elif page == "ℹ️ CVE Info":
    st.markdown("## ℹ️ CVE & Asset Intelligence")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    # Risk Heatmap by Vendor + Severity
    st.markdown("### 🔥 Risk Heatmap: Vendor vs Severity")
    vendor_severity = filtered_df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_heatmap = px.imshow(vendor_severity, title="Higher count = Higher risk", 
                           color_continuous_scale="Reds", aspect="auto")
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # Asset Risk Waterfall
    st.markdown("### 📉 Cumulative Risk by Asset")
    top_assets = filtered_df.groupby(['vendor', 'product']).agg({
        'cvss_v3_raw': 'mean', 'nvd_severity': 'count'
    }).round(2).sort_values('cvss_v3_raw', ascending=False).head(10)
    fig_waterfall = px.bar(top_assets, x=top_assets.index, y='cvss_v3_raw', 
                          title="Average CVSS by Asset", color='cvss_v3_raw')
    st.plotly_chart(fig_waterfall, use_container_width=True)
    
    # CVE Age Distribution
    st.markdown("### 📅 CVE Age Analysis")
    df_age = filtered_df.copy()
    df_age['last_modified_date'] = pd.to_datetime(df_age['last_modified'], format='mixed', errors='coerce')
    df_age['days_old'] = (pd.to_datetime('today') - df_age['last_modified_date']).dt.days.clip(lower=0)
    fig_age = px.histogram(df_age, x='days_old', nbins=30, title="Distribution of CVE Age", 
                          labels={'days_old': 'Days Since Last Modified'})
    st.plotly_chart(fig_age, use_container_width=True)

# ============================================
# PAGE 3: MITRE DETAILS - ADVANCED VISUALIZATIONS
# ============================================
elif page == "🎯 MITRE Details":
    st.markdown("## 🎯 MITRE ATT&CK Intelligence")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    mitre_cols = [col for col in df.columns if 'mitre_top' in col and ('id' in col or col.endswith('_id'))]
    if not mitre_cols:
        st.warning("⚠️ Run 'MITRE Map' first!")
        st.stop()
    
    # 1. MITRE Technique Attack Chain (Sankey Diagram)
    st.markdown("### 🔗 MITRE Attack Chain")
    mitre_data = []
    for idx, row in df.iterrows():
        for i in range(1, 4):  # Top 3 MITRE
            col = f'mitre_top{i}_id'
            if col in df.columns and pd.notna(row.get(col)):
                mitre_data.append({
                    'CVE': row['cve_id'][:10],
                    'Technique': row[col],
                    'Severity': row['nvd_severity']
                })
    
    mitre_df = pd.DataFrame(mitre_data)
    if not mitre_df.empty:
        # Sankey: Severity → Technique → Count
        fig_sankey = px.sankey(mitre_df, path=['Severity', 'Technique'],
                              title="MITRE Attack Flow: Severity → Techniques")
        st.plotly_chart(fig_sankey, use_container_width=True)
    
    # 2. Technique Risk Radar Chart
    st.markdown("### 🎯 Technique Risk Profile")
    top_tech = df[mitre_cols[0]].value_counts().head(8).index
    radar_data = []
    for tech in top_tech:
        tech_df = df[df[mitre_cols[0]] == tech]
        radar_data.append({
            'Technique': tech[:15],
            'Avg_CVSS': tech_df['cvss_v3_raw'].mean(),
            'Critical_Pct': len(tech_df[tech_df['nvd_severity']=='CRITICAL'])/max(len(tech_df),1),
            'Frequency': len(tech_df)
        })
    
    radar_df = pd.DataFrame(radar_data)
    fig_radar = px.line_polar(radar_df, r='Avg_CVSS', theta='Technique', line_close=True,
                             title="MITRE Technique Risk Radar")
    st.plotly_chart(fig_radar, use_container_width=True)
    
    # 3. Technique Timeline (Temporal Analysis)
    st.markdown("### ⏱️ MITRE Technique Evolution")
    df_mitre_time = df.copy()
    df_mitre_time['year'] = pd.to_datetime(df_mitre_time['published'], format='mixed', errors='coerce').dt.year
    mitre_time = df_mitre_time.groupby(['year', mitre_cols[0]]).size().reset_index(name='count')
    fig_time = px.line(mitre_time, x='year', y='count', color=mitre_cols[0],
                      title="MITRE Techniques Over Time")
    st.plotly_chart(fig_time, use_container_width=True)
    
    # MITRE Table
    st.markdown("### 📋 MITRE Mappings")
    st.dataframe(mitre_df.head(50), use_container_width=True)

# ============================================
# PAGE 4: EXPORT
# ============================================
elif page == "📄 Export":
    st.markdown("## 📄 Export Professional PDF Report")
    st.info("Configure options and generate comprehensive PDF with charts + remediation steps")
    st.button("Generate PDF Report", type="primary")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | Advanced Threat Intelligence")
