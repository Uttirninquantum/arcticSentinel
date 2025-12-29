# pages/2_Dashboard.py - ALL 3 PAGES FULLY IMPLEMENTED
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

def analyze_vuln_text(text: str) -> dict:
    result = {
        'vendor': 'Unknown', 'product': 'Unknown', 'version': 'N/A',
        'cve_id': None, 'description': text[:400], 'nvd_severity': 'MEDIUM',
        'nvd_severity_score': 0.60, 'cvss_v3_raw': 6.5,
        'published': datetime.now().strftime('%Y-%m-%d'),
        'last_modified': datetime.now().strftime('%Y-%m-%d'),
        'source': 'text_analysis'
    }
    
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
    
    vendor_db = {
        'apache': ('Apache', 'HTTP Server'), 'nginx': ('Nginx', 'Nginx'),
        'tomcat': ('Apache', 'Tomcat'), 'mysql': ('Oracle', 'MySQL'),
        'postgres': ('PostgreSQL', 'PostgreSQL'), 'chrome': ('Google', 'Chrome')
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
    page = st.selectbox("📍 Navigate", ["📊 Overview", "ℹ️ CVE Info", "🎯 MITRE Details"])
    
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
    if st.button("💾 Export"):
        df_export = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
        if len(df_export) > 0:
            csv = df_export.to_csv(index=False).encode()
            st.download_button("📥 Download CSV", csv, "threat_report.csv", "text/csv")

# === GET ACTIVE DATA ===
df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
has_data = len(df) > 0

# ============================================
# PAGE 1: OVERVIEW ✅ FULLY LOADED
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    
    if not has_data:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # Text Scanner
    st.markdown("### 💬 Text Vulnerability Scanner")
    col1, col2 = st.columns([3, 1])
    with col1:
        vuln_text = st.text_area("Enter CVE or description", height=80, placeholder="Apache 2.4.57 RCE")
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
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    total = len(df)
    critical = len(df[df['nvd_severity'] == 'CRITICAL'])
    high = len(df[df['nvd_severity'] == 'HIGH'])
    mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else 'mitre_top1'
    mitre_hits = df[mitre_col].notna().sum() if mitre_col and mitre_col in df.columns else 0
    avg_cvss = df['cvss_v3_raw'].mean() if 'cvss_v3_raw' in df.columns else 0
    
    with col1: st.metric("Total Threats", total)
    with col2: st.metric("CRITICAL", critical, f"{critical/max(total,1)*100:.1f}%")
    with col3: st.metric("HIGH", high)
    with col4: st.metric("MITRE Mapped", mitre_hits)
    with col5: st.metric("Avg CVSS", f"{avg_cvss:.1f}")
    
    # Charts
    col1, col2 = st.columns(2)
    with col1:
        severity_counts = df['nvd_severity'].value_counts()
        fig_pie = px.pie(values=severity_counts.values, names=severity_counts.index, hole=0.4, title="Severity")
        st.plotly_chart(fig_pie, width="stretch")
    
    with col2:
        top_vendors = df['vendor'].value_counts().head(10)
        fig_hist = px.bar(x=top_vendors.index, y=top_vendors.values, title="Top Vendors (Vertical)")
        st.plotly_chart(fig_hist, width="stretch")
    
    # Timeline: FIXED (modified → today)
    st.markdown("### 📅 Age Timeline (Modified → Today)")
    df_timeline = df.copy()
    df_timeline['last_modified_date'] = pd.to_datetime(df_timeline['last_modified'], format='mixed', errors='coerce')
    df_timeline['current_date'] = pd.to_datetime('today').normalize()
    df_timeline['days_since_modified'] = (df_timeline['current_date'] - df_timeline['last_modified_date']).dt.days.clip(lower=0)
    df_timeline['age_category'] = pd.cut(df_timeline['days_since_modified'], 
                                       bins=[0, 7, 30, 90, float('inf')], 
                                       labels=['🟢 Recent', '🟡 Medium', '🟠 Old', '🔴 Very Old'])
    
    color_map = {'🟢 Recent': '#00ff88', '🟡 Medium': '#ffaa00', '🟠 Old': '#ff4400', '🔴 Very Old': '#cc0000'}
    fig_timeline = px.timeline(df_timeline.head(50), x_start="last_modified_date", x_end="current_date",
                              y="cve_id", color="age_category", color_discrete_map=color_map,
                              title="🟢 Recent → 🔴 Old")
    st.plotly_chart(fig_timeline, width="stretch")

# ============================================
# PAGE 2: CVE INFO ✅ FULLY LOADED
# ============================================
elif page == "ℹ️ CVE Info":
    st.markdown("## ℹ️ CVE & Organization Intelligence")
    st.divider()
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    # Organization Summary Cards
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 🏢 **Most Vulnerable Vendors**")
        vendor_counts = df['vendor'].value_counts().head(5)
        for vendor, count in vendor_counts.items():
            st.metric(vendor, count)
    
    with col2:
        st.markdown("### ⚠️ **Critical Assets**")
        critical_assets = df[df['nvd_severity'] == 'CRITICAL'].groupby(['vendor', 'product']).size().reset_index(name='count').sort_values('count', ascending=False).head(5)
        for _, row in critical_assets.iterrows():
            st.metric(f"{row['vendor']} {row['product']}", row['count'])
    
    with col3:
        st.markdown("### 📊 **Severity by Vendor**")
        severity_vendor = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
        fig_small = px.bar(severity_vendor, barmode='stack', title="Severity per Vendor")
        st.plotly_chart(fig_small, width="stretch")
    
    # VERTICAL HISTOGRAM
    st.markdown("### 📈 **Threat Distribution by Vendor (Vertical)**")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_vendor = px.bar(vendor_severity, title="Vendors vs Severity (Vertical)", barmode='stack')
    st.plotly_chart(fig_vendor, width="stretch", height=500)
    
    # CVE Table
    st.markdown("### 📋 **Complete CVE Inventory**")
    display_cols = ['cve_id', 'vendor', 'product', 'version', 'nvd_severity', 'cvss_v3_raw', 'published', 'last_modified']
    available_cols = [col for col in display_cols if col in df.columns]
    st.dataframe(df[available_cols], use_container_width=True)

# ============================================
# PAGE 3: MITRE DETAILS ✅ FULLY LOADED
# ============================================
elif page == "🎯 MITRE Details":
    st.markdown("## 🎯 MITRE ATT&CK Intelligence")
    st.divider()
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else 'mitre_top1'
    if mitre_col not in df.columns or df[mitre_col].isna().all():
        st.warning("⚠️ Run 'MITRE Map' to generate MITRE mappings!")
        st.stop()
    
    # MITRE Technique Table with Similarity Scores
    st.markdown("### 🎯 **MITRE Technique Mappings (Top 5 per CVE)**")
    mitre_data = []
    for idx, row in df.iterrows():
        for i in range(1, 6):
            tech_col = f'mitre_top{i}_id'
            name_col = f'mitre_top{i}_name'
            sim_col = f'mitre_top{i}_sim'
            
            if tech_col in df.columns and pd.notna(row.get(tech_col)):
                mitre_data.append({
                    'CVE ID': row['cve_id'],
                    'MITRE ID': row[tech_col],
                    'Technique': row.get(name_col, 'N/A')[:50],
                    'Similarity': f"{row.get(sim_col, 0):.3f}" if pd.notna(row.get(sim_col)) else 'N/A',
                    'Severity': row['nvd_severity']
                })
    
    if mitre_data:
        mitre_df = pd.DataFrame(mitre_data)
        st.dataframe(mitre_df.head(50), use_container_width=True)
        
        # Top Techniques Chart
        st.markdown("### 📊 **Most Common MITRE Techniques**")
        top_techniques = mitre_df['MITRE ID'].value_counts().head(10)
        fig_mitre = px.bar(x=top_techniques.values, y=top_techniques.index, 
                          title="Top MITRE Techniques", orientation='h')
        st.plotly_chart(fig_mitre, width="stretch")
        
        # Similarity Distribution
        st.markdown("### 🔥 **Similarity Score Distribution**")
        sim_scores = pd.to_numeric(mitre_df['Similarity'], errors='coerce').dropna()
        fig_sim = px.histogram(x=sim_scores, nbins=20, title="MITRE Similarity Scores")
        st.plotly_chart(fig_sim, width="stretch")
        
        # Heatmap: Techniques vs Severity
        st.markdown("### 🌡️ **MITRE Techniques vs Severity Heatmap**")
        severity_mitre = pd.crosstab(df[mitre_col], df['nvd_severity'], normalize='index') * 100
        fig_heatmap = px.imshow(severity_mitre, title="MITRE Techniques by Severity (%)", aspect="auto")
        st.plotly_chart(fig_heatmap, width="stretch")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | NVD + MITRE ATT&CK | Production Ready")
