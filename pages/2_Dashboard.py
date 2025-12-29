# pages/2_Dashboard.py - COMPLETE FIXED VERSION WITH SIDEBAR + ALL 3 PAGES
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
    """Analyze vulnerability text"""
    result = {
        'vendor': 'Unknown', 'product': 'Unknown', 'version': 'N/A',
        'cve_id': None, 'description': text[:400], 'severity': 'MEDIUM',
        'severity_score': 0.60, 'cvss_v3_raw': 6.5,
        'published': datetime.now().strftime('%Y-%m-%d'),
        'last_modified': datetime.now().strftime('%Y-%m-%d'),
        'source': 'text_analysis'
    }
    
    # CVE extraction
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
                    result['severity'] = get_nvd_severity(cvss_v3_raw)
                    result['severity_score'] = get_nvd_severity_score(result['severity'])
                result['published'] = cve.get('published', result['published'])
                result['last_modified'] = cve.get('lastModified', result['last_modified'])
        except:
            pass
    
    # Vendor/Product extraction
    vendor_db = {
        'apache': ('Apache', 'HTTP Server'), 'nginx': ('Nginx', 'Nginx'),
        'httpd': ('Apache', 'HTTP Server'), 'tomcat': ('Apache', 'Tomcat'),
        'node.js': ('Node.js', 'Node.js'), 'express': ('Express', 'Express'),
        'mysql': ('Oracle', 'MySQL'), 'postgres': ('PostgreSQL', 'PostgreSQL'),
        'ubuntu': ('Canonical', 'Ubuntu Linux'), 'chrome': ('Google', 'Chrome')
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

# === SIDEBAR ===
st.sidebar.title("🛡️ Arctic Sentinel")
page = st.sidebar.selectbox("📍 Navigate", ["📊 Overview", "ℹ️ CVE Info", "🎯 MITRE Details"])

# Initialize session state
if "threat_data" not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state:
    st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state:
    st.session_state.assets_file = None

# Load uploaded file
if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

# ============================================
# PAGE 1: OVERVIEW
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Overview Dashboard")
    st.divider()
    
    # Controls
    col1, col2 = st.columns([1, 3])
    with col1:
        st.subheader("⚙️ Pipeline")
        if st.button("🔍 Scan CVEs", type="primary", help="ThreatTimelinePipeline"):
            if st.session_state.assets_file:
                with st.spinner("Running ThreatTimelinePipeline..."):
                    csv_bytes = st.session_state.assets_file.read()
                    csv_string = csv_bytes.decode('utf-8')
                    df_assets = pd.read_csv(io.StringIO(csv_string))
                    pipeline = ThreatTimelinePipeline()
                    st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
                    st.rerun()
            else:
                st.error("❌ Upload CSV first!")
        
        if st.button("🎯 MITRE CrossMap", help="5x5 MITRE+CVE mapping"):
            if len(st.session_state.threat_data) > 0:
                with st.spinner("Running MITRECrossMapper..."):
                    mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                    st.session_state.cross_mapped_data = mapper.run_mapping()
                    st.rerun()
            else:
                st.warning("⚠️ Run scan first!")
        
        if st.button("💾 Export", help="Download CSV"):
            if len(st.session_state.cross_mapped_data) > 0:
                csv = st.session_state.cross_mapped_data.to_csv(index=False).encode()
                st.download_button("📥 Download Full", csv, "threat_report.csv")
            elif len(st.session_state.threat_data) > 0:
                csv = st.session_state.threat_data.to_csv(index=False).encode()
                st.download_button("📥 Download", csv, "threats.csv")
    
    with col2:
        # Text Scanner
        st.subheader("💬 Text Vulnerability Scanner")
        vuln_text = st.text_area("Enter CVE ID or description", height=80, 
                               placeholder="Apache 2.4.57 RCE or CVE-2023-25690")
        col_add, col_search = st.columns(2)
        with col_add:
            if st.button("➕ Analyze & ADD", type="secondary"):
                if vuln_text.strip():
                    analyzed = analyze_vuln_text(vuln_text)
                    new_row = pd.DataFrame([analyzed])
                    if len(st.session_state.cross_mapped_data) > 0:
                        st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                    else:
                        st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                    st.success("✅ Added to dataset!")
                    st.rerun()
        
        with col_search:
            search_term = st.text_input("🔍 Quick Search", placeholder="CVE-2023 or T1190")
    
    # Results
    if len(st.session_state.cross_mapped_data) > 0:
        df = st.session_state.cross_mapped_data
    elif len(st.session_state.threat_data) > 0:
        df = st.session_state.threat_data
    else:
        st.info("👆 Upload assets CSV, click 'Scan CVEs', then 'MITRE CrossMap'")
        st.stop()
    
    # Metrics
    st.markdown("### 📈 Key Metrics")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_threats = len(df)
    critical = len(df[df['nvd_severity'] == 'CRITICAL'])
    high = len(df[df['nvd_severity'] == 'HIGH'])
    mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else 'mitre_top1'
    mitre_hits = df[mitre_col].notna().sum()
    avg_cvss = df['cvss_v3_raw'].mean() if 'cvss_v3_raw' in df.columns else 0
    
    with col1: st.metric("Total Threats", total_threats)
    with col2: st.metric("CRITICAL", critical, f"{critical/max(total_threats,1)*100:.1f}%")
    with col3: st.metric("HIGH", high)
    with col4: st.metric("MITRE Mapped", mitre_hits)
    with col5: st.metric("Avg CVSS", f"{avg_cvss:.1f}")
    
    # Charts Row 1
    st.markdown("### 📊 Analysis Charts")
    col1, col2 = st.columns(2)
    
    with col1:
        severity_counts = df['nvd_severity'].value_counts()
        fig_pie = px.pie(values=severity_counts.values, names=severity_counts.index, 
                        title="Severity Distribution", hole=0.4,
                        color_discrete_map={'CRITICAL': '#d62728', 'HIGH': '#ff7f0e', 
                                          'MEDIUM': '#2ca02c', 'LOW': '#1f77b4'})
        st.plotly_chart(fig_pie, width="stretch")
    
    with col2:
        # VERTICAL HISTOGRAM (not horizontal!)
        top_vendors = df['vendor'].value_counts().head(10)
        fig_hist = px.bar(x=top_vendors.index, y=top_vendors.values, 
                         title="Top Vulnerable Vendors", labels={'y': 'Count', 'x': 'Vendor'})
        st.plotly_chart(fig_hist, width="stretch")
    
    # Age Timeline
    st.markdown("### 📅 CVE Timeline (Age Coloring)")
    df_timeline = df.copy()
    df_timeline['published_date'] = pd.to_datetime(df_timeline['published'], format='mixed', errors='coerce')
    df_timeline['last_modified_date'] = pd.to_datetime(df_timeline['last_modified'], format='mixed', errors='coerce')
    df_timeline['current_date'] = pd.to_datetime('today').normalize()
    df_timeline['days_since_modified'] = (df_timeline['current_date'] - df_timeline['last_modified_date']).dt.days.clip(lower=0)
    df_timeline['age_category'] = pd.cut(df_timeline['days_since_modified'], 
                                       bins=[0, 7, 30, 90, float('inf')], 
                                       labels=['🟢 Recent', '🟡 Medium', '🟠 Old', '🔴 Very Old'])
    
    color_map = {'🟢 Recent': '#00ff88', '🟡 Medium': '#ffaa00', '🟠 Old': '#ff4400', '🔴 Very Old': '#cc0000'}
    fig_timeline = px.timeline(df_timeline.head(100), x_start="published_date", x_end="last_modified_date",
                              y="cve_id", color="age_category", color_discrete_map=color_map,
                              title="Timeline: Darker = Older Vulnerability")
    fig_timeline.update_yaxes(categoryorder="total ascending")
    st.plotly_chart(fig_timeline, width="stretch")
    
    # Search Results
    if search_term:
        st.markdown("---")
        st.subheader(f"🔍 Search Results: '{search_term}'")
        filtered_df = df[
            df['cve_id'].astype(str).str.contains(search_term, case=False, na=False) |
            df['description'].astype(str).str.contains(search_term, case=False, na=False) |
            df['vendor'].astype(str).str.contains(search_term, case=False, na=False)
        ]
        if len(filtered_df) > 0:
            st.dataframe(filtered_df[['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw']].head(20), width="stretch")
        else:
            st.info("No matches found")

# ============================================
# PAGE 2: CVE INFO (Organization View)
# ============================================
elif page == "ℹ️ CVE Info":
    st.markdown("## ℹ️ CVE Information & Organization View")
    st.divider()
    
    if len(st.session_state.cross_mapped_data) > 0:
        df = st.session_state.cross_mapped_data
    elif len(st.session_state.threat_data) > 0:
        df = st.session_state.threat_data
    else:
        st.info("⚠️ Run analysis first!")
        st.stop()
    
    # Organization breakdown
    st.markdown("### 🏢 Organization Information")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**Most Vulnerable Vendors**")
        vendor_counts = df['vendor'].value_counts().head(5)
        for vendor, count in vendor_counts.items():
            st.write(f"🔴 {vendor}: **{count}** threats")
    
    with col2:
        st.markdown("**Critical Assets at Risk**")
        critical_assets = df[df['nvd_severity'] == 'CRITICAL'].groupby(['vendor', 'product']).size().reset_index(name='count').sort_values('count', ascending=False).head(5)
        for _, row in critical_assets.iterrows():
            st.write(f"⚠️ {row['vendor']} {row['product']}: **{row['count']}** CRITICAL")
    
    with col3:
        st.markdown("**Severity Breakdown**")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len(df[df['nvd_severity'] == severity])
            st.write(f"{severity}: **{count}**")
    
    # VERTICAL HISTOGRAM
    st.markdown("### 📊 Vendor Threat Distribution (Vertical)")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_vendor = px.bar(vendor_severity, title="Threats by Vendor & Severity", barmode='stack')
    st.plotly_chart(fig_vendor, width="stretch")
    
    # Detailed table
    st.markdown("### 📋 CVE Details")
    display_cols = ['cve_id', 'vendor', 'product', 'version', 'nvd_severity', 'cvss_v3_raw', 'published']
    st.dataframe(df[display_cols].head(50), width="stretch")

# ============================================
# PAGE 3: MITRE DETAILS (Tactics + Similarities)
# ============================================
elif page == "🎯 MITRE Details":
    st.markdown("## 🎯 MITRE ATT&CK Tactics & Techniques")
    st.divider()
    
    if len(st.session_state.cross_mapped_data) > 0:
        df = st.session_state.cross_mapped_data
    elif len(st.session_state.threat_data) > 0:
        df = st.session_state.threat_data
    else:
        st.info("⚠️ Run analysis first!")
        st.stop()
    
    # Check for MITRE columns
    mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else None
    if not mitre_col:
        st.warning("⚠️ Run 'MITRE CrossMap' to see tactics!")
        st.stop()
    
    # Top MITRE Techniques with similarities
    st.markdown("### 🎯 Top MITRE Techniques & Similarity Scores")
    
    # For each threat, show top MITRE matches
    mitre_data = []
    for idx, row in df.iterrows():
        for i in range(1, 6):  # mitre_top1 through mitre_top5
            tech_col = f'mitre_top{i}_id'
            sim_col = f'mitre_top{i}_sim'
            
            if tech_col in df.columns and pd.notna(row.get(tech_col)):
                mitre_data.append({
                    'CVE': row['cve_id'],
                    'MITRE ID': row.get(tech_col),
                    'Technique': row.get(f'mitre_top{i}_name', 'Unknown'),
                    'Similarity': f"{row.get(sim_col, 0):.3f}" if pd.notna(row.get(sim_col)) else 'N/A'
                })
    
    if mitre_data:
        mitre_df = pd.DataFrame(mitre_data)
        st.markdown("**All MITRE Mappings (Top 5 per threat)**")
        st.dataframe(mitre_df, width="stretch")
        
        # Neat presentation of similarity scores
        st.markdown("### 📊 MITRE Similarity Distribution")
        top_techniques = mitre_df['MITRE ID'].value_counts().head(10)
        fig_mitre = px.bar(x=top_techniques.index, y=top_techniques.values, 
                          title="Most Common MITRE Techniques",
                          labels={'x': 'MITRE Technique', 'y': 'Frequency'})
        st.plotly_chart(fig_mitre, width="stretch")
        
        # Heatmap of techniques by severity
        st.markdown("### 🔥 MITRE Techniques by Severity")
        severity_mitre = pd.crosstab(df[mitre_col], df['nvd_severity'])
        fig_heatmap = px.imshow(severity_mitre, title="MITRE Techniques vs Severity")
        st.plotly_chart(fig_heatmap, width="stretch")
    else:
        st.info("No MITRE data available. Run 'MITRE CrossMap'!")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | NVD + MITRE ATT&CK + Attack-BERT | Production Ready")
