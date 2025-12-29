# pages/2_Dashboard.py - FULL INTEGRATION WITH BOTH PIPELINES
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

st.set_page_config(page_title="Dashboard", layout="wide")

st.markdown(
    """
    <style>
        [data-testid="stSidebar"] { display: none; }
        .block-container { padding-left: 3rem; padding-right: 3rem; padding-top: 2rem; }
        .metric-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; padding: 1.5rem; border-radius: 15px; text-align: center; 
            margin: 0.5rem 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stPlotlyChart { border-radius: 10px; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("## 🛡️ Arctic Sentinel Dashboard")
st.divider()

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

# === LEFT PANEL: CONTROLS ===
left, right = st.columns([1, 3])

with left:
    st.subheader("⚙️ Analysis Pipeline")
    
    # 1. Scan CVEs (ThreatTimelinePipeline)
    if st.button("🔍 Scan CVEs (ThreatTimeline)", type="primary", use_container_width=True, help="Full NVD + MITRE pipeline"):
        if st.session_state.assets_file is not None:
            with st.spinner("🚀 Running COMPLETE ThreatTimelinePipeline..."):
                import io
                csv_bytes = st.session_state.assets_file.read()
                csv_string = csv_bytes.decode('utf-8')
                df_assets = pd.read_csv(io.StringIO(csv_string))
                
                pipeline = ThreatTimelinePipeline()
                st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
                st.rerun()
        else:
            st.error("❌ Upload assets CSV first!")
    
    # 2. MITRE CrossMapper (FULL version)
    if st.button("🎯 Advanced MITRE Mapping", use_container_width=True, help="5 MITRE + 5 CVE similarities per threat"):
        if len(st.session_state.threat_data) > 0:
            with st.spinner("🧠 Running FULL MITRE CrossMapper..."):
                mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                st.session_state.cross_mapped_data = mapper.run_mapping()
                st.rerun()
        else:
            st.warning("⚠️ Run CVE scan first!")
    
    # 3. Export
    if st.button("💾 Export Full Report", use_container_width=True):
        if len(st.session_state.cross_mapped_data) > 0:
            csv = st.session_state.cross_mapped_data.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download (50+ cols)", csv, "threat_timeline_full.csv", "text/csv")
        elif len(st.session_state.threat_data) > 0:
            csv = st.session_state.threat_data.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download (Pipeline)", csv, "threat_timeline.csv", "text/csv")

# === ADVANCED SEARCH ===
st.subheader("🔎 Advanced Search")
search_col1, search_col2 = st.columns([3, 1])
with search_col1:
    search_term = st.text_input("Search CVEs / MITRE / Vendors", 
                              placeholder="CVE-2023-25690 or T1190 or Apache")
with search_col2:
    if st.button("🔍 Filter", type="secondary", use_container_width=True):
        pass  # Live search below

# === TEXT VULN ANALYZER ===
def analyze_vuln_text(text: str) -> Dict:
    """NLP-powered vulnerability text analysis"""
    from sentence_transformers import SentenceTransformer
    import requests, re
    
    result = {
        'vendor': None, 'product': None, 'version': None, 
        'cve_id': None, 'cpe': None, 'severity': 'MEDIUM',
        'severity_score': 0.60, 'cvss_score': 6.5,
        'mitre_top1': None, 'attack_vector': None
    }
    
    text_lower = text.lower()
    
    # 1. DIRECT CVE LOOKUP (highest priority)
    cve_match = re.search(r'CVE-(d{4})-(d+)', text, re.IGNORECASE)
    if cve_match:
        cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
        result['cve_id'] = cve_id
        
        # Fetch real NVD data
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            resp = requests.get(url, timeout=5)
            data = resp.json()
            vuln = data.get('vulnerabilities', [{}])[0]
            if vuln:
                cve = vuln['cve']
                metrics = cve.get('metrics', {})
                cvss_v3 = (metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore') 
                          if metrics.get('cvssMetricV31') else None)
                result['cvss_score'] = cvss_v3 or 6.5
                result['severity'] = get_nvd_severity(result['cvss_score'])
                result['severity_score'] = get_nvd_severity_score(result['severity'])
                result['published'] = cve.get('published')
                result['last_modified'] = cve.get('lastModified')
        except:
            pass
    
    # 2. VENDOR/PRODUCT EXTRACTION (NLP + Regex)
    vendor_db = {
        'apache': ('Apache', 'HTTP Server'), 'nginx': ('Nginx', 'Nginx'),
        'httpd': ('Apache', 'HTTP Server'), 'tomcat': ('Apache', 'Tomcat'),
        'node.js': ('Node.js', 'Node.js'), 'express': ('Express', 'Express'),
        'mysql': ('Oracle', 'MySQL'), 'postgres': ('PostgreSQL', 'PostgreSQL'),
        'ubuntu': ('Canonical', 'Ubuntu Linux'), 'chrome': ('Google', 'Chrome')
    }
    
    for key, (vendor, product) in vendor_db.items():
        if re.search(rf'\b{re.escape(key)}\b', text_lower):
            result['vendor'] = vendor
            result['product'] = product
            break
    
    # 3. VERSION EXTRACTION
    version_match = re.search(r'(d+.d+(?:.d+)?)', text)
    if version_match:
        result['version'] = version_match.group(1)
        result['cpe'] = f"cpe:2.3:a:{result.get('vendor', 'unknown')}:{result.get('product', 'unknown')}:{result['version']}:*:*:*:*:*:*:*"
    
    # 4. MITRE MAPPING (semantic)
    try:
        model = SentenceTransformer('basel/ATTACK-BERT')
        mitre_df = load_mitre_data()  # From earlier function
        mitre_emb = model.encode(mitre_df['full_text'].tolist())
        text_emb = model.encode([text])
        similarities = cosine_similarity(text_emb, mitre_emb)[0]
        top_idx = np.argsort(similarities)[-3:][::-1]
        
        result['mitre_top1'] = mitre_df.iloc[top_idx[0]]['id'] if similarities[top_idx[0]] > 0.2 else None
        result['attack_vector'] = mitre_df.iloc[top_idx[0]]['tactic_primary'] if similarities[top_idx[0]] > 0.2 else None
    except:
        pass
    
    return result

def get_nvd_severity(score):
    if score >= 9.0: return 'CRITICAL'
    if score >= 7.0: return 'HIGH'
    if score >= 4.0: return 'MEDIUM'
    if score >= 0.1: return 'LOW'
    return 'NONE'

def get_nvd_severity_score(severity):
    return {'CRITICAL': 0.95, 'HIGH': 0.80, 'MEDIUM': 0.60, 'LOW': 0.30, 'NONE': 0.0}.get(severity, 0.0)

# REPLACE the Text Vulnerability Scanner section with this:
st.subheader("💬 Text Vulnerability Scanner")
vuln_col1, vuln_col2 = st.columns([3, 1])

with vuln_col1:
    vuln_text = st.text_area("Enter CVE ID OR vulnerability description", height=100, 
                           placeholder="Apache HTTP Server 2.4.57 remote code execution vulnerability")

with vuln_col2:
    if st.button("➕ Analyze & ADD", type="secondary", use_container_width=True):
        if vuln_text.strip():
            with st.spinner("🔍 Analyzing vulnerability text..."):
                analyzed_vuln = analyze_vuln_text(vuln_text)  # New function below
                new_row = pd.DataFrame([{
                    'vendor': analyzed_vuln.get('vendor', 'Unknown'),
                    'product': analyzed_vuln.get('product', 'Unknown'),
                    'version': analyzed_vuln.get('version', 'N/A'),
                    'cpe': analyzed_vuln.get('cpe', 'manual_entry'),
                    'cve_id': analyzed_vuln.get('cve_id'),
                    'description': vuln_text[:400],
                    'nvd_severity': analyzed_vuln.get('severity', 'MEDIUM'),
                    'nvd_severity_score': analyzed_vuln.get('severity_score', 0.60),
                    'cvss_v3_raw': analyzed_vuln.get('cvss_score'),
                    'published': analyzed_vuln.get('published', datetime.now().strftime('%Y-%m-%d')),
                    'last_modified': analyzed_vuln.get('last_modified', datetime.now().strftime('%Y-%m-%d')),
                    'mitre_top1': analyzed_vuln.get('mitre_top1'),
                    'attack_vector': analyzed_vuln.get('attack_vector'),
                    'source': 'text_analysis'
                }])
                
                # Add to active dataset
                if len(st.session_state.cross_mapped_data) > 0:
                    st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                else:
                    st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                
                st.success("✅ Added vulnerability to dataset!")
                st.json(analyzed_vuln)  # Show analysis details
                st.rerun()
                
# === RIGHT PANEL: RESULTS ===
with right:
    st.subheader("📊 Threat Intelligence Dashboard")
    
    # Check data availability
    if len(st.session_state.cross_mapped_data) == 0 and len(st.session_state.threat_data) == 0:
        st.info("👆 Upload assets → Click 'Scan CVEs' → 'Advanced MITRE Mapping'")
        st.stop()
    
    # Use cross-mapped if available, else pipeline data
    df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
    
    # === KEY METRICS ===
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    total_threats = len(df)
    critical = len(df[df['nvd_severity'] == 'CRITICAL'])
    high = len(df[df['nvd_severity'] == 'HIGH'])
    mitre_hits = df['mitre_top1_id'].notna().sum() if 'mitre_top1_id' in df.columns else df['mitre_top1'].notna().sum()
    text_added = len(df[df['source'] == 'text_scanner']) if 'source' in df.columns else 0
    avg_cvss = df['cvss_v3_raw'].mean()
    
    with col1: st.metric("Total Threats", total_threats)
    with col2: st.metric("Critical", critical, f"{critical/total_threats*100:.1f}%")
    with col3: st.metric("High Risk", high)
    with col4: st.metric("MITRE Mapped", mitre_hits)
    with col5: st.metric("Text Added", text_added)
    with col6: st.metric("Avg CVSS", f"{avg_cvss:.1f}")
    
    # === CHARTS ROW 1 ===
    col1, col2 = st.columns(2)
    with col1:
        severity_counts = df['nvd_severity'].value_counts()
        fig_pie = px.pie(values=severity_counts.values, names=severity_counts.index, 
                        title="Severity Distribution", hole=0.4,
                        color_discrete_map={
                            'CRITICAL': '#d62728', 'HIGH': '#ff7f0e', 
                            'MEDIUM': '#2ca02c', 'LOW': '#1f77b4', 'NONE': '#9467bd'
                        })
        st.plotly_chart(fig_pie, use_container_width=True)
    
    with col2:
        # Top MITRE Techniques
        mitre_col = 'mitre_top1_id' if 'mitre_top1_id' in df.columns else 'mitre_top1'
        top_mitre = df[mitre_col].value_counts().head(10)
        fig_mitre = px.bar(y=top_mitre.values, x=top_mitre.index, 
                          title="Top 10 MITRE Techniques", orientation='h')
        st.plotly_chart(fig_mitre, use_container_width=True)
    
    # === AGE-COLORED TIMELINE ===
    st.subheader("📅 CVE Timeline (🟢 Recent → 🔴 Very Old)")
    df_timeline = df.copy()
    df_timeline['published_date'] = pd.to_datetime(df_timeline['published'].fillna('2025-01-01'))
    df_timeline['last_modified_date'] = pd.to_datetime(df_timeline['last_modified'].fillna('2025-01-01'))
    df_timeline['current_date'] = pd.to_datetime('today').normalize()
    df_timeline['days_since_modified'] = (df_timeline['current_date'] - df_timeline['last_modified_date']).dt.days.clip(lower=0)
    
    # Age-based coloring
    df_timeline['age_category'] = pd.cut(df_timeline['days_since_modified'], 
                                       bins=[0, 7, 30, 90, float('inf')], 
                                       labels=['🟢 Recent(<7d)', '🟡 Medium(8-30d)', '🟠 Old(31-90d)', '🔴 Very Old(>90d)'])
    
    color_map = {
        '🟢 Recent(<7d)': '#00ff00', 
        '🟡 Medium(8-30d)': '#ffaa00', 
        '🟠 Old(31-90d)': '#ff4400', 
        '🔴 Very Old(>90d)': '#aa0000'
    }
    
    fig_timeline = px.timeline(df_timeline.head(100), 
                              x_start="published_date", x_end="last_modified_date",
                              y="cve_id", color="age_category",
                              color_discrete_map=color_map,
                              title="Timeline: Darker color = Older vulnerability")
    fig_timeline.update_yaxes(categoryorder="total ascending")
    fig_timeline.update_layout(height=500)
    st.plotly_chart(fig_timeline, use_container_width=True)
    
    # === DATA TABLE ===
    st.subheader("📋 Complete Threat Intelligence")
    display_cols = ['cve_id', 'vendor', 'product', 'version', 'nvd_severity', 
                   'cvss_v3_raw', 'mitre_top1_id', 'mitre_top1_name', 
                   'attack_vector', 'published', 'last_modified']
    
    # Use available columns
    available_cols = [col for col in display_cols if col in df.columns]
    st.dataframe(df[available_cols].head(50), use_container_width=True)

# === LIVE SEARCH RESULTS ===
if search_term and len(df) > 0:
    st.markdown("---")
    st.subheader(f"🔍 Search Results for '{search_term}' ({len(filtered_df)} matches)")
    filtered_df = df[
        df['cve_id'].astype(str).str.contains(search_term, case=False, na=False) |
        df['description'].astype(str).str.contains(search_term, case=False, na=False) |
        df['mitre_top1_id'].astype(str).str.contains(search_term, case=False, na=False) |
        df['mitre_top1_name'].astype(str).str.contains(search_term, case=False, na=False) |
        df['vendor'].astype(str).str.contains(search_term, case=False, na=False)
    ]
    
    if len(filtered_df) > 0:
        st.dataframe(filtered_df[['cve_id', 'description', 'nvd_severity', 'mitre_top1_id', 'vendor']].head(20))

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | NVD + MITRE ATT&CK + Attack-BERT | Production Ready")