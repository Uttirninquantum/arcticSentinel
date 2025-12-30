# pages/2_Dashboard.py - COMPLETE FINAL VERSION (ALL FEATURES + THREAT TIMELINE + GLOBAL SEARCH + NO CSV EXPORT + ERROR-FREE)

import streamlit as st
from models.threat_timeline import ThreatTimelinePipeline
from models.mitre_cross_mapper import MITRECrossMapper
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import re
import numpy as np
import io
import plotly.io as pio
import warnings
warnings.filterwarnings('ignore')

st.set_page_config(page_title="Arctic Sentinel", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    section[data-testid="stSidebar"] {
        width: 320px !important;
        background: linear-gradient(180deg, #1e3a8a 0%, #1e40af 100%);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# === LOAD ATTACK-BERT ===
@st.cache_resource
def load_bert_model():
    return SentenceTransformer('basel/ATTACK-BERT')

bert_model = load_bert_model()

def get_similar_cves(df, text, top_k=5):
    """Find similar CVEs using ATTACK-BERT embeddings"""
    if len(df) == 0 or pd.isna(text):
        return pd.DataFrame()
    
    try:
        text_embedding = bert_model.encode([str(text)])[0]
        cve_embeddings = bert_model.encode(df['description'].fillna('').astype(str).tolist())
        similarities = cosine_similarity([text_embedding], cve_embeddings)[0]
        
        top_indices = np.argsort(similarities)[::-1][:top_k]
        similar_df = df.iloc[top_indices].copy()
        similar_df['similarity_score'] = similarities[top_indices]
        
        return similar_df[similar_df['similarity_score'] > 0.5]
    except:
        return pd.DataFrame()

def get_nvd_cve_data(cve_id):
    """Fetch CVE data from NVD API with CVSS v3/v2 fallback"""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                cve = data['vulnerabilities'][0]['cve']
                cve_data = {
                    'cve_id': cve['id'],
                    'description': cve['descriptions'][0]['value'],
                    'published': cve.get('published', 'N/A')
                }
                
                # CVSS v3 first, then v2
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                if cvss_v3.get('baseScore', 0) > 0:
                    cve_data.update({
                        'cvss_v3_raw': cvss_v3.get('baseScore', 0),
                        'nvd_severity': cvss_v3.get('baseSeverity', 'UNKNOWN'),
                        'attack_vector': cvss_v3.get('attackVector', 'N/A')
                    })
                else:
                    cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                    score_v2 = cvss_v2.get('baseScore', 0)
                    severity_v2 = cvss_v2.get('baseSeverity', 'UNKNOWN')
                    cve_data.update({
                        'cvss_v3_raw': score_v2,
                        'nvd_severity': severity_v2,
                        'attack_vector': cvss_v2.get('accessVector', 'N/A')
                    })
                return pd.DataFrame([cve_data])
    except:
        pass
    return pd.DataFrame()

# === SESSION STATE ===
if "threat_data" not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state:
    st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state:
    st.session_state.assets_file = None
if "global_results" not in st.session_state:
    st.session_state.global_results = pd.DataFrame()

if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("## 🛡️ Arctic Sentinel")
    page = st.selectbox("📍 Navigate", ["📊 Overview", "🔐 CVE Info", "🎯 MITRE Info", "📅 Threat Timeline", "🌍 Global Search", "🔍 Search", "📄 Export PDF"])
    
    st.markdown("---")
    st.subheader("⚙️ Controls")
    if st.button("🔍 Scan CVEs", type="primary"):
        if st.session_state.assets_file:
            with st.spinner("Running pipeline..."):
                try:
                    csv_bytes = st.session_state.assets_file.read()
                    csv_string = csv_bytes.decode('utf-8')
                    df_assets = pd.read_csv(io.StringIO(csv_string))
                    pipeline = ThreatTimelinePipeline()
                    st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
                    st.rerun()
                except Exception as e:
                    st.error(f"Pipeline error: {str(e)}")
    
    if st.button("🎯 MITRE Map"):
        if len(st.session_state.threat_data) > 0:
            with st.spinner("Mapping MITRE..."):
                try:
                    mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                    st.session_state.cross_mapped_data = mapper.run_mapping()
                    st.rerun()
                except Exception as e:
                    st.error(f"MITRE mapping error: {str(e)}")

# === GET ACTIVE DATA ===
df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
has_data = len(df) > 0
total_threats = len(df)

# ============================================
# PAGE 1: OVERVIEW (NO TEXTBOX)
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    
    if not has_data:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # === METRICS ===
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("📊 Total Threats", total_threats)
    with col2: st.metric("🔴 CRITICAL", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("🟠 HIGH", len(df[df['nvd_severity']=='HIGH']))
    with col4: st.metric("📈 Avg CVSS", f"{df['cvss_v3_raw'].fillna(0).mean():.1f}")
    
    # === CHARTS ===
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(df, names='nvd_severity', hole=0.4, title="Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    with col2:
        fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors")
        st.plotly_chart(fig_vendors, use_container_width=True)

# ============================================
# PAGE 2: CVE INFO
# ============================================
elif page == "🔐 CVE Info":
    st.markdown("## 🔐 CVE Intelligence")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Unique Vendors", df['vendor'].nunique())
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    st.markdown("### 🔥 Vendor Risk Matrix")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_heatmap = px.imshow(vendor_severity, title="Vendor vs Severity", color_continuous_scale="Reds")
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    st.markdown("### 📊 All CVEs")
    display_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw', 'published']
    st.dataframe(df[display_cols].sort_values('cvss_v3_raw', ascending=False), use_container_width=True)

# ============================================
# PAGE 3: MITRE INFO
# ============================================
elif page == "🎯 MITRE Info":
    st.markdown("## 🎯 MITRE ATT&CK Tactics & Techniques")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    if not mitre_cols:
        st.warning("⚠️ Run 'MITRE Map' first!")
        st.stop()
    
    mitre_col = mitre_cols[0]
    st.markdown("### 📊 Top MITRE Techniques")
    top_mitre = df[mitre_col].value_counts().head(10)
    fig_mitre = px.bar(x=top_mitre.values, y=top_mitre.index, orientation='h', title="MITRE Technique Frequency")
    st.plotly_chart(fig_mitre, use_container_width=True)
    
    selected_mitre = st.selectbox("Select MITRE Technique:", df[mitre_col].dropna().unique())
    same_tactic = df[df[mitre_col] == selected_mitre]
    
    if len(same_tactic) > 0:
        st.info(f"**{selected_mitre}** used in {len(same_tactic)} threats")
        severity_dist = same_tactic['nvd_severity'].value_counts()
        fig_severity = px.pie(values=severity_dist.values, names=severity_dist.index, title=f"Severity for {selected_mitre}")
        st.plotly_chart(fig_severity, use_container_width=True)
        
        cve_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw']
        st.dataframe(same_tactic[cve_cols], use_container_width=True)

# ============================================
# PAGE 4: THREAT TIMELINE
# ============================================
elif page == "📅 Threat Timeline":
    st.markdown("## 📅 Threat Timeline - CVE Evolution")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    df_timeline = df.copy()
    df_timeline['published_date'] = pd.to_datetime(df_timeline['published'], errors='coerce')
    df_timeline = df_timeline.dropna(subset=['published_date']).sort_values('published_date')
    
    if len(df_timeline) == 0:
        st.warning("No CVEs with valid dates")
        st.stop()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Earliest CVE", df_timeline['published_date'].min().strftime('%Y-%m-%d'))
    with col2: st.metric("Latest CVE", df_timeline['published_date'].max().strftime('%Y-%m-%d'))
    with col3: st.metric("Span (days)", f"{(df_timeline['published_date'].max() - df_timeline['published_date'].min()).days}")
    with col4: st.metric("Total CVEs", len(df_timeline))
    
    daily_cves = df_timeline.groupby('published_date').size().reset_index(name='count')
    fig_timeline = px.area(daily_cves, x='published_date', y='count', title="CVEs Published Over Time")
    st.plotly_chart(fig_timeline, use_container_width=True)
    
    severity_timeline = df_timeline.groupby(['published_date', 'nvd_severity']).size().reset_index(name='count')
    fig_severity_time = px.area(severity_timeline, x='published_date', y='count', color='nvd_severity',
                               title="Severity Evolution", color_discrete_map={
                                   'CRITICAL': '#dc2626', 'HIGH': '#ea580c', 'MEDIUM': '#f59e0b', 'LOW': '#10b981'
                               })
    st.plotly_chart(fig_severity_time, use_container_width=True)

# ============================================
# PAGE 5: GLOBAL SEARCH
# ============================================
elif page == "🌍 Global Search":
    st.markdown("## 🌍 Global CVE Search - NVD Database")
    
    col1, col2 = st.columns(2)
    with col1:
        global_query = st.text_area("🔍 Search NVD...", height=100,
                                   placeholder="path traversal, RCE, SQL injection, buffer overflow")
    with col2:
        days_back = st.slider("Last", 30, 365, 90)
        severity_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
    
    if st.button("🚀 Search NVD API", type="primary", use_container_width=True):
        if global_query.strip():
            with st.spinner("🔍 Querying NVD API..."):
                try:
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=days_back)
                    
                    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {
                        'keywordSearch': global_query,
                        'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                        'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
                        'resultsPerPage': 1000
                    }
                    
                    response = requests.get(nvd_url, params=params, timeout=30)
                    nvd_data = response.json()
                    
                    global_cves = []
                    for vuln in nvd_data.get('vulnerabilities', []):
                        cve = vuln['cve']
                        cve_data = {
                            'cve_id': cve['id'],
                            'description': cve['descriptions'][0]['value'],
                            'published': cve.get('published', 'N/A')
                        }
                        
                        metrics = cve.get('metrics', {})
                        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                        if cvss_v3.get('baseScore', 0) > 0:
                            cve_data.update({
                                'cvss_v3_raw': cvss_v3.get('baseScore', 0),
                                'nvd_severity': cvss_v3.get('baseSeverity', 'UNKNOWN')
                            })
                        else:
                            cvss_v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                            cve_data.update({
                                'cvss_v3_raw': cvss_v2.get('baseScore', 0),
                                'nvd_severity': cvss_v2.get('baseSeverity', 'UNKNOWN')
                            })
                        
                        global_cves.append(cve_data)
                    
                    global_df = pd.DataFrame(global_cves)
                    global_df = global_df[global_df['nvd_severity'].isin(severity_filter)]
                    st.session_state.global_results = global_df
                    
                    st.success(f"✅ Found {len(global_df)} global CVEs")
                    st.rerun()
                except Exception as e:
                    st.error(f"NVD API error: {str(e)}")
    
    if 'global_results' in st.session_state and len(st.session_state.global_results) > 0:
        global_df = st.session_state.global_results
        
        col1, col2, col3 = st.columns(3)
        with col1: st.metric("🌍 Global Matches", len(global_df))
        with col2: st.metric("🔴 Critical", len(global_df[global_df['nvd_severity']=='CRITICAL']))
        with col3: st.metric("📊 Avg CVSS", f"{global_df['cvss_v3_raw'].mean():.1f}")
        
        st.markdown("### ➕ Add to Dataset")
        for idx, (_, row) in enumerate(global_df.head(10).iterrows()):
            if st.button(f"➕ Add {row['cve_id']}", key=f"add_global_{idx}"):
                new_row = pd.DataFrame([row])
                if len(st.session_state.cross_mapped_data) > 0:
                    st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                else:
                    st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                st.success(f"✅ Added {row['cve_id']}")
                st.rerun()

# ============================================
# PAGE 6: SEARCH
# ============================================
elif page == "🔍 Search":
    st.markdown("## 🔍 Advanced Threat Search")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: search_cve = st.text_input("CVE ID")
    with col2: search_vendor = st.text_input("Vendor")
    with col3: search_product = st.text_input("Product")
    
    col1, col2, col3 = st.columns(3)
    with col1: severity_filter = st.multiselect("Severity", df['nvd_severity'].unique())
    with col2: cvss_min = st.slider("Min CVSS", 0.0, 10.0, 0.0)
    
    results = df.copy()
    if search_cve: results = results[results['cve_id'].str.contains(search_cve, case=False, na=False)]
    if search_vendor: results = results[results['vendor'].str.contains(search_vendor, case=False, na=False)]
    if search_product: results = results[results['product'].str.contains(search_product, case=False, na=False)]
    if severity_filter: results = results[results['nvd_severity'].isin(severity_filter)]
    if cvss_min > 0: results = results[results['cvss_v3_raw'] >= cvss_min]
    
    st.success(f"✅ **{len(results)}** results found")
    st.dataframe(results[['cve_id', 'vendor', 'nvd_severity', 'cvss_v3_raw']].sort_values('cvss_v3_raw', ascending=False), use_container_width=True)

# ============================================
# PAGE 7: EXPORT PDF
# ============================================
elif page == "📄 Export PDF":
    st.markdown("## 📄 Generate PDF Report")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Critical", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    if st.button("🚀 GENERATE PDF REPORT", type="primary", use_container_width=True):
        with st.spinner("📄 Creating PDF..."):
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib import colors
                from reportlab.lib.units import inch
                
                pdf_buffer = io.BytesIO()
                doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
                styles = getSampleStyleSheet()
                heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], 
                                              fontSize=16, textColor=colors.HexColor('#1e3a8a'))
                body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=10)
                
                story = []
                story.append(Paragraph("🛡️ ARCTIC SENTINEL THREAT REPORT", styles['Heading1']))
                story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
                story.append(Spacer(1, 20))
                
                critical = len(df[df['nvd_severity'] == 'CRITICAL'])
                story.append(Paragraph("📋 Executive Summary", heading_style))
                summary_text = f"<b>Total:</b> {total_threats} | <b>Critical:</b> {critical} | <b>Avg CVSS:</b> {df['cvss_v3_raw'].mean():.1f}"
                story.append(Paragraph(summary_text, body_style))
                
                sev_data = [['Severity', 'Count']]
                for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = len(df[df['nvd_severity']==sev])
                    sev_data.append([sev, str(count)])
                
                sev_table = Table(sev_data)
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                    ('GRID', (0,0), (-1,-1), 1, colors.black)
                ]))
                story.append(sev_table)
                
                doc.build(story)
                pdf_buffer.seek(0)
                
                st.download_button("📥 Download PDF", pdf_buffer.getvalue(),
                                 f"arctic_sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                 "application/pdf", use_container_width=True)
                st.success("✅ PDF Generated!")
            except Exception as e:
                st.error(f"PDF error: {str(e)}")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | Production Ready")
