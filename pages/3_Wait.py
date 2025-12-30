import streamlit as st
from models.threat_timeline import ThreatTimelinePipeline
from models.mitre_cross_mapper import MITRECrossMapper
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import requests
import numpy as np
import io
import plotly.io as pio
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import warnings
import kaleido
import os

try:
    kaleido.get_chrome()
    print("✅ Chrome installed for PDF export")
except:
    print("⚠️ Chrome installation failed - PDF charts may not work")
    
warnings.filterwarnings('ignore')

st.set_page_config(page_title="Arctic Sentinel", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
    .metric-container {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        padding: 1rem;
        border-radius: 12px;
        border: 1px solid #334155;
    }
    .status-card {
        background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
        padding: 1.5rem;
        border-radius: 12px;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_bert_model():
    return SentenceTransformer('basel/ATTACK-BERT')

bert_model = load_bert_model()

def get_similar_cves(df, text, top_k=5):
    if len(df) == 0 or pd.isna(text):
        return pd.DataFrame()
    try:
        text_embedding = bert_model.encode([str(text)])[0]
        cve_embeddings = bert_model.encode(df['description'].fillna('').astype(str).tolist())
        similarities = cosine_similarity([text_embedding], cve_embeddings)[0]
        top_indices = np.argsort(similarities)[::-1][:top_k]
        similar_df = df.iloc[top_indices].copy()
        similar_df['similarity_score'] = similarities[top_indices]
        return similar_df[similar_df['similarity_score'] > 0.2]
    except:
        return pd.DataFrame()

def generate_nlp_remediation(df):
    critical_count = len(df[df['nvd_severity'] == 'CRITICAL'])
    high_count = len(df[df['nvd_severity'] == 'HIGH'])
    top_vendors = df['vendor'].value_counts().head(3).index.tolist()
    total_threats = len(df)
    
    remediation = f"""
    <b>🚨 IMMEDIATE ACTIONS (0-24h):</b><br/>
    • Prioritize {critical_count} CRITICAL vulnerabilities ({critical_count/total_threats*100:.1f}%)<br/>
    • Isolate {', '.join(top_vendors[:2])} systems immediately<br/>
    • Deploy emergency patches + WAF rules<br/>
    <br/>
    <b>🔧 SHORT-TERM (1-7 days):</b><br/>
    • Patch {high_count} HIGH severity CVEs<br/>
    • Update IDS/IPS signatures<br/>
    • Network segmentation review<br/>
    <br/>
    <b>🛡️ LONG-TERM (30+ days):</b><br/>
    • Automated patch management pipeline<br/>
    • Vendor risk assessment: {top_vendors[0]}<br/>
    • 72h SLA for critical patches
    """
    return remediation

if "threat_data" not in st.session_state: st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state: st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state: st.session_state.assets_file = None

if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

st.markdown("# 🛡️ **Arctic Sentinel**")
st.markdown("---")

col1, col2 = st.columns([3,1])
with col2:
    if st.button("📤 Upload New CVE File", type="secondary"):
        st.switch_page("pages/1_Upload.py")

st.markdown("### 🧊 **Analysis Status**")
status_col1, status_col2, status_col3 = st.columns(3)

with status_col1:
    if st.session_state.assets_file:
        st.markdown("""
        <div class="status-card">
            <h4>✅ File Loaded</h4>
            <p>Ready for CVE scan</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-card">
            <h4>📤 No File</h4>
            <p>Upload CSV first</p>
        </div>
        """, unsafe_allow_html=True)

with status_col2:
    if len(st.session_state.threat_data) > 0:
        st.markdown(f"""
        <div class="status-card">
            <h4>📊 {len(st.session_state.threat_data)} Threats</h4>
            <p>CVEs analyzed</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-card">
            <h4>🔍 Not Scanned</h4>
            <p>Run CVE pipeline</p>
        </div>
        """, unsafe_allow_html=True)

with status_col3:
    if len(st.session_state.cross_mapped_data) > 0:
        st.markdown("""
        <div class="status-card">
            <h4>🎯 MITRE Mapped</h4>
            <p>Full analysis ready</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-card">
            <h4>🗺️ Not Mapped</h4>
            <p>Run MITRE mapping</p>
        </div>
        """, unsafe_allow_html=True)

st.markdown("---")

page = st.selectbox("📍 Navigate", ["📤 Upload", "🔍 Scan CVEs", "🎯 MITRE Map", "📊 Overview", "🔐 CVE Info", "🎯 MITRE Info", "🔍 Search", "📄 Export PDF"])

df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
has_data = len(df) > 0
total_threats = len(df)

if page == "📤 Upload":
    st.markdown("## 📤 Upload Assets CSV")
    uploaded = st.file_uploader("Choose CSV file", type="csv", help="Upload your asset inventory CSV")
    
    if uploaded:
        col1, col2 = st.columns(2)
        with col1:
            st.success("✅ File selected")
        with col2:
            st.empty()
        
        if st.button("➤ Next: Scan CVEs", type="primary", use_container_width=True):
            st.session_state["file"] = uploaded
            st.switch_page("pages/2_Dashboard.py")

elif page == "🔍 Scan CVEs":
    st.markdown("## 🔍 CVE Threat Analysis")
    
    st.markdown("### 📤 File Status")
    if st.session_state.assets_file:
        csv_bytes = st.session_state.assets_file.read()
        csv_string = csv_bytes.decode('utf-8')
        preview_df = pd.read_csv(io.StringIO(csv_string))
        st.dataframe(preview_df.head(), use_container_width=True)
        
        if st.button("🚀 Run CVE Pipeline", type="primary", use_container_width=True):
            with st.spinner("🔍 Scanning vulnerabilities..."):
                try:
                    csv_bytes = st.session_state.assets_file.read()
                    csv_string = csv_bytes.decode('utf-8')
                    df_assets = pd.read_csv(io.StringIO(csv_string))
                    pipeline = ThreatTimelinePipeline()
                    st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
                    st.success(f"✅ Found {len(st.session_state.threat_data)} threats!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Pipeline error: {str(e)}")
    else:
        st.warning("👆 Upload file first")

elif page == "🎯 MITRE Map":
    st.markdown("## 🎯 MITRE ATT&CK Mapping")
    
    if len(st.session_state.threat_data) == 0:
        st.warning("🔍 Run CVE scan first!")
        st.stop()
    
    st.info(f"📊 {len(st.session_state.threat_data)} threats ready for MITRE mapping")
    
    if st.button("🎯 Generate MITRE Mapping", type="primary", use_container_width=True):
        with st.spinner("🗺️ Mapping to MITRE ATT&CK..."):
            try:
                mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                st.session_state.cross_mapped_data = mapper.run_mapping()
                st.success(f"✅ MITRE mapping complete!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ MITRE error: {str(e)}")

elif page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Dashboard")
    
    if not has_data:
        st.info("🔍 Scan CVEs → 🎯 MITRE Map to unlock dashboard")
        st.stop()
    
    st.markdown("### 📈 Executive Summary")
    col1, col2, col3, col4 = st.columns(4)
    with col1: 
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("📊 Total Threats", total_threats)
        st.markdown('</div>', unsafe_allow_html=True)
    with col2: 
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🔴 CRITICAL", len(df[df['nvd_severity']=='CRITICAL']))
        st.markdown('</div>', unsafe_allow_html=True)
    with col3: 
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("🟠 HIGH", len(df[df['nvd_severity']=='HIGH']))
        st.markdown('</div>', unsafe_allow_html=True)
    with col4: 
        st.markdown('<div class="metric-container">', unsafe_allow_html=True)
        st.metric("📈 Avg CVSS", f"{df['cvss_v3_raw'].fillna(0).mean():.1f}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(df, names='nvd_severity', hole=0.4, title="Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    with col2:
        fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors")
        st.plotly_chart(fig_vendors, use_container_width=True)
    
    st.markdown("### 📅 Timeline Analysis")
    df_timeline = df.copy()
    df_timeline['published_date'] = pd.to_datetime(df_timeline['published'], errors='coerce')
    df_timeline = df_timeline.dropna(subset=['published_date']).sort_values('published_date')
    
    if len(df_timeline) > 0:
        col1, col2, col3 = st.columns(3)
        with col1: st.metric("📅 Earliest", df_timeline['published_date'].min().strftime('%Y-%m-%d'))
        with col2: st.metric("📅 Latest", df_timeline['published_date'].max().strftime('%Y-%m-%d'))
        with col3: st.metric("📏 Span", f"{(df_timeline['published_date'].max() - df_timeline['published_date'].min()).days}d")
        
        col1, col2 = st.columns(2)
        with col1:
            daily_cves = df_timeline.groupby('published_date').size().reset_index(name='count')
            fig_timeline = px.area(daily_cves, x='published_date', y='count', 
                                   title="Publication Timeline", height=300)
            st.plotly_chart(fig_timeline, use_container_width=True)
        
        with col2:
            current_time = pd.Timestamp.now()
            df_gantt = df_timeline.head(20).copy()
            df_gantt['end_date'] = current_time
            fig_gantt = px.timeline(df_gantt, x_start="published_date", x_end="end_date",
                                   y="cve_id", color="nvd_severity",
                                   title="CVE Age Gantt (Top 20)", height=300,
                                   color_discrete_map={'CRITICAL': '#dc2626', 'HIGH': '#ea580c'})
            fig_gantt.update_yaxes(autorange="reversed")
            st.plotly_chart(fig_gantt, use_container_width=True)
    else:
        st.info("No valid publication dates found")

elif page == "🔐 CVE Info":
    st.markdown("## 🔐 CVE Intelligence")
    
    if not has_data:
        st.warning("🔍 Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Unique Vendors", df['vendor'].nunique())
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    st.markdown("### 🔥 Vendor Risk Heatmap")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_heatmap = px.imshow(vendor_severity, title="Vendor vs Severity", color_continuous_scale="Reds")
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    st.markdown("### 🔗 CVE Relationships")
    selected_cve = st.selectbox("Select CVE:", df['cve_id'].unique())
    selected_row = df[df['cve_id'] == selected_cve].iloc[0]
    
    related_cves = get_similar_cves(df, selected_row['description'], top_k=8)
    related_cves = related_cves[related_cves['cve_id'] != selected_cve]
    
    if len(related_cves) > 0:
        st.success(f"Found {len(related_cves)} related CVEs")
        for _, row in related_cves.iterrows():
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.markdown(f"**{row['cve_id']}** | {row['vendor']} {row['product']}")
                st.caption(row['description'][:200])
            with col2:
                st.metric("Similarity", f"{row['similarity_score']:.1%}")
            with col3:
                st.metric("Severity", row['nvd_severity'])
            st.divider()
    
    st.markdown("### 📋 CVE Table")
    display_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw', 'published']
    st.dataframe(df[display_cols].sort_values('cvss_v3_raw', ascending=False), use_container_width=True)

elif page == "🎯 MITRE Info":
    st.markdown("## 🎯 MITRE ATT&CK Framework")
    
    if not has_data:
        st.warning("🔍 Run analysis first!")
        st.stop()
    
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    if not mitre_cols:
        st.warning("🎯 Run MITRE Map first!")
        st.stop()
    
    mitre_col = mitre_cols[0]
    
    st.markdown("### 📊 MITRE Tactics Distribution")
    top_mitre = df[mitre_col].value_counts().head(10)
    fig_mitre = px.bar(x=top_mitre.values, y=top_mitre.index, orientation='h', title="Top Tactics")
    st.plotly_chart(fig_mitre, use_container_width=True)
    
    selected_mitre = st.selectbox("Select Tactic:", df[mitre_col].dropna().unique())
    mitre_cves = df[df[mitre_col] == selected_mitre]
    
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**{selected_mitre}** affects {len(mitre_cves)} CVEs")
        attack_vectors = mitre_cves['attack_vector'].value_counts()
        for vector, count in attack_vectors.head(3).items():
            st.caption(f"• {vector}: {count} CVEs")
    
    with col2:
        severity_dist = mitre_cves['nvd_severity'].value_counts()
        fig_pie = px.pie(values=severity_dist.values, names=severity_dist.index, title="Severity")
        st.plotly_chart(fig_pie, use_container_width=True)

elif page == "🔍 Search":
    st.markdown("## 🔍 Advanced Search")
    
    if not has_data:
        st.warning("🔍 Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: 
        search_cve = st.text_input("🔢 CVE ID", placeholder="CVE-2023-")
        search_vendor = st.text_input("🏢 Vendor", placeholder="Apache")
    with col2:
        search_product = st.text_input("📦 Product", placeholder="HTTP Server")
        mitre_search = st.text_input("🎯 MITRE ID", placeholder="T1190")
    with col3:
        severity_filter = st.multiselect("Severity", df['nvd_severity'].unique())
        cvss_min = st.slider("Min CVSS", 0.0, 10.0, 0.0)
    
    results = df.copy()
    if search_cve: results = results[results['cve_id'].str.contains(search_cve, case=False, na=False)]
    if search_vendor: results = results[results['vendor'].str.contains(search_vendor, case=False, na=False)]
    if search_product: results = results[results['product'].str.contains(search_product, case=False, na=False)]
    if mitre_search:
        mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
        if mitre_cols: results = results[results[mitre_cols[0]].str.contains(mitre_search, case=False, na=False)]
    if severity_filter: results = results[results['nvd_severity'].isin(severity_filter)]
    if cvss_min > 0: results = results[results['cvss_v3_raw'] >= cvss_min]
    
    st.success(f"✅ **{len(results)}** results")
    
    st.markdown("### 📋 Results")
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    mitre_col = mitre_cols[0] if mitre_cols else None
    
    for _, row in results.iterrows():
        with st.container():
            col1, col2, col3, col4, col5, col6 = st.columns([1.5, 1.5, 1.2, 2, 1.5, 2])
            
            with col1: st.markdown(f"**🏢 {row['vendor']}**")
            with col2: st.markdown(f"**📦 {row['product']}**")
            with col3: st.markdown(f"**🔢 {row['cve_id']}**")
            with col4: st.markdown(row['description'] + "...")
            with col5: 
                if mitre_col and pd.notna(row[mitre_col]):
                    st.markdown(f"**🎯 {row[mitre_col]}**")
                else:
                    st.markdown("**🎯 N/A**")
            with col6: st.markdown(f"**{row['nvd_severity']}** | **CVSS:** {row['cvss_v3_raw']:.1f}")
            
            st.divider()

elif page == "📄 Export PDF":
    st.markdown("## 📄 Professional Reports")
    os.system("plotly_get_chrome -y")
    
    if not has_data:
        st.warning("🔍 Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Critical", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    st.markdown("### 🚀 Generate Report")
    if st.button("📥 DOWNLOAD COMPLETE PDF", type="primary", use_container_width=True):
        with st.spinner("📄 Building report..."):
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], 
                                          fontSize=16, textColor=colors.HexColor('#1e3a8a'))
            body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=10)
            
            story = []
            
            story.append(Paragraph("🛡️ ARCTIC SENTINEL - THREAT REPORT", styles['Heading1']))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
            story.append(Spacer(1, 20))
            
            critical = len(df[df['nvd_severity'] == 'CRITICAL'])
            summary = f"<b>Total CVEs:</b> {total_threats} | <b>Critical:</b> {critical} | <b>Avg CVSS:</b> {df['cvss_v3_raw'].mean():.1f}"
            story.append(Paragraph(summary, body_style))
            story.append(Spacer(1, 12))
            
            fig_pie = px.pie(df, names='nvd_severity', hole=0.4)
            pie_png = pio.to_image(fig_pie, format="png", width=500, height=400)
            story.append(Paragraph("📊 Severity Distribution", heading_style))
            story.append(Image(pie_png, width=5*inch, height=3.5*inch))
            story.append(Spacer(1, 12))
            
            fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors")
            vendors_png = pio.to_image(fig_vendors, format="png", width=500, height=400)
            story.append(Paragraph("🏢 Top Vendors", heading_style))
            story.append(Image(vendors_png, width=5*inch, height=3.5*inch))
            story.append(Spacer(1, 12))
            
            df_timeline = df.copy()
            df_timeline['published_date'] = pd.to_datetime(df_timeline['published'], errors='coerce')
            df_timeline = df_timeline.dropna(subset=['published_date'])
            if len(df_timeline) > 0:
                daily_cves = df_timeline.groupby('published_date').size().reset_index(name='count')
                fig_timeline = px.area(daily_cves, x='published_date', y='count', title="Timeline")
                timeline_png = pio.to_image(fig_timeline, format="png", width=500, height=400)
                story.append(Paragraph("📅 CVE Timeline", heading_style))
                story.append(Image(timeline_png, width=5*inch, height=3.5*inch))
                story.append(Spacer(1, 12))
            
            story.append(Paragraph("📋 Top 20 CVEs", heading_style))
            cve_data = [['CVE ID', 'Vendor', 'Product', 'Severity', 'CVSS']]
            for _, row in df.nlargest(20, 'cvss_v3_raw').iterrows():
                cve_data.append([
                    str(row['cve_id'])[:15], str(row['vendor'])[:12], str(row['product'])[:12],
                    row['nvd_severity'], f"{row['cvss_v3_raw']:.1f}"
                ])
            cve_table = Table(cve_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 0.8*inch, 0.8*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('FONTSIZE', (0,0), (-1,-1), 8)
            ]))
            story.append(cve_table)
            story.append(PageBreak())
            
            story.append(Paragraph("🔧 REMEDIATION STRATEGY", heading_style))
            remediation_text = generate_nlp_remediation(df)
            story.append(Paragraph(remediation_text, body_style))
            
            doc.build(story)
            pdf_buffer.seek(0)
            
            st.download_button(
                "📥 Download Report",
                pdf_buffer.getvalue(),
                f"arctic_sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "application/pdf",
                use_container_width=True
            )
            st.balloons()
            st.success("✅ Report ready!")
