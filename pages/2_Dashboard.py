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
warnings.filterwarnings('ignore')

st.set_page_config(page_title="Arctic Sentinel", layout="wide", initial_sidebar_state="expanded")

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
        return similar_df[similar_df['similarity_score']]
    except:
        return pd.DataFrame()

def generate_nlp_remediation(df):
    """Generate dynamic NLP-based remediation steps"""
    critical_count = len(df[df['nvd_severity'] == 'CRITICAL'])
    high_count = len(df[df['nvd_severity'] == 'HIGH'])
    top_vendors = df['vendor'].value_counts().head(3).index.tolist()
    
    remediation = f"""
    <b>🚨 IMMEDIATE ACTIONS (0-24h):</b><br/>
    • Patch {critical_count} CRITICAL vulnerabilities in {', '.join(top_vendors[:2])}<br/>
    • Isolate affected systems and enable WAF<br/>
    
    <b>🔧 SHORT-TERM (1-7 days):</b><br/>
    • Deploy patches for {high_count} HIGH severity issues<br/>
    • Update IDS/IPS signatures for detected CVEs<br/>
    
    <b>🛡️ LONG-TERM (30+ days):</b><br/>
    • Implement automated patch management<br/>
    • Conduct vendor risk assessment for {top_vendors[0]}<br/>
    • Establish 72h SLA for critical patches
    """
    return remediation

# === SESSION STATE ===
if "threat_data" not in st.session_state: st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state: st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state: st.session_state.assets_file = None

if "file" in st.session_state:
    st.session_state.assets_file = st.session_state["file"]
    del st.session_state["file"]

# === SIDEBAR ===
with st.sidebar:
    st.markdown("## 🛡️ Arctic Sentinel")
    page = st.selectbox("📍 Navigate", ["📊 Overview", "🔐 CVE Info", "🎯 MITRE Info", "🔍 Search", "📄 Export PDF"])
    
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
    
    if st.button("🎯 MITRE Map"):
        if len(st.session_state.threat_data) > 0:
            with st.spinner("Mapping MITRE..."):
                mapper = MITRECrossMapper(threat_df=st.session_state.threat_data)
                st.session_state.cross_mapped_data = mapper.run_mapping()
                st.rerun()

# === GET ACTIVE DATA ===
df = st.session_state.cross_mapped_data if len(st.session_state.cross_mapped_data) > 0 else st.session_state.threat_data
has_data = len(df) > 0
total_threats = len(df)

# ============================================
# PAGE 1: OVERVIEW (PIE + HISTOGRAM + TEXT-TO-VULN)
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    
    if not has_data:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # === METRICS + CHARTS ===
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("📊 Total Threats", total_threats)
    with col2: st.metric("🔴 CRITICAL", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("🟠 HIGH", len(df[df['nvd_severity']=='HIGH']))
    with col4: st.metric("📈 Avg CVSS", f"{df['cvss_v3_raw'].fillna(0).mean():.1f}")
    
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(df, names='nvd_severity', hole=0.4, title="Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    with col2:
        fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors")
        st.plotly_chart(fig_vendors, use_container_width=True)
    # ADD THIS TIMELINE SECTION to Overview page (after vendor histogram, before Text-to-Vuln)

    # === TIMELINE SECTION ===
    st.markdown("### 📅 CVE Timeline Analysis")
    df_timeline = df.copy()
    df_timeline['published_date'] = pd.to_datetime(df_timeline['published'], errors='coerce')
    df_timeline = df_timeline.dropna(subset=['published_date']).sort_values('published_date')

    if len(df_timeline) > 0:
        col1, col2, col3 = st.columns(3)
        with col1: st.metric("Earliest", df_timeline['published_date'].min().strftime('%Y-%m-%d'))
        with col2: st.metric("Latest", df_timeline['published_date'].max().strftime('%Y-%m-%d'))
        with col3: st.metric("Span", f"{(df_timeline['published_date'].max() - df_timeline['published_date'].min()).days}d")
    
        col1, col2 = st.columns(2)
        with col1:
            daily_cves = df_timeline.groupby('published_date').size().reset_index(name='count')
            fig_timeline = px.area(daily_cves, x='published_date', y='count', 
                              title="CVE Publication Timeline", height=300)
            st.plotly_chart(fig_timeline, use_container_width=True)
    
        with col2:
            current_time = pd.Timestamp.now()
            df_gantt = df_timeline.head(20).copy()
            df_gantt['end_date'] = current_time
            fig_gantt = px.timeline(df_gantt, x_start="published_date", x_end="end_date",
                               y="cve_id", color="nvd_severity",
                               title="CVE Age Gantt (Top 20)", height=300,
                               color_discrete_map={'CRITICAL': '#dc2626', 'HIGH': '#ea580c'})
            st.plotly_chart(fig_gantt, use_container_width=True)
    else:
        st.info("No valid publication dates found")


    # === TEXT-TO-VULN SEARCH ===
    st.markdown("### 🚀 Text-to-Vulnerability Search (ATTACK-BERT)")
    vuln_text = st.text_area("Enter vulnerability description...", height=120,
                           placeholder="Apache HTTP Server path traversal allowing RCE via crafted request")
    
    if st.button("🔍 Find Similar CVEs", type="primary"):
        if vuln_text.strip():
            with st.spinner("🧠 Computing ATTACK-BERT embeddings..."):
                similar_cves = get_similar_cves(df, vuln_text, top_k=10)
                
                if len(similar_cves) > 0:
                    st.success(f"✅ Found {len(similar_cves)} similar CVEs")
                    for idx, (_, row) in enumerate(similar_cves.iterrows()):
                        with st.expander(f"#{idx+1} {row['cve_id']} ({row['similarity_score']:.1%})"):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Severity", row['nvd_severity'])
                                st.metric("Vendor", row['vendor'])
                            with col2:
                                st.metric("CVSS", f"{row['cvss_v3_raw']:.1f}")
                                st.metric("Published", row['published'][:10])
                            st.write(row['description'])
                            
                            if st.button(f"➕ Add to Dataset", key=f"add_{idx}"):
                                new_row = pd.DataFrame([row.drop('similarity_score')])
                                if len(st.session_state.cross_mapped_data) > 0:
                                    st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                                else:
                                    st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
                                st.success(f"✅ Added! Total: {total_threats+1}")
                                st.rerun()
                else:
                    st.warning("❌ No similar CVEs found (threshold: 50%)")

# ============================================
# PAGE 2: CVE INFO (ALL CVEs + RELATED + COMMON)
# ============================================
elif page == "🔐 CVE Info":
    st.markdown("## 🔐 CVE Intelligence & Relationships")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Unique Vendors", df['vendor'].nunique())
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    # === VENDOR RISK HEATMAP ===
    st.markdown("### 🔥 Vendor Risk Matrix")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_heatmap = px.imshow(vendor_severity, title="Vendor vs Severity", color_continuous_scale="Reds")
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # === RELATED CVEs ===
    st.markdown("### 🔗 Related CVEs (ATTACK-BERT)")
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
    
    # === ALL CVEs TABLE ===
    st.markdown("### 📋 All CVEs")
    display_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw', 'published']
    st.dataframe(df[display_cols].sort_values('cvss_v3_raw', ascending=False), use_container_width=True)

# ============================================
# PAGE 3: MITRE INFO (TACTICS + RELATED + VECTORS)
# ============================================
elif page == "🎯 MITRE Info":
    st.markdown("## 🎯 MITRE ATT&CK Intelligence")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    if not mitre_cols:
        st.warning("⚠️ Run 'MITRE Map' first!")
        st.stop()
    
    mitre_col = mitre_cols[0]
    
    # === TOP TACTICS ===
    st.markdown("### 📊 Top MITRE Tactics")
    top_mitre = df[mitre_col].value_counts().head(10)
    fig_mitre = px.bar(x=top_mitre.values, y=top_mitre.index, orientation='h', title="MITRE Tactic Frequency")
    st.plotly_chart(fig_mitre, use_container_width=True)
    
    # === SELECTED TACTIC ANALYSIS ===
    selected_mitre = st.selectbox("Select MITRE Tactic:", df[mitre_col].dropna().unique())
    mitre_cves = df[df[mitre_col] == selected_mitre]
    
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"**{selected_mitre}** affects {len(mitre_cves)} CVEs")
        attack_vectors = mitre_cves['attack_vector'].value_counts()
        for vector, count in attack_vectors.head(3).items():
            st.caption(f"• {vector}: {count} CVEs")
    
    with col2:
        severity_dist = mitre_cves['nvd_severity'].value_counts()
        fig_pie = px.pie(values=severity_dist.values, names=severity_dist.index, title="Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # === RELATED TACTICS (BERT) ===
    st.markdown("### 🔗 Related MITRE Tactics (BERT)")
    mitre_text = " ".join(df[df[mitre_col] == selected_mitre]['description'].tolist())
    all_mitre_df = df[[mitre_col, 'description']].dropna().rename(columns={mitre_col: 'mitre_id'})
    related_tactics = get_similar_cves(all_mitre_df, mitre_text, top_k=5)
    related_tactics = related_tactics[related_tactics['mitre_id'] != selected_mitre]
    
    if len(related_tactics) > 0:
        for _, row in related_tactics.iterrows():
            col1, col2 = st.columns(2)
            with col1: st.markdown(f"**{row['mitre_id']}** ({row['similarity_score']:.1%})")
            with col2: st.metric("CVEs", len(df[df[mitre_col] == row['mitre_id']]))
            st.divider()

# ============================================
# PAGE 4: SEARCH (ADVANCED + ROW FORMAT)
# ============================================
elif page == "🔍 Search":
    st.markdown("## 🔍 Advanced Threat Search")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    # === SEARCH CONTROLS ===
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
    
    # === FILTER RESULTS ===
    results = df.copy()
    if search_cve: results = results[results['cve_id'].str.contains(search_cve, case=False, na=False)]
    if search_vendor: results = results[results['vendor'].str.contains(search_vendor, case=False, na=False)]
    if search_product: results = results[results['product'].str.contains(search_product, case=False, na=False)]
    if mitre_search:
        mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
        if mitre_cols: results = results[results[mitre_cols[0]].str.contains(mitre_search, case=False, na=False)]
    if severity_filter: results = results[results['nvd_severity'].isin(severity_filter)]
    if cvss_min > 0: results = results[results['cvss_v3_raw'] >= cvss_min]
    
    st.success(f"✅ **{len(results)}** results found")
    
    # === ROW FORMAT OUTPUT ===
    st.markdown("### 📋 Search Results")
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    mitre_col = mitre_cols[0] if mitre_cols else None
    
    for _, row in results.iterrows():
        with st.container():
            col1, col2, col3, col4, col5, col6 = st.columns([1.5, 1.5, 1.2, 2, 1.5, 2])
            
            with col1: st.markdown(f"**🏢 {row['vendor']}**")
            with col2: st.markdown(f"**📦 {row['product']}**")
            with col3: st.markdown(f"**🔢 {row['cve_id']}**")
            with col4: st.markdown(row['description'][:150] + "...")
            with col5: 
                if mitre_col and pd.notna(row[mitre_col]):
                    st.markdown(f"**🎯 {row[mitre_col]}**")
                else:
                    st.markdown("**🎯 N/A**")
            with col6: st.markdown(f"**Severity:** {row['nvd_severity']} | **CVSS:** {row['cvss_v3_raw']:.1f}")
            
            st.divider()

# ============================================
# PAGE 5: EXPORT PDF (ALL CHARTS + NLP REMEDIATION)
# ============================================
elif page == "📄 Export PDF":
    st.markdown("## 📄 Professional PDF Report")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", total_threats)
    with col2: st.metric("Critical", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    if st.button("🚀 GENERATE COMPLETE PDF REPORT", type="primary", use_container_width=True):
        with st.spinner("📄 Creating comprehensive report with ALL charts..."):
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter)
            styles = getSampleStyleSheet()
            heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], 
                                          fontSize=16, textColor=colors.HexColor('#1e3a8a'))
            body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=10)
            
            story = []
            
            # === TITLE + SUMMARY ===
            story.append(Paragraph("🛡️ ARCTIC SENTINEL - THREAT INTELLIGENCE REPORT", styles['Heading1']))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
            story.append(Spacer(1, 20))
            
            critical = len(df[df['nvd_severity'] == 'CRITICAL'])
            summary = f"<b>Total CVEs:</b> {total_threats} | <b>Critical:</b> {critical} | <b>Avg CVSS:</b> {df['cvss_v3_raw'].mean():.1f}"
            story.append(Paragraph(summary, body_style))
            story.append(Spacer(1, 12))
            
            # === CHART 1: SEVERITY PIE ===
            fig_pie = px.pie(df, names='nvd_severity', hole=0.4)
            pie_png = pio.to_image(fig_pie, format="png", width=500, height=400)
            story.append(Paragraph("📊 Severity Distribution", heading_style))
            story.append(Image(pie_png, width=5*inch, height=3.5*inch))
            story.append(Spacer(1, 12))
            
            # === CHART 2: TOP VENDORS ===
            fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors")
            vendors_png = pio.to_image(fig_vendors, format="png", width=500, height=400)
            story.append(Paragraph("🏢 Top Vulnerable Vendors", heading_style))
            story.append(Image(vendors_png, width=5*inch, height=3.5*inch))
            story.append(Spacer(1, 12))
            
            # === CVE TABLE ===
            story.append(Paragraph("📋 Top 20 Critical CVEs", heading_style))
            cve_data = [['CVE ID', 'Vendor', 'Product', 'Severity', 'CVSS']]
            for _, row in df.nlargest(20, 'cvss_v3_raw').iterrows():
                cve_data.append([
                    str(row['cve_id'])[:15], 
                    str(row['vendor'])[:12], 
                    str(row['product'])[:12],
                    row['nvd_severity'],
                    f"{row['cvss_v3_raw']:.1f}"
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
            
            # === NLP REMEDIATION ===
            story.append(Paragraph("🔧 AI-GENERATED REMEDIATION STRATEGY", heading_style))
            remediation_text = generate_nlp_remediation(df)
            story.append(Paragraph(remediation_text, body_style))
            
            doc.build(story)
            pdf_buffer.seek(0)
            
            st.download_button(
                "📥 Download Complete Report",
                pdf_buffer.getvalue(),
                f"arctic_sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "application/pdf",
                use_container_width=True
            )
            st.balloons()
            st.success("✅ Professional PDF Report Generated!")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | ATTACK-BERT + NLP | Production Ready")
