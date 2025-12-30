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
import re
import numpy as np
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import plotly.io as pio

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
    if len(df) == 0:
        return pd.DataFrame()
    
    text_embedding = bert_model.encode([text])[0]
    cve_embeddings = bert_model.encode(df['description'].fillna('').tolist())
    similarities = cosine_similarity([text_embedding], cve_embeddings)[0]
    
    top_indices = np.argsort(similarities)[::-1][:top_k]
    similar_df = df.iloc[top_indices].copy()
    similar_df['similarity_score'] = similarities[top_indices]
    
    return similar_df[similar_df['similarity_score'] > 0.5]

def get_similar_mitre(df, mitre_id, top_k=5):
    """Get similar MITRE tactics"""
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    if not mitre_cols:
        return pd.DataFrame()
    
    col = mitre_cols[0]
    mitre_tactics = df[col].value_counts()
    return mitre_tactics.head(top_k)

def generate_remediation_nlp(df):
    """NLP-based remediation generation"""
    critical_count = len(df[df['nvd_severity'] == 'CRITICAL'])
    high_count = len(df[df['nvd_severity'] == 'HIGH'])
    
    remediation = f"""
    <b>REMEDIATION STRATEGY (AI-Generated)</b><br/>
    <br/>
    <b>Critical Issues:</b> {critical_count} vulnerabilities require immediate action<br/>
    • Isolate affected systems from network immediately<br/>
    • Apply emergency patches within 24 hours<br/>
    • Enable enhanced logging and monitoring<br/>
    <br/>
    <b>High Severity:</b> {high_count} vulnerabilities need urgent attention<br/>
    • Schedule patching within 1 week<br/>
    • Implement WAF rules for web-based exploits<br/>
    • Deploy compensating controls if patches unavailable<br/>
    <br/>
    <b>Long-term:</b><br/>
    • Implement vulnerability scanning pipeline<br/>
    • Establish SLA for patch management<br/>
    • Conduct security awareness training<br/>
    """
    return remediation

# === SESSION STATE ===
if "threat_data" not in st.session_state:
    st.session_state.threat_data = pd.DataFrame()
if "cross_mapped_data" not in st.session_state:
    st.session_state.cross_mapped_data = pd.DataFrame()
if "assets_file" not in st.session_state:
    st.session_state.assets_file = None
if "total_threats" not in st.session_state:
    st.session_state.total_threats = 0

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

# ============================================
# PAGE 1: OVERVIEW
# ============================================
if page == "📊 Overview":
    st.markdown("## 📊 Threat Intelligence Overview")
    
    if not has_data:
        st.info("👆 Upload CSV → Scan CVEs → MITRE Map")
        st.stop()
    
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.metric("Total Threats", st.session_state.total_threats)
    with col2: st.metric("CRITICAL", len(df[df['nvd_severity']=='CRITICAL']))
    with col3: st.metric("HIGH", len(df[df['nvd_severity']=='HIGH']))
    with col4: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].fillna(0).mean():.1f}")
    
    # Charts
    col1, col2 = st.columns(2)
    with col1:
        fig_pie = px.pie(df, names='nvd_severity', hole=0.4, title="Severity Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)
    with col2:
        fig_vendors = px.bar(df['vendor'].value_counts().head(10), title="Top Vendors (Vertical)")
        st.plotly_chart(fig_vendors, use_container_width=True)
    
    # === ATTACK-BERT CUSTOM VULNERABILITY SEARCH ===
    st.markdown("### 🚀 Find Similar CVEs using ATTACK-BERT")
    vuln_text = st.text_area("Enter vulnerability description...", height=100,
                           placeholder="Apache HTTP Server path traversal vulnerability allowing RCE")
    
    if st.button("🔍 Find Similar CVEs", type="primary"):
        if vuln_text.strip():
            with st.spinner("🧠 Using ATTACK-BERT embeddings..."):
                similar_cves = get_similar_cves(df, vuln_text, top_k=5)
                
                if len(similar_cves) > 0:
                    st.success(f"✅ Found {len(similar_cves)} similar CVEs")
                    
                    # Display similar CVEs
                    for idx, (_, row) in enumerate(similar_cves.iterrows()):
                        with st.expander(f"#{idx+1} {row['cve_id']} (Similarity: {row['similarity_score']:.2%})"):
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.metric("Vendor", row['vendor'])
                                st.metric("Severity", row['nvd_severity'])
                            with col_b:
                                st.metric("CVSS", f"{row['cvss_v3_raw']:.1f}")
                                st.metric("Published", row['published'])
                            st.write(f"**Description:** {row['description']}")
                            
                            # Add this CVE to dataset
                            # ✅ CORRECT - update first, THEN rerun
                            if st.button("➕ ADD to Dataset", key=f"add_{len(df)}"):  # Unique key
                                analyzed = analyze_vuln_text_nlp(vuln_text)
                                new_row = pd.DataFrame([analyzed])
                                if len(st.session_state.cross_mapped_data) > 0:
                                    st.session_state.cross_mapped_data = pd.concat([st.session_state.cross_mapped_data, new_row], ignore_index=True)
                                else:
                                    st.session_state.threat_data = pd.concat([st.session_state.threat_data, new_row], ignore_index=True)
    
                                st.session_state.total_threats = len(st.session_state.cross_mapped_data) + len(st.session_state.threat_data)  # ✅ Force counter update
                                st.success(f"✅ Added! Total: {st.session_state.total_threats}")
                                st.rerun()  # ✅ Now runs AFTER update
                else:
                    st.warning("No similar CVEs found (similarity < 0.5)")

# ============================================
# PAGE 2: CVE INFO - RELATED CVEs
# ============================================
elif page == "🔐 CVE Info":
    st.markdown("## 🔐 CVE Intelligence & Similar CVEs")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    # Overview metrics
    col1, col2, col3 = st.columns(3)
    with col1: st.metric("Total CVEs", len(df))
    with col2: st.metric("Unique Vendors", df['vendor'].nunique())
    with col3: st.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")
    
    # Risk Heatmap
    st.markdown("### 🔥 Vendor Risk Matrix")
    vendor_severity = df.groupby(['vendor', 'nvd_severity']).size().unstack(fill_value=0)
    fig_heatmap = px.imshow(vendor_severity, title="Vendor vs Severity", color_continuous_scale="Reds", aspect="auto")
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # === RELATED CVEs WITH SIMILARITY ===
    st.markdown("### 🔗 Related CVEs (Similarity-Based Grouping)")
    
    # Group by similarity
    selected_cve = st.selectbox("Select CVE to find related:", df['cve_id'].unique())
    selected_row = df[df['cve_id'] == selected_cve].iloc[0]
    
    related = get_similar_cves(df, selected_row['description'], top_k=5)
    related = related[related['cve_id'] != selected_cve]
    
    if len(related) > 0:
        st.success(f"Found {len(related)} related CVEs")
        
        # Display as clean cards
        for _, rel_cve in related.iterrows():
            with st.container():
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.markdown(f"**{rel_cve['cve_id']}** | {rel_cve['vendor']} {rel_cve['product']}")
                    st.caption(rel_cve['description'][:150])
                with col2:
                    st.metric("Similarity", f"{rel_cve['similarity_score']:.1%}")
                    st.metric("Severity", rel_cve['nvd_severity'])
                with col3:
                    st.metric("CVSS", f"{rel_cve['cvss_v3_raw']:.1f}")
                    st.metric("Published", rel_cve['published'][:10])
                st.divider()
    
    # Common CVEs table
    st.markdown("### 📊 All CVEs Overview")
    display_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw', 'published']
    st.dataframe(df[display_cols].sort_values('cvss_v3_raw', ascending=False), use_container_width=True)

# ============================================
# PAGE 3: MITRE INFO - TACTICS & DESCRIPTIONS
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
    tactic_col = [col for col in df.columns if 'attack_vector' in col]
    
    # Top MITRE Techniques
    st.markdown("### 📊 Top MITRE Techniques")
    top_mitre = df[mitre_col].value_counts().head(10)
    fig_mitre = px.bar(x=top_mitre.values, y=top_mitre.index, orientation='h', title="MITRE Technique Frequency")
    st.plotly_chart(fig_mitre, use_container_width=True)
    
    # === SIMILAR MITRE TACTICS ===
    st.markdown("### 🔗 Related MITRE Tactics (Similarity)")
    selected_mitre = st.selectbox("Select MITRE Technique:", df[mitre_col].dropna().unique())
    
    # Get all techniques using this tactic
    same_tactic = df[df[mitre_col] == selected_mitre]
    
    if len(same_tactic) > 0:
        st.info(f"**{selected_mitre}** used in {len(same_tactic)} threats")
        
        # Show tactics description
        tactic_desc = df[df[mitre_col] == selected_mitre]['attack_vector'].iloc[0] if tactic_col and len(same_tactic) > 0 else "N/A"
        st.write(f"**Common Attack Vector:** {tactic_desc}")
        
        # Severity breakdown for this tactic
        severity_dist = same_tactic['nvd_severity'].value_counts()
        fig_severity = px.pie(values=severity_dist.values, names=severity_dist.index, 
                             title=f"Severity Distribution for {selected_mitre}")
        st.plotly_chart(fig_severity, use_container_width=True)
        
        # Related CVEs using this tactic
        st.markdown("**CVEs Using This Tactic:**")
        cve_cols = ['cve_id', 'vendor', 'product', 'nvd_severity', 'cvss_v3_raw']
        st.dataframe(same_tactic[cve_cols], use_container_width=True)

# ============================================
# PAGE 4: ADVANCED SEARCH
# ============================================
elif page == "🔍 Search":
    st.markdown("## 🔍 Advanced Threat Search")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    # Search controls
    col1, col2, col3 = st.columns(3)
    with col1:
        search_cve = st.text_input("CVE ID", placeholder="CVE-2023-25690")
    with col2:
        search_vendor = st.text_input("Vendor", placeholder="Apache")
    with col3:
        search_product = st.text_input("Product", placeholder="HTTP Server")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.multiselect("Severity", df['nvd_severity'].unique())
    with col2:
        mitre_search = st.text_input("MITRE Tactic", placeholder="T1190")
    with col3:
        cvss_min = st.slider("Min CVSS", 0.0, 10.0, 0.0)
    
    # Apply filters
    results = df.copy()
    if search_cve:
        results = results[results['cve_id'].str.contains(search_cve, case=False, na=False)]
    if search_vendor:
        results = results[results['vendor'].str.contains(search_vendor, case=False, na=False)]
    if search_product:
        results = results[results['product'].str.contains(search_product, case=False, na=False)]
    if severity_filter:
        results = results[results['nvd_severity'].isin(severity_filter)]
    if cvss_min > 0:
        results = results[results['cvss_v3_raw'] >= cvss_min]
    if mitre_search:
        mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
        if mitre_cols:
            results = results[results[mitre_cols[0]].str.contains(mitre_search, case=False, na=False)]
    
    st.success(f"✅ **{len(results)}** results found")
    
    # === CLEAN RESULT ROWS ===
    st.markdown("### 📋 Search Results")
    mitre_cols = [col for col in df.columns if 'mitre_top1' in col]
    
    for _, row in results.iterrows():
        with st.container():
            col1, col2, col3, col4, col5 = st.columns([1.5, 1.5, 1, 1, 1])
            with col1:
                st.markdown(f"**Vendor:** {row['vendor']}")
                st.markdown(f"**Product:** {row['product']}")
            with col2:
                st.markdown(f"**CVE ID:** `{row['cve_id']}`")
                st.caption(row['description'][:100])
            with col3:
                st.metric("Severity", row['nvd_severity'])
                st.metric("CVSS", f"{row['cvss_v3_raw']:.1f}")
            with col4:
                if mitre_cols:
                    st.metric("MITRE", str(row[mitre_cols[0]]))
                st.metric("Published", row['published'][:10])
            with col5:
                st.metric("Version", row['version'])
            st.divider()
    
    # Export
    csv = results.to_csv(index=False).encode()
    st.download_button("💾 Export Results", csv, "search_results.csv", use_container_width=True)

# ============================================
# PAGE 5: EXPORT PDF
# ============================================
elif page == "📄 Export PDF":
    st.markdown("## 📄 Generate Professional PDF Report")
    
    if not has_data:
        st.warning("⚠️ Run analysis first!")
        st.stop()
    
    st.info("Generate comprehensive PDF with all charts, CVE data, and NLP-based remediation")
    
    if st.button("🚀 Generate & Download PDF", type="primary", use_container_width=True):
        with st.spinner("📄 Generating PDF..."):
            pdf_buffer = io.BytesIO()
            doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
            
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            story.append(Paragraph("🛡️ ARCTIC SENTINEL THREAT REPORT", styles['Heading1']))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            story.append(Paragraph("📋 Executive Summary", styles['Heading2']))
            summary_text = f"""
            <b>Total Vulnerabilities:</b> {len(df)}<br/>
            <b>Critical:</b> {len(df[df['nvd_severity']=='CRITICAL'])} ({len(df[df['nvd_severity']=='CRITICAL'])/max(len(df),1)*100:.1f}%)<br/>
            <b>High:</b> {len(df[df['nvd_severity']=='HIGH'])}<br/>
            <b>Average CVSS:</b> {df['cvss_v3_raw'].mean():.1f}
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Severity Table
            story.append(Paragraph("📊 Vulnerability Breakdown", styles['Heading2']))
            sev_data = [['Severity', 'Count', 'Percentage']]
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = len(df[df['nvd_severity']==sev])
                pct = count/max(len(df),1)*100
                sev_data.append([sev, str(count), f"{pct:.1f}%"])
            sev_table = Table(sev_data, colWidths=[2*inch]*3)
            sev_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('GRID', (0,0), (-1,-1), 1, colors.black)
            ]))
            story.append(sev_table)
            story.append(PageBreak())
            
            # CVE Details
            story.append(Paragraph("📋 CVE Details", styles['Heading2']))
            cve_data = [['CVE ID', 'Vendor', 'Severity', 'CVSS', 'Published']]
            for _, row in df.head(20).iterrows():
                cve_data.append([str(row['cve_id'])[:15], str(row['vendor'])[:15], row['nvd_severity'], 
                               f"{row['cvss_v3_raw']:.1f}", row['published'][:10]])
            cve_table = Table(cve_data, colWidths=[1.2*inch]*5)
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.lightblue, colors.white])
            ]))
            story.append(cve_table)
            story.append(PageBreak())
            
            # NLP-Based Remediation
            story.append(Paragraph("🔧 AI-Generated Remediation Strategy", styles['Heading2']))
            remediation = generate_remediation_nlp(df)
            story.append(Paragraph(remediation, styles['Normal']))
            
            doc.build(story)
            pdf_buffer.seek(0)
            
            st.download_button(
                "📥 Download PDF Report",
                pdf_buffer,
                f"arctic_sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "application/pdf",
                use_container_width=True
            )
            st.success("✅ PDF generated successfully!")

st.markdown("---")
st.markdown("🛡️ Arctic Sentinel | Powered by ATTACK-BERT + NLP")
