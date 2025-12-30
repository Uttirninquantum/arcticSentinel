import streamlit as st
import pandas as pd
import numpy as np
import io
import os
import warnings
from datetime import datetime

from models.threat_timeline import ThreatTimelinePipeline
from models.mitre_cross_mapper import MITRECrossMapper

from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

import plotly.express as px
import plotly.io as pio

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

warnings.filterwarnings("ignore")

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="Arctic Sentinel",
    layout="wide"
)

# =========================
# STATE INIT
# =========================
for key in ["assets_file", "threat_data", "cross_mapped_data"]:
    if key not in st.session_state:
        st.session_state[key] = pd.DataFrame() if "data" in key else None

# =========================
# LOAD ATTACK-BERT
# =========================
@st.cache_resource
def load_bert():
    return SentenceTransformer("basel/ATTACK-BERT")

bert_model = load_bert()

# =========================
# HELPERS
# =========================
def get_similar_cves(df, text, top_k=8):
    if df.empty or not text:
        return pd.DataFrame()

    emb_text = bert_model.encode([text])[0]
    emb_cves = bert_model.encode(df["description"].fillna("").tolist())

    sims = cosine_similarity([emb_text], emb_cves)[0]
    idx = np.argsort(sims)[::-1][:top_k]

    out = df.iloc[idx].copy()
    out["similarity_score"] = sims[idx]
    return out[out["similarity_score"] > 0.2]

def generate_remediation(df):
    total = len(df)
    crit = len(df[df["nvd_severity"] == "CRITICAL"])
    high = len(df[df["nvd_severity"] == "HIGH"])
    vendors = df["vendor"].value_counts().head(3).index.tolist()

    return f"""
    <b>IMMEDIATE (0–24h)</b><br/>
    • Patch {crit} CRITICAL vulnerabilities<br/>
    • Isolate systems from {", ".join(vendors[:2])}<br/><br/>

    <b>SHORT TERM (1–7d)</b><br/>
    • Patch {high} HIGH vulnerabilities<br/>
    • Update IDS/IPS signatures<br/><br/>

    <b>LONG TERM</b><br/>
    • Automated patching<br/>
    • Vendor risk review: {vendors[0]}
    """

# =========================
# HEADER + NAV
# =========================
st.markdown("# 🛡️ Arctic Sentinel")

page = st.radio(
    "Navigation",
    [
        "1️⃣ Upload Assets",
        "2️⃣ Scan CVEs",
        "3️⃣ MITRE Mapping",
        "4️⃣ Analysis & Search",
        "5️⃣ Export PDF"
    ],
    horizontal=True
)

st.divider()

# =========================
# PAGE 1 — UPLOAD
# =========================
if page == "1️⃣ Upload Assets":
    st.subheader("📤 Upload Asset Inventory")

    file = st.file_uploader("Upload CSV", type=["csv"])
    if file:
        st.session_state.assets_file = file
        st.success("✅ Asset file uploaded")

# =========================
# PAGE 2 — SCAN CVEs
# =========================
elif page == "2️⃣ Scan CVEs":
    st.subheader("🔍 CVE Threat Scan")

    if not st.session_state.assets_file:
        st.warning("Upload assets first")
        st.stop()

    if st.button("🚀 Run CVE Pipeline", type="primary"):
        with st.spinner("Running pipeline..."):
            df_assets = pd.read_csv(
                io.StringIO(st.session_state.assets_file.read().decode("utf-8"))
            )
            pipeline = ThreatTimelinePipeline()
            st.session_state.threat_data = pipeline.run_pipeline_csv(df_assets)
            st.success("✅ CVE scan completed")

# =========================
# PAGE 3 — MITRE
# =========================
elif page == "3️⃣ MITRE Mapping":
    st.subheader("🎯 MITRE ATT&CK Mapping")

    if st.session_state.threat_data.empty:
        st.warning("Run CVE scan first")
        st.stop()

    if st.button("🎯 Map MITRE ATT&CK", type="primary"):
        with st.spinner("Mapping tactics..."):
            mapper = MITRECrossMapper(st.session_state.threat_data)
            st.session_state.cross_mapped_data = mapper.run_mapping()
            st.success("✅ MITRE mapping completed")

# =========================
# PAGE 4 — ANALYSIS
# =========================
elif page == "4️⃣ Analysis & Search":
    df = (
        st.session_state.cross_mapped_data
        if not st.session_state.cross_mapped_data.empty
        else st.session_state.threat_data
    )

    if df.empty:
        st.warning("No data available")
        st.stop()

    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔍 Search", "🧠 ATTACK-BERT"])

    # --- OVERVIEW ---
    with tab1:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total CVEs", len(df))
        c2.metric("CRITICAL", len(df[df["nvd_severity"] == "CRITICAL"]))
        c3.metric("HIGH", len(df[df["nvd_severity"] == "HIGH"]))
        c4.metric("Avg CVSS", f"{df['cvss_v3_raw'].mean():.1f}")

        st.plotly_chart(
            px.pie(df, names="nvd_severity", hole=0.4),
            use_container_width=True
        )

    # --- SEARCH ---
    with tab2:
        search = st.text_input("Search CVE / Vendor / Product")
        if search:
            res = df[
                df.apply(
                    lambda r: search.lower() in str(r).lower(), axis=1
                )
            ]
            st.dataframe(res, use_container_width=True)

    # --- BERT ---
    with tab3:
        text = st.text_area("Describe vulnerability")
        if st.button("Find Similar CVEs"):
            sims = get_similar_cves(df, text)
            st.dataframe(sims, use_container_width=True)

# =========================
# PAGE 5 — EXPORT
# =========================
elif page == "5️⃣ Export PDF":
    st.subheader("📄 Export Threat Intelligence Report")

    df = (
        st.session_state.cross_mapped_data
        if not st.session_state.cross_mapped_data.empty
        else st.session_state.threat_data
    )

    if df.empty:
        st.warning("Nothing to export")
        st.stop()

    if st.button("📥 Generate PDF", type="primary"):
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter)
        styles = getSampleStyleSheet()

        story = [
            Paragraph("ARCTIC SENTINEL REPORT", styles["Heading1"]),
            Spacer(1, 12),
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                styles["Normal"]
            ),
            Spacer(1, 12),
            Paragraph(generate_remediation(df), styles["Normal"]),
        ]

        doc.build(story)
        buf.seek(0)

        st.download_button(
            "Download PDF",
            buf,
            f"arctic_sentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            "application/pdf"
        )

        st.success("✅ PDF generated successfully")
