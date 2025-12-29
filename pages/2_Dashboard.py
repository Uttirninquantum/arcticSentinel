import streamlit as st

st.set_page_config(page_title="Dashboard", layout="wide")

st.markdown(
    """
    <style>
        [data-testid="stSidebar"] {
            display: none;
        }
        .block-container {
            padding-left: 3rem;
            padding-right: 3rem;
            padding-top: 2rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("## Arctic Sentinel Dashboard")

st.divider()

left, right = st.columns([1, 3])

with left:
    st.subheader("Controls")
    st.button("Scan CVEs")
    st.button("MITRE ATT&CK")
    st.button("Export Report")

with right:
    st.subheader("Analysis Output")
    st.info("Results will appear here after processing the uploaded file.")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("CVEs Found", "—")
    with col2:
        st.metric("Critical", "—")

    st.empty()
