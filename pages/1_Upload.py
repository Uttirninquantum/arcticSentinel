import streamlit as st

st.set_page_config(page_title="Upload File", layout="wide")

st.markdown(
    """
    <style>
        
        .block-container {
            padding-left: 3rem;
            padding-right: 3rem;
            padding-top: 2rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)
st.markdown(
    """
    <style>
        .hero {
            display: flex;
            margin-top: 5rem;
            margin-bottom: 5rem;
            margin-left: auto;
            margin-right: auto;
            justify-content: center;
            align-items: center;
            text-align: center;
        }
        .hero-inner {
            max-width: 600px;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

st.subheader("Choose File")
st.caption("Upload your asset list, please note the format of the asset list as follows")
st.caption("part (a for application, o for operating system and h for hardware), vendor, product, version") 

uploaded = st.file_uploader(
    "", type=["csv"], label_visibility="collapsed"
)

col1, col2 = st.columns(2)
with col1:
    if uploaded:
        st.success("File selected")

with col2:
    if uploaded and st.button("Upload", type="primary"):
        st.session_state["file"] = uploaded
        st.switch_page("pages/2_Dashboard.py")

st.markdown("</div></div>", unsafe_allow_html=True)
