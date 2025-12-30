import streamlit as st
import pandas as pd

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
    section[data-testid="stSidebar"] {
        display: none !important;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""",
    unsafe_allow_html=True,
)

st.subheader("Choose File")
st.caption(
    "Upload your asset list, please note the format of the asset list as follows"
)
st.caption(
    "part (a for application, o for operating system and h for hardware), vendor, product, version"
)

uploaded = st.file_uploader("", type=["csv"], label_visibility="collapsed")

if uploaded:
    col1, col2 = st.columns(2)

    with col1:
        st.success("File selected", width="stretch")

    with col2:
        st.empty()

    if st.button("Upload", type="primary", key="upload_btn", width="stretch"):
        st.session_state["file"] = uploaded
        st.switch_page("pages/2_Dashboard.py")


template_data = {
    "part": ["a", "a", "h", "o"],
    "vendor": ["nginx", "openssl", "intel", "ubuntu"],
    "product": ["nginx", "openssl", "cpu", "linux"],
    "version": ["1.25.3", "3.0.14", "i7-9700K", "20.04"],
}

df_template = pd.DataFrame(template_data)

st.markdown("## 📋 CSV Template")
st.dataframe(df_template, use_container_width=True)

st.markdown("</div></div>", unsafe_allow_html=True)
