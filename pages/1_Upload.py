import streamlit as st

st.set_page_config(page_title="Upload File", layout="wide")

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

st.subheader("Choose File")
st.caption("Upload a .csv file containing asset data to begin analysis. You may use the sample file provided in the github repository. For individual testing, another interface will be available.")

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
