import streamlit as st

st.set_page_config(
    page_title="Arctic Sentinel",
    layout="wide",
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

st.markdown('<div class="hero"><div class="hero-inner">', unsafe_allow_html=True)

st.title("Arctic Sentinel")
st.caption("Threat intelligence. Simplified.")

if st.button("Get Started", type="primary"):
    st.switch_page("pages/1_Upload.py")

st.markdown('</div></div>', unsafe_allow_html=True)
