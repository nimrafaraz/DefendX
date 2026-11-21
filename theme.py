"""Global styling (CSS) for the DEFEND-X look."""
import streamlit as st

CSS = """
<style>
.block-container {padding-top: 2rem; max-width: 1400px;}
.dx-card {background:#131c2e; border:1px solid #243049; border-radius:12px; padding:14px 18px; height:100%;}
.dx-card .dx-label {font-size:0.75rem; letter-spacing:.08em; text-transform:uppercase; color:#8fa3c4;}
.dx-card .dx-value {font-size:1.9rem; font-weight:700; line-height:1.2;}
.dx-card .dx-sub {font-size:0.8rem; color:#8fa3c4;}
.dx-ok {color:#19c3a6;} .dx-warn {color:#f5b83d;} .dx-bad {color:#ff5d5d;} .dx-neutral {color:#e6edf7;}
.dx-banner {background:#10243a; border-left:4px solid #19c3a6; padding:8px 14px; border-radius:6px;
            font-size:0.85rem; color:#b8c8e0; margin-bottom:1rem;}
.dx-badge {display:inline-block; padding:2px 10px; border-radius:999px; font-weight:700; font-size:0.8rem;}
.dx-LOW {background:#14391f; color:#5fe08a;} .dx-MEDIUM {background:#3d3410; color:#f5d24a;}
.dx-HIGH {background:#44230f; color:#ff9b4a;} .dx-CRITICAL {background:#4a1414; color:#ff6b6b;}
</style>
"""


def apply_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
