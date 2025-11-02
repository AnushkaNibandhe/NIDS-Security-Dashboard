"""
AI-Powered Network Intrusion Detection System (NIDS)
Main Streamlit Application Entry Point
"""

import streamlit as st
import json
from datetime import datetime
import os

st.set_page_config(
    page_title="NIDS - Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for better visibility
st.markdown("""
<style>
    /* Force text colors */
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    
    /* Main content text */
    .main .block-container {
        color: #fafafa !important;
    }
    
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #fafafa !important;
    }
    
    /* Paragraphs and text */
    p, span, div {
        color: #fafafa !important;
    }
    
    /* Input fields */
    input {
        color: #fafafa !important;
        background-color: #262730 !important;
    }
    
    /* Buttons */
    .stButton > button {
        background-color: #FF4B4B;
        color: white;
        border: none;
        border-radius: 5px;
        padding: 10px 20px;
    }
    
    /* Metrics */
    .stMetric {
        background-color: #262730;
        padding: 15px;
        border-radius: 10px;
        color: #fafafa !important;
    }
    
    .stMetric label {
        color: #fafafa !important;
    }
    
    .stMetric .metric-value {
        color: #fafafa !important;
    }
    
    /* Sidebar */
    .css-1d391kg, [data-testid="stSidebar"] {
        background-color: #262730;
    }
    
    .css-1d391kg p, [data-testid="stSidebar"] p {
        color: #fafafa !important;
    }
    
    /* Tables */
    .dataframe {
        color: #fafafa !important;
    }
    
    /* Info/Warning/Error boxes */
    .stAlert {
        color: #000000 !important;
    }
</style>
""", unsafe_allow_html=True)


# Initialize session state
def init_session_state():
    """Initialize session state variables"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'detections' not in st.session_state:
        st.session_state.detections = []
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []
    if 'blocked_ips' not in st.session_state:
        st.session_state.blocked_ips = []
    if 'whitelisted_ips' not in st.session_state:
        st.session_state.whitelisted_ips = []

def login_page():
    """Display login page"""
    st.title("🛡️ NIDS - Security Operations Center")
    st.markdown("### Secure Login Portal")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("---")
        username = st.text_input("👤 Username", key="login_username")
        password = st.text_input("🔒 Password", type="password", key="login_password")
        
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("🔐 Login as User", use_container_width=True):
                if username == "user" and password == "user123":
                    st.session_state.authenticated = True
                    st.session_state.user_role = "user"
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials")
        
        with col_b:
            if st.button("👨‍💼 Login as Admin", use_container_width=True):
                if username == "admin" and password == "admin123":
                    st.session_state.authenticated = True
                    st.session_state.user_role = "admin"
                    st.session_state.username = username
                    st.rerun()
                else:
                    st.error("❌ Invalid credentials")
        
        st.markdown("---")
        st.info("""
        **Demo Credentials:**
        - User: `user` / `user123`
        - Admin: `admin` / `admin123`
        """)

def main_app():
    """Main application after authentication"""
    
    # Sidebar
    with st.sidebar:
        st.title("🛡️ NIDS SOC")
        st.markdown(f"**User:** {st.session_state.username}")
        st.markdown(f"**Role:** {st.session_state.user_role.upper()}")
        st.markdown("---")
        
        # Role-based navigation info
        if st.session_state.user_role == "admin":
            st.success("✅ Admin Portal Active")
            st.markdown("""
            **Admin Access:**
            - Full system control
            - Threat management
            - Incident response
            - Audit logs
            - System settings
            """)
        else:
            st.info("👤 User Portal Active")
            st.markdown("""
            **User Access:**
            - View dashboards
            - Monitor detections
            - Security assistant
            - Help & documentation
            """)
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.username = None
            st.rerun()
    
    # Main content
    st.title("🏠 Network Intrusion Detection System")
    st.markdown("### Real-Time Security Monitoring Dashboard")
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🔴 Active Threats",
            value=len([d for d in st.session_state.detections if d['severity'] in ['High', 'Medium']]),
            delta="Live"
        )
    
    with col2:
        st.metric(
            label="📊 Total Detections",
            value=len(st.session_state.detections),
            delta="+3 today"
        )
    
    with col3:
        st.metric(
            label="🚫 Blocked IPs",
            value=len(st.session_state.blocked_ips),
            delta=None
        )
    
    with col4:
        st.metric(
            label="✅ System Status",
            value="Operational",
            delta="All systems normal"
        )
    
    st.markdown("---")
    
    # Recent activity
    st.subheader("📌 Recent Activity")
    
    if st.session_state.detections:
        recent = st.session_state.detections[-5:][::-1]
        for det in recent:
            severity_color = {
                'High': '🔴',
                'Medium': '🟡',
                'Low': '🟢',
                'Safe': '✅'
            }
            st.markdown(f"{severity_color.get(det['severity'], '⚪')} **{det['attack_type']}** - "
                       f"Confidence: {det['confidence']:.1%} - {det['timestamp']}")
    else:
        st.info("No recent detections. System monitoring active.")
    
    st.markdown("---")
    
    # Navigation guide
    st.subheader("🧭 Navigation Guide")
    
    if st.session_state.user_role == "admin":
        st.markdown("""
        **Admin Portal Pages:**
        1. 🛡️ **Admin Dashboard** - SOC metrics and system health
        2. ⚠️ **Threat Console** - Real-time threat analysis
        3. 🔧 **Incident Actions** - Block IPs, create tickets
        4. 📋 **Audit Logs** - Complete system audit trail
        5. ⚙️ **Settings** - Model and system configuration
        """)
    else:
        st.markdown("""
        **User Portal Pages:**
        1. 👤 **User Dashboard** - Attack statistics and trends
        2. 🔍 **User Detections** - View detection history
        3. 🤖 **Security Assistant** - AI-powered security guidance
        """)
    
    # System information
    with st.expander("ℹ️ System Information"):
        st.markdown("""
        **NIDS Version:** 1.0.0  
        **ML Model:** Random Forest Classifier  
        **LLM Assistant:** Foundation-Sec-8B (HuggingFace)  
        **Dataset:** NSL-KDD  
        **Attack Categories:** DoS, Probe, R2L, U2R, Normal  
        
        **Last Model Update:** 2024-11-01  
        **System Uptime:** 99.9%
        """)

def main():
    """Main application entry point"""
    init_session_state()
    
    if not st.session_state.authenticated:
        login_page()
    else:
        main_app()

if __name__ == "__main__":
    main()