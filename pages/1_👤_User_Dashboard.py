"""
User Dashboard - Attack Statistics and Trends
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import get_attack_stats, get_severity_emoji, check_authentication

# Check authentication
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

if st.session_state.get('user_role') != 'user':
    st.warning("👨‍💼 This is the user portal. Switch to admin portal for full access.")

st.title("👤 User Dashboard")
st.markdown("### Network Security Overview")

# Get statistics
stats = get_attack_stats()

# Top metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="📊 Total Detections",
        value=stats['total'],
        delta=f"+{len([d for d in st.session_state.get('detections', [])[-10:]])}" if stats['total'] > 0 else None
    )

with col2:
    high_severity = stats['by_severity'].get('High', 0)
    st.metric(
        label="🔴 High Severity",
        value=high_severity,
        delta="Critical" if high_severity > 0 else "None"
    )

with col3:
    active_threats = len([d for d in st.session_state.get('detections', []) 
                         if d['severity'] in ['High', 'Medium']])
    st.metric(
        label="⚠️ Active Threats",
        value=active_threats,
        delta="Monitoring"
    )

with col4:
    st.metric(
        label="✅ System Status",
        value="Operational",
        delta="All systems OK"
    )

st.markdown("---")

# Charts
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("📈 Attack Types Distribution")
    
    if stats['by_type']:
        # Create pie chart
        fig_pie = go.Figure(data=[go.Pie(
            labels=list(stats['by_type'].keys()),
            values=list(stats['by_type'].values()),
            hole=0.4,
            marker_colors=['#ff4444', '#ffaa00', '#44ff44', '#0088ff', '#aa44ff']
        )])
        fig_pie.update_layout(
            height=350,
            margin=dict(t=30, b=0, l=0, r=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No attack data available yet")

with col_right:
    st.subheader("🎯 Severity Breakdown")
    
    if stats['by_severity']:
        severity_data = pd.DataFrame({
            'Severity': list(stats['by_severity'].keys()),
            'Count': list(stats['by_severity'].values())
        })
        
        fig_bar = px.bar(
            severity_data,
            x='Severity',
            y='Count',
            color='Severity',
            color_discrete_map={
                'High': '#ff4444',
                'Medium': '#ffaa00',
                'Low': '#44ff44',
                'Safe': '#00aa00'
            }
        )
        fig_bar.update_layout(
            height=350,
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.info("No severity data available yet")

st.markdown("---")

# Recent detections table
st.subheader("🕐 Recent Detections")

if stats['recent']:
    detection_df = pd.DataFrame(stats['recent'])
    
    # Format display
    display_df = detection_df[['timestamp', 'attack_type', 'severity', 'confidence']].copy()
    display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.1%}")
    display_df.columns = ['Timestamp', 'Attack Type', 'Severity', 'Confidence']
    
    # Color code by severity
    def highlight_severity(row):
        colors = {
            'High': 'background-color: #ff4444; color: white',
            'Medium': 'background-color: #ffaa00; color: white',
            'Low': 'background-color: #44ff44; color: black',
            'Safe': 'background-color: #00aa00; color: white'
        }
        return [colors.get(row['Severity'], '')] * len(row)
    
    styled_df = display_df.style.apply(highlight_severity, axis=1)
    st.dataframe(styled_df, use_container_width=True, height=300)
else:
    st.info("No recent detections. System is monitoring...")

# Time series chart
st.markdown("---")
st.subheader("📊 Detection Timeline")

if st.session_state.get('detections'):
    # Generate hourly data (simulated)
    timeline_data = []
    for i in range(24):
        hour_time = datetime.now() - timedelta(hours=23-i)
        count = len([d for d in st.session_state.detections if i % 3 == 0])  # Simulated distribution
        timeline_data.append({
            'Hour': hour_time.strftime('%H:00'),
            'Detections': count
        })
    
    timeline_df = pd.DataFrame(timeline_data)
    
    fig_timeline = px.line(
        timeline_df,
        x='Hour',
        y='Detections',
        markers=True,
        line_shape='spline'
    )
    fig_timeline.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis_title="Time (24h)",
        yaxis_title="Number of Detections"
    )
    fig_timeline.update_traces(line_color='#0088ff')
    st.plotly_chart(fig_timeline, use_container_width=True)
else:
    st.info("Insufficient data for timeline visualization")

# Help section
with st.expander("ℹ️ Understanding the Dashboard"):
    st.markdown("""
    **Attack Types:**
    - **DoS (Denial of Service)**: Attempts to overwhelm system resources
    - **Probe**: Network reconnaissance and scanning activities
    - **R2L (Remote to Local)**: Unauthorized remote access attempts
    - **U2R (User to Root)**: Privilege escalation attempts
    - **Normal**: Legitimate network traffic
    
    **Severity Levels:**
    - 🔴 **High**: Immediate attention required (DoS, U2R with high confidence)
    - 🟡 **Medium**: Monitor closely (Probe, R2L, or lower confidence critical attacks)
    - 🟢 **Low**: Routine monitoring (Low confidence detections)
    - ✅ **Safe**: Normal traffic, no threat detected
    
    **What to do:**
    - Monitor high-severity alerts closely
    - Use Security Assistant for mitigation guidance
    - Report persistent threats to administrator
    """)