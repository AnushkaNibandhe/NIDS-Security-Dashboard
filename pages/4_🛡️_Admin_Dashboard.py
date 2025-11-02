"""
Admin Dashboard - SOC Metrics and System Health
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import get_attack_stats, check_authentication, check_admin

# Check authentication and admin role
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

if not check_admin():
    st.error("🚫 Admin access required")
    st.stop()

st.title("🛡️ Admin Dashboard - Security Operations Center")
st.markdown("### Real-Time Threat Intelligence & System Monitoring")

# System health metrics
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        label="🟢 System Health",
        value="99.9%",
        delta="Optimal"
    )

with col2:
    total_detections = len(st.session_state.get('detections', []))
    st.metric(
        label="📊 Total Alerts",
        value=total_detections,
        delta="+12 today"
    )

with col3:
    blocked_count = len(st.session_state.get('blocked_ips', []))
    st.metric(
        label="🚫 Blocked IPs",
        value=blocked_count,
        delta=None
    )

with col4:
    false_positive_rate = 2.3  # Simulated
    st.metric(
        label="📉 False Positive Rate",
        value=f"{false_positive_rate}%",
        delta="-0.5%"
    )

with col5:
    response_time = "1.2s"
    st.metric(
        label="⚡ Avg Response Time",
        value=response_time,
        delta="Fast"
    )

st.markdown("---")

# Get statistics
stats = get_attack_stats()

# Main charts section
col_main_left, col_main_right = st.columns([2, 1])

with col_main_left:
    st.subheader("🔥 Threat Heat Map (Last 24 Hours)")
    
    # Simulated heatmap data
    hours = [f"{i:02d}:00" for i in range(24)]
    categories = ['DoS', 'Probe', 'R2L', 'U2R', 'Normal']
    
    import numpy as np
    np.random.seed(42)
    z_data = np.random.randint(0, 50, size=(len(categories), len(hours)))
    
    fig_heatmap = go.Figure(data=go.Heatmap(
        z=z_data,
        x=hours,
        y=categories,
        colorscale='Reds',
        hoverongaps=False
    ))
    fig_heatmap.update_layout(
        height=300,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        xaxis_title="Time",
        yaxis_title="Attack Type"
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)

with col_main_right:
    st.subheader("⚠️ Active Incidents")
    
    active_incidents = [d for d in st.session_state.get('detections', []) 
                       if d['severity'] in ['High', 'Medium']][-5:]
    
    if active_incidents:
        for incident in active_incidents[::-1]:
            severity_emoji = {'High': '🔴', 'Medium': '🟡'}.get(incident['severity'], '⚪')
            with st.container():
                st.markdown(f"""
                <div style='padding: 10px; border-left: 3px solid {"#ff4444" if incident['severity']=="High" else "#ffaa00"}; margin-bottom: 10px; background-color: rgba(255,255,255,0.05); border-radius: 5px;'>
                    <strong>{severity_emoji} {incident['attack_type']}</strong><br/>
                    <small>Confidence: {incident['confidence']:.1%}</small><br/>
                    <small>{incident['timestamp']}</small>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("✅ No active high-priority incidents")

st.markdown("---")

# Attack distribution and trends
col_dist_left, col_dist_right = st.columns(2)

with col_dist_left:
    st.subheader("📊 Attack Distribution")
    
    if stats['by_type']:
        type_df = pd.DataFrame({
            'Attack Type': list(stats['by_type'].keys()),
            'Count': list(stats['by_type'].values())
        })
        
        fig_funnel = go.Figure(go.Funnel(
            y=type_df['Attack Type'],
            x=type_df['Count'],
            textinfo="value+percent initial",
            marker=dict(color=['#ff4444', '#ffaa00', '#44ff44', '#0088ff', '#aa44ff'])
        ))
        fig_funnel.update_layout(
            height=350,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig_funnel, use_container_width=True)
    else:
        st.info("No attack data available")

with col_dist_right:
    st.subheader("🎯 Severity Analysis")
    
    severity_counts = stats.get('by_severity', {})
    
    if severity_counts:
        labels = list(severity_counts.keys())
        values = list(severity_counts.values())
        colors = {
            'High': '#ff4444',
            'Medium': '#ffaa00',
            'Low': '#44ff44',
            'Safe': '#00aa00'
        }
        
        fig_gauge = go.Figure()
        
        for i, (label, value) in enumerate(zip(labels, values)):
            fig_gauge.add_trace(go.Bar(
                x=[value],
                y=[label],
                orientation='h',
                marker_color=colors.get(label, '#888888'),
                text=[value],
                textposition='auto',
                name=label
            ))
        
        fig_gauge.update_layout(
            height=350,
            showlegend=False,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis_title="Count",
            yaxis_title="Severity"
        )
        st.plotly_chart(fig_gauge, use_container_width=True)
    else:
        st.info("No severity data available")

st.markdown("---")

# System information panel
st.subheader("💻 System Information")

sys_col1, sys_col2, sys_col3 = st.columns(3)

with sys_col1:
    st.markdown("""
    **Model Status**
    - 🤖 Model: Random Forest
    - 📊 Accuracy: 99.7%
    - 🎯 Precision: 99.6%
    - ⚡ Last Update: 2024-11-01
    """)

with sys_col2:
    st.markdown("""
    **Network Status**
    - 📡 Packets Analyzed: 1.2M
    - ⏱️ Avg Latency: 12ms
    - 📈 Throughput: 950 Mbps
    - 🔄 Uptime: 99.9%
    """)

with sys_col3:
    st.markdown("""
    **Security Posture**
    - 🛡️ Active Rules: 847
    - 🚫 Blocked IPs: """ + str(len(st.session_state.get('blocked_ips', []))) + """
    - ✅ Whitelisted: """ + str(len(st.session_state.get('whitelisted_ips', []))) + """
    - 📋 Audit Logs: """ + str(len(st.session_state.get('audit_logs', []))) + """
    """)

# Quick actions
st.markdown("---")
st.subheader("⚡ Quick Actions")

action_col1, action_col2, action_col3, action_col4 = st.columns(4)

with action_col1:
    if st.button("🔍 View Threats", use_container_width=True):
        st.switch_page("pages/5_⚠️_Threat_Console.py")

with action_col2:
    if st.button("🔧 Take Action", use_container_width=True):
        st.switch_page("pages/6_🔧_Incident_Actions.py")

with action_col3:
    if st.button("📋 Audit Logs", use_container_width=True):
        st.switch_page("pages/7_📋_Audit_Logs.py")

with action_col4:
    if st.button("⚙️ Settings", use_container_width=True):
        st.switch_page("pages/8_⚙️_Settings.py")