"""
Audit Logs - Complete System Activity Trail
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import check_authentication, check_admin, export_audit_logs_csv

# Check authentication
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

if not check_admin():
    st.error("🚫 Admin access required")
    st.stop()

st.title("📋 Audit Logs")
st.markdown("### Complete System Activity Trail")

# Summary metrics
if st.session_state.get('audit_logs'):
    logs = st.session_state.audit_logs
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📊 Total Events", len(logs))
    
    with col2:
        high_severity = len([log for log in logs if log['severity'] in ['High', 'HIGH', 'Critical']])
        st.metric("🔴 High Severity", high_severity)
    
    with col3:
        unique_users = len(set(log['user'] for log in logs))
        st.metric("👥 Unique Users", unique_users)
    
    with col4:
        recent_24h = len([log for log in logs 
                         if (datetime.now() - datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')).days == 0])
        st.metric("⏰ Last 24h", recent_24h)
    
    st.markdown("---")
    
    # Filters
    st.subheader("🔍 Filter Logs")
    
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    
    with col_f1:
        # Get unique users
        users = sorted(set(log['user'] for log in logs))
        user_filter = st.multiselect("User", options=users, default=users)
    
    with col_f2:
        # Get unique actions
        actions = sorted(set(log['action'] for log in logs))
        action_filter = st.multiselect("Action", options=actions)
    
    with col_f3:
        severity_filter = st.multiselect(
            "Severity",
            options=['HIGH', 'Medium', 'INFO', 'Low'],
            default=['HIGH', 'Medium']
        )
    
    with col_f4:
        date_range = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
        )
    
    # Apply filters
    filtered_logs = logs.copy()
    
    # User filter
    if user_filter:
        filtered_logs = [log for log in filtered_logs if log['user'] in user_filter]
    
    # Action filter
    if action_filter:
        filtered_logs = [log for log in filtered_logs if log['action'] in action_filter]
    
    # Severity filter
    if severity_filter:
        filtered_logs = [log for log in filtered_logs if log['severity'] in severity_filter]
    
    # Date filter
    if date_range != "All Time":
        now = datetime.now()
        if date_range == "Last Hour":
            cutoff = now - timedelta(hours=1)
        elif date_range == "Last 24 Hours":
            cutoff = now - timedelta(days=1)
        elif date_range == "Last 7 Days":
            cutoff = now - timedelta(days=7)
        else:  # Last 30 Days
            cutoff = now - timedelta(days=30)
        
        filtered_logs = [log for log in filtered_logs 
                        if datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S') >= cutoff]
    
    st.markdown(f"**Showing {len(filtered_logs)} of {len(logs)} events**")
    
    # Export button
    col_export1, col_export2 = st.columns([4, 1])
    
    with col_export2:
        if st.button("📥 Export CSV", use_container_width=True):
            csv_data = export_audit_logs_csv()
            if csv_data:
                st.download_button(
                    label="⬇️ Download",
                    data=csv_data,
                    file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
    
    st.markdown("---")
    
    # Display logs table
    st.subheader("📜 Event Log")
    
    if filtered_logs:
        # Create DataFrame
        df = pd.DataFrame(filtered_logs)
        
        # Add severity emoji
        severity_emoji_map = {
            'HIGH': '🔴',
            'High': '🔴',
            'Medium': '🟡',
            'INFO': '🔵',
            'Info': '🔵',
            'Low': '🟢'
        }
        df['🚨'] = df['severity'].map(severity_emoji_map)
        
        # Reorder columns
        display_df = df[['🚨', 'timestamp', 'user', 'action', 'severity', 'details']]
        display_df.columns = ['', 'Timestamp', 'User', 'Action', 'Severity', 'Details']
        
        # Display with color coding
        def highlight_severity(row):
            if row['Severity'] in ['HIGH', 'High']:
                return ['background-color: rgba(255, 68, 68, 0.2)'] * len(row)
            elif row['Severity'] in ['Medium']:
                return ['background-color: rgba(255, 170, 0, 0.2)'] * len(row)
            else:
                return [''] * len(row)
        
        styled_df = display_df.style.apply(highlight_severity, axis=1)
        st.dataframe(styled_df, use_container_width=True, height=500)
        
        # Detailed view
        st.markdown("---")
        st.subheader("🔍 Event Details")
        
        event_idx = st.selectbox(
            "Select event for details",
            range(len(filtered_logs)),
            format_func=lambda x: f"{filtered_logs[x]['timestamp']} - {filtered_logs[x]['action']}"
        )
        
        if event_idx is not None:
            event = filtered_logs[event_idx]
            
            col_detail1, col_detail2 = st.columns(2)
            
            with col_detail1:
                st.markdown(f"""
                **Event Information:**
                - **Timestamp**: {event['timestamp']}
                - **User**: {event['user']}
                - **Action**: {event['action']}
                - **Severity**: {severity_emoji_map.get(event['severity'], '⚪')} {event['severity']}
                """)
            
            with col_detail2:
                st.markdown(f"""
                **Details:**
                ```
                {event['details']}
                ```
                """)
                
                # Show context (previous and next events by same user)
                user_events = [log for log in logs if log['user'] == event['user']]
                st.markdown(f"**Other actions by {event['user']}**: {len(user_events)} total")
    else:
        st.info("No events match the selected filters")

else:
    st.info("📭 No audit logs available yet")
    st.markdown("""
    Audit logs will be automatically generated when:
    - Users log in/out
    - Detections are added
    - IPs are blocked/whitelisted
    - Tickets are created
    - System actions are performed
    """)

# Statistics section
st.markdown("---")
st.subheader("📊 Audit Statistics")

if st.session_state.get('audit_logs'):
    col_stat1, col_stat2 = st.columns(2)
    
    with col_stat1:
        st.markdown("**Action Distribution**")
        action_counts = {}
        for log in logs:
            action = log['action']
            action_counts[action] = action_counts.get(action, 0) + 1
        
        action_df = pd.DataFrame({
            'Action': list(action_counts.keys()),
            'Count': list(action_counts.values())
        }).sort_values('Count', ascending=False)
        
        st.dataframe(action_df, use_container_width=True)
    
    with col_stat2:
        st.markdown("**User Activity**")
        user_counts = {}
        for log in logs:
            user = log['user']
            user_counts[user] = user_counts.get(user, 0) + 1
        
        user_df = pd.DataFrame({
            'User': list(user_counts.keys()),
            'Actions': list(user_counts.values())
        }).sort_values('Actions', ascending=False)
        
        st.dataframe(user_df, use_container_width=True)

# Info panel
with st.expander("ℹ️ About Audit Logs"):
    st.markdown("""
    **Audit Trail Purpose:**
    - Complete system activity tracking
    - Compliance and forensic analysis
    - Security incident investigation
    - User action accountability
    
    **What Gets Logged:**
    - ✅ User authentication events
    - ✅ Detection additions and modifications
    - ✅ IP blocking/whitelisting actions
    - ✅ Ticket creation and updates
    - ✅ Configuration changes
    - ✅ System errors and warnings
    
    **Retention Policy:**
    - Last 1000 events kept in memory
    - Export to CSV for long-term storage
    - Consider external logging system for production
    
    **Best Practices:**
    - Regular log reviews
    - Export logs periodically
    - Monitor high-severity events
    - Investigate unusual patterns
    """)

# Footer
st.markdown("---")
st.caption("🛡️ All system activities are logged | Export regularly for compliance")