"""
Incident Actions - Block IPs, Create Tickets, Manage Threats
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import (check_authentication, check_admin, block_ip, whitelist_ip,
                         unblock_ip, create_ticket, log_audit_event)

# Check authentication
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

if not check_admin():
    st.error("🚫 Admin access required")
    st.stop()

st.title("🔧 Incident Actions")
st.markdown("### Threat Response & Management")

# Tabs for different actions
tab1, tab2, tab3, tab4 = st.tabs(["🚫 Block IP", "✅ Whitelist IP", "🎫 Create Ticket", "📋 Manage Lists"])

# TAB 1: Block IP
with tab1:
    st.subheader("🚫 Block Malicious IP Address")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("**Block Configuration**")
        
        ip_to_block = st.text_input(
            "IP Address to Block",
            placeholder="192.168.1.100",
            help="Enter the IP address you want to block"
        )
        
        block_reason = st.text_area(
            "Reason for Blocking",
            placeholder="Detected DoS attack with 95% confidence...",
            height=100,
            help="Provide detailed reason for audit trail"
        )
        
        block_duration = st.selectbox(
            "Block Duration",
            ["Permanent", "24 Hours", "7 Days", "30 Days", "Custom"]
        )
        
        if block_duration == "Custom":
            custom_hours = st.number_input("Custom Duration (hours)", 1, 8760, 24)
        
        notify_admin = st.checkbox("Send Notification", value=True)
        
        if st.button("🚫 Block IP Address", type="primary"):
            if ip_to_block and block_reason:
                # Validate IP format (basic)
                if '.' in ip_to_block:
                    success = block_ip(
                        ip_address=ip_to_block,
                        reason=block_reason,
                        user=st.session_state.get('username', 'admin')
                    )
                    
                    if success:
                        st.success(f"✅ Successfully blocked IP: {ip_to_block}")
                        
                        if notify_admin:
                            st.info("📧 Admin notification sent (simulated)")
                        
                        # Show confirmation
                        st.markdown(f"""
                        **Action Summary:**
                        - 🚫 IP Blocked: `{ip_to_block}`
                        - ⏰ Duration: {block_duration}
                        - 👤 Blocked By: {st.session_state.get('username')}
                        - 📅 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        """)
                    else:
                        st.error("❌ Failed to block IP")
                else:
                    st.error("❌ Invalid IP address format")
            else:
                st.warning("⚠️ Please fill in all required fields")
    
    with col2:
        st.markdown("**Quick Actions**")
        
        # Show recent detections for quick blocking
        if st.session_state.get('detections'):
            recent_high = [d for d in st.session_state.detections[-10:] 
                          if d['severity'] == 'High']
            
            if recent_high:
                st.markdown("**Recent High-Severity Threats:**")
                for idx, det in enumerate(recent_high[::-1][:5]):
                    with st.expander(f"🔴 {det['attack_type']} - {det['timestamp']}"):
                        st.markdown(f"""
                        - **Type**: {det['attack_type']}
                        - **Confidence**: {det['confidence']:.1%}
                        - **Time**: {det['timestamp']}
                        """)
                        # Simulated IP (in real system, would extract from packet data)
                        suggested_ip = f"192.168.{(idx+1)*10}.{(idx+1)*5}"
                        if st.button(f"Block {suggested_ip}", key=f"quick_block_{idx}"):
                            block_ip(suggested_ip, f"Auto-block: {det['attack_type']}", 
                                   st.session_state.get('username'))
                            st.success(f"Blocked {suggested_ip}")
            else:
                st.info("No recent high-severity threats")

# TAB 2: Whitelist IP
with tab2:
    st.subheader("✅ Whitelist Trusted IP Address")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        whitelist_ip_input = st.text_input(
            "IP Address to Whitelist",
            placeholder="10.0.0.50",
            help="Add trusted IP to whitelist"
        )
        
        whitelist_reason = st.text_area(
            "Reason for Whitelisting",
            placeholder="Trusted internal server, production database...",
            height=100
        )
        
        permanent_whitelist = st.checkbox("Permanent Whitelist", value=True)
        
        if st.button("✅ Add to Whitelist", type="primary"):
            if whitelist_ip_input and whitelist_reason:
                if '.' in whitelist_ip_input:
                    success = whitelist_ip(
                        ip_address=whitelist_ip_input,
                        reason=whitelist_reason,
                        user=st.session_state.get('username', 'admin')
                    )
                    
                    if success:
                        st.success(f"✅ IP {whitelist_ip_input} added to whitelist")
                        st.info("This IP will be excluded from future detections")
                    else:
                        st.error("❌ Failed to whitelist IP")
                else:
                    st.error("❌ Invalid IP address format")
            else:
                st.warning("⚠️ Please fill in all required fields")
    
    with col2:
        st.markdown("**Whitelist Guidelines**")
        st.info("""
        **When to Whitelist:**
        - Internal infrastructure
        - Known monitoring systems
        - Verified business partners
        - Testing environments
        
        **⚠️ Be cautious:**
        - Verify IP ownership
        - Regular reviews
        - Time-limited when possible
        """)

# TAB 3: Create Ticket
with tab3:
    st.subheader("🎫 Create Incident Ticket")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        ticket_title = st.text_input(
            "Incident Title",
            placeholder="DoS Attack from Multiple Sources",
            help="Brief description of the incident"
        )
        
        ticket_priority = st.selectbox(
            "Priority Level",
            ["Critical", "High", "Medium", "Low"]
        )
        
        ticket_category = st.selectbox(
            "Category",
            ["Network Attack", "Unauthorized Access", "Data Breach", "Policy Violation", "Other"]
        )
        
        ticket_description = st.text_area(
            "Detailed Description",
            placeholder="Describe the incident, affected systems, and initial observations...",
            height=150
        )
        
        affected_systems = st.text_input(
            "Affected Systems",
            placeholder="192.168.1.10, web-server-01, database-cluster"
        )
        
        assign_to = st.selectbox(
            "Assign To",
            ["Auto-assign", "Security Team", "Network Team", "Incident Response"]
        )
        
        if st.button("🎫 Create Ticket", type="primary"):
            if ticket_title and ticket_description:
                ticket_id = create_ticket(
                    title=ticket_title,
                    description=ticket_description,
                    priority=ticket_priority,
                    user=st.session_state.get('username', 'admin')
                )
                
                st.success(f"✅ Ticket created: {ticket_id}")
                
                # Show ticket summary
                st.markdown(f"""
                **Ticket Summary:**
                - 🎫 **ID**: {ticket_id}
                - 📋 **Title**: {ticket_title}
                - ⚡ **Priority**: {ticket_priority}
                - 🏷️ **Category**: {ticket_category}
                - 👤 **Created By**: {st.session_state.get('username')}
                - 📅 **Created**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                - 👥 **Assigned**: {assign_to}
                """)
                
                if ticket_priority in ["Critical", "High"]:
                    st.warning("⚠️ High-priority ticket - immediate attention required")
            else:
                st.warning("⚠️ Please fill in required fields")
    
    with col2:
        st.markdown("**Priority Guidelines**")
        st.markdown("""
        **🔴 Critical:**
        - Active data breach
        - System compromise
        - Service outage
        
        **🟠 High:**
        - Confirmed attacks
        - Security vulnerabilities
        - Policy violations
        
        **🟡 Medium:**
        - Suspicious activity
        - Failed access attempts
        - Performance issues
        
        **🟢 Low:**
        - Informational
        - False positives
        - Routine checks
        """)

# TAB 4: Manage Lists
with tab4:
    st.subheader("📋 Manage Blocked & Whitelisted IPs")
    
    col_blocked, col_whitelisted = st.columns(2)
    
    with col_blocked:
        st.markdown("### 🚫 Blocked IPs")
        
        if st.session_state.get('blocked_ips'):
            blocked_df = pd.DataFrame(st.session_state.blocked_ips)
            st.dataframe(blocked_df, use_container_width=True)
            
            # Unblock functionality
            ip_to_unblock = st.selectbox(
                "Select IP to Unblock",
                options=[ip['ip'] for ip in st.session_state.blocked_ips]
            )
            
            if st.button("🔓 Unblock Selected IP"):
                success = unblock_ip(ip_to_unblock, st.session_state.get('username'))
                if success:
                    st.success(f"✅ Unblocked IP: {ip_to_unblock}")
                    st.rerun()
                else:
                    st.error("❌ Failed to unblock IP")
        else:
            st.info("No blocked IPs")
    
    with col_whitelisted:
        st.markdown("### ✅ Whitelisted IPs")
        
        if st.session_state.get('whitelisted_ips'):
            whitelist_df = pd.DataFrame(st.session_state.whitelisted_ips)
            st.dataframe(whitelist_df, use_container_width=True)
            
            # Remove from whitelist
            ip_to_remove = st.selectbox(
                "Select IP to Remove",
                options=[ip['ip'] for ip in st.session_state.whitelisted_ips]
            )
            
            if st.button("❌ Remove from Whitelist"):
                st.session_state.whitelisted_ips = [
                    ip for ip in st.session_state.whitelisted_ips 
                    if ip['ip'] != ip_to_remove
                ]
                log_audit_event(
                    "IP Removed from Whitelist",
                    st.session_state.get('username'),
                    f"IP: {ip_to_remove}",
                    "INFO"
                )
                st.success(f"✅ Removed from whitelist: {ip_to_remove}")
                st.rerun()
        else:
            st.info("No whitelisted IPs")

# Footer
st.markdown("---")
st.caption("🛡️ All actions are logged in audit trail | Simulated firewall integration")