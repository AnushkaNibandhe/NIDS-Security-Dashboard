"""
Utility Functions for NIDS Application
Logging, alerts, data management
"""

import json
import os
from datetime import datetime
import streamlit as st
import pandas as pd

def log_audit_event(action, user, details, severity="INFO"):
    """
    Log audit event to session state
    
    Args:
        action: Action performed
        user: Username
        details: Additional details
        severity: Event severity
    """
    if 'audit_logs' not in st.session_state:
        st.session_state.audit_logs = []
    
    event = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'user': user,
        'action': action,
        'details': details,
        'severity': severity
    }
    
    st.session_state.audit_logs.append(event)
    
    # Keep only last 1000 entries
    if len(st.session_state.audit_logs) > 1000:
        st.session_state.audit_logs = st.session_state.audit_logs[-1000:]

def add_detection(detection):
    """Add new detection to session state"""
    if 'detections' not in st.session_state:
        st.session_state.detections = []
    
    st.session_state.detections.append(detection)
    
    # Log audit event
    log_audit_event(
        action="Detection Added",
        user=st.session_state.get('username', 'system'),
        details=f"{detection['attack_type']} - {detection['severity']}",
        severity=detection['severity']
    )

def block_ip(ip_address, reason, user):
    """Block an IP address"""
    if 'blocked_ips' not in st.session_state:
        st.session_state.blocked_ips = []
    
    block_entry = {
        'ip': ip_address,
        'reason': reason,
        'blocked_by': user,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    st.session_state.blocked_ips.append(block_entry)
    
    log_audit_event(
        action="IP Blocked",
        user=user,
        details=f"IP: {ip_address} - Reason: {reason}",
        severity="HIGH"
    )
    
    return True

def whitelist_ip(ip_address, reason, user):
    """Whitelist an IP address"""
    if 'whitelisted_ips' not in st.session_state:
        st.session_state.whitelisted_ips = []
    
    whitelist_entry = {
        'ip': ip_address,
        'reason': reason,
        'whitelisted_by': user,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    st.session_state.whitelisted_ips.append(whitelist_entry)
    
    log_audit_event(
        action="IP Whitelisted",
        user=user,
        details=f"IP: {ip_address} - Reason: {reason}",
        severity="INFO"
    )
    
    return True

def unblock_ip(ip_address, user):
    """Remove IP from blocklist"""
    if 'blocked_ips' in st.session_state:
        st.session_state.blocked_ips = [
            entry for entry in st.session_state.blocked_ips 
            if entry['ip'] != ip_address
        ]
        
        log_audit_event(
            action="IP Unblocked",
            user=user,
            details=f"IP: {ip_address}",
            severity="INFO"
        )
        return True
    return False

def export_audit_logs_csv():
    """Export audit logs to CSV format"""
    if 'audit_logs' in st.session_state and st.session_state.audit_logs:
        df = pd.DataFrame(st.session_state.audit_logs)
        return df.to_csv(index=False).encode('utf-8')
    return None

def export_detections_csv():
    """Export detections to CSV format"""
    if 'detections' in st.session_state and st.session_state.detections:
        df = pd.DataFrame(st.session_state.detections)
        return df.to_csv(index=False).encode('utf-8')
    return None

def get_severity_color(severity):
    """Get color code for severity level"""
    colors = {
        'High': '#ff4444',
        'Medium': '#ffaa00',
        'Low': '#44ff44',
        'Safe': '#00aa00'
    }
    return colors.get(severity, '#888888')

def get_severity_emoji(severity):
    """Get emoji for severity level"""
    emojis = {
        'High': '🔴',
        'Medium': '🟡',
        'Low': '🟢',
        'Safe': '✅'
    }
    return emojis.get(severity, '⚪')

def format_confidence(confidence):
    """Format confidence as percentage"""
    return f"{confidence:.1%}"

def send_alert_notification(attack_type, severity, confidence):
    """
    Send alert notification (placeholder for Twilio integration)
    
    Args:
        attack_type: Type of attack
        severity: Severity level
        confidence: Detection confidence
    """
    # This is a placeholder - actual Twilio implementation would go here
    log_audit_event(
        action="Alert Sent",
        user="system",
        details=f"Attack: {attack_type}, Severity: {severity}",
        severity=severity
    )
    return True

def get_attack_stats():
    """Get statistics about detected attacks"""
    if 'detections' not in st.session_state or not st.session_state.detections:
        return {
            'total': 0,
            'by_type': {},
            'by_severity': {},
            'recent': []
        }
    
    detections = st.session_state.detections
    
    # Count by type
    by_type = {}
    for det in detections:
        attack_type = det['attack_type']
        by_type[attack_type] = by_type.get(attack_type, 0) + 1
    
    # Count by severity
    by_severity = {}
    for det in detections:
        severity = det['severity']
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    # Get recent detections
    recent = detections[-10:][::-1]
    
    return {
        'total': len(detections),
        'by_type': by_type,
        'by_severity': by_severity,
        'recent': recent
    }

def create_ticket(title, description, priority, user):
    """Create incident ticket (simulated)"""
    ticket_id = f"INC-{len(st.session_state.audit_logs):05d}"
    
    log_audit_event(
        action="Ticket Created",
        user=user,
        details=f"{ticket_id}: {title} (Priority: {priority})",
        severity=priority
    )
    
    return ticket_id

def check_authentication():
    """Check if user is authenticated"""
    return st.session_state.get('authenticated', False)

def check_admin():
    """Check if user has admin role"""
    return st.session_state.get('user_role', '') == 'admin'