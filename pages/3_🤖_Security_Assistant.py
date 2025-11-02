"""
Security Assistant - AI-Powered Security Guidance
"""

import streamlit as st
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.llm import SecurityAssistant
from shared.utils import check_authentication, log_audit_event

# Check authentication
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

st.title("🤖 Security Assistant")
st.markdown("### AI-Powered Cybersecurity Guidance")

# Initialize LLM assistant
if 'llm_assistant' not in st.session_state:
    st.session_state.llm_assistant = SecurityAssistant()

if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Quick action buttons
st.markdown("### 🎯 Quick Actions")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("🔴 DoS Attack Guidance", use_container_width=True):
        guidance = st.session_state.llm_assistant.get_mitigation_steps('DoS', 0.95)
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': f"**DoS Attack Mitigation Steps:**\n\n{guidance}"
        })

with col2:
    if st.button("🔍 Probe Attack Guidance", use_container_width=True):
        guidance = st.session_state.llm_assistant.get_mitigation_steps('Probe', 0.92)
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': f"**Probe Attack Mitigation Steps:**\n\n{guidance}"
        })

with col3:
    if st.button("🚪 R2L Attack Guidance", use_container_width=True):
        guidance = st.session_state.llm_assistant.get_mitigation_steps('R2L', 0.88)
        st.session_state.chat_history.append({
            'role': 'assistant',
            'content': f"**R2L Attack Mitigation Steps:**\n\n{guidance}"
        })

st.markdown("---")

# Chat interface
st.markdown("### 💬 Ask Security Questions")

# Display chat history
chat_container = st.container()

with chat_container:
    for message in st.session_state.chat_history:
        if message['role'] == 'user':
            st.markdown(f"""
            <div style='background-color: rgba(0, 123, 255, 0.1); padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 3px solid #007bff;'>
                <strong>👤 You:</strong><br/>{message['content']}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style='background-color: rgba(0, 255, 127, 0.1); padding: 15px; border-radius: 10px; margin: 10px 0; border-left: 3px solid #00ff7f;'>
                <strong>🤖 Security Assistant:</strong><br/>{message['content']}
            </div>
            """, unsafe_allow_html=True)

# Chat input
user_input = st.text_area(
    "Type your security question here...",
    height=100,
    placeholder="Example: How do I prevent SQL injection attacks? What are best practices for network segmentation?"
)

col_send, col_clear = st.columns([4, 1])

with col_send:
    if st.button("📤 Send Message", type="primary", use_container_width=True):
        if user_input.strip():
            # Add user message
            st.session_state.chat_history.append({
                'role': 'user',
                'content': user_input
            })
            
            # Get AI response
            with st.spinner("🤖 Thinking..."):
                try:
                    response = st.session_state.llm_assistant.chat_response(user_input)
                    st.session_state.chat_history.append({
                        'role': 'assistant',
                        'content': response
                    })
                    
                    # Log interaction
                    log_audit_event(
                        action="Security Assistant Query",
                        user=st.session_state.get('username', 'user'),
                        details=f"Question: {user_input[:100]}...",
                        severity="INFO"
                    )
                    
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Error: {e}")
                    st.info("💡 Tip: Ensure HF_TOKEN is configured in .env file")
        else:
            st.warning("⚠️ Please enter a question")

with col_clear:
    if st.button("🗑️ Clear", use_container_width=True):
        st.session_state.chat_history = []
        st.rerun()

# Information panel
st.markdown("---")

with st.expander("ℹ️ About Security Assistant"):
    st.markdown("""
    **🤖 AI-Powered Guidance**
    
    This security assistant uses Foundation-Sec-8B, a specialized large language model
    trained for cybersecurity applications, to provide:
    
    - **Threat Mitigation**: Step-by-step defensive measures for detected attacks
    - **Best Practices**: Security guidance and recommendations
    - **Incident Response**: What to do when attacks are detected
    - **Prevention Strategies**: Proactive security measures
    
    **📝 How to Use:**
    1. Use quick action buttons for common attack types
    2. Ask specific security questions in the chat
    3. Get detailed, actionable recommendations
    
    **🔒 Privacy Note:**
    - Queries are processed via HuggingFace API
    - No sensitive production data should be shared
    - For demo/training purposes only
    
    **⚙️ Model Information:**
    - Model: fdtn-ai/Foundation-Sec-8B
    - Provider: HuggingFace Inference API
    - Specialization: Network security and intrusion detection
    """)

# Sample questions
with st.expander("💡 Sample Questions"):
    st.markdown("""
    **Try asking:**
    
    - "What are the most effective ways to prevent DoS attacks?"
    - "How do I configure firewall rules for maximum security?"
    - "What should I do immediately after detecting a privilege escalation attempt?"
    - "Explain the difference between IDS and IPS"
    - "What are indicators of a port scanning attack?"
    - "How do I implement network segmentation?"
    - "What security measures prevent SQL injection?"
    - "Explain zero-trust architecture principles"
    """)

# Footer
st.markdown("---")
st.caption("🛡️ Powered by Foundation-Sec-8B LLM | HuggingFace API")