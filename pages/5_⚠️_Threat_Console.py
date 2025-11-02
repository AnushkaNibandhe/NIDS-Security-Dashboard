"""
Threat Console - Real-time Threat Analysis and Prediction
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import sys
import os
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.inference import NIDSInference, generate_synthetic_traffic
from shared.llm import SecurityAssistant
from shared.utils import (check_authentication, check_admin, add_detection,
                         get_severity_emoji, log_audit_event)

# --- DEFINITIONS FOR PREPROCESSING (Using known values for feature stability) ---
RAW_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count'
]
CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']
TOTAL_EXPECTED_FEATURES = 122
# --- END OF DEFINITIONS ---


# Check authentication
if not check_authentication():
    st.error("⛔ Please log in to access this page")
    st.stop()

if not check_admin():
    st.error("🚫 Admin access required")
    st.stop()

st.title("⚠️ Threat Console")
st.markdown("### Real-Time Threat Detection & Analysis")

# Initialize inference engine and LLM assistant
if 'inference_engine' not in st.session_state:
    st.session_state.inference_engine = NIDSInference()
    st.session_state.llm_assistant = SecurityAssistant()

# Initialize state for persistent mitigation display
if 'current_mitigation_output' not in st.session_state:
    st.session_state.current_mitigation_output = ""

# Tabs for different views
tab1, tab2, tab3 = st.tabs(["🔴 Live Detection", "📊 Predictions Table", "🧪 Test with Sample Data"])

# TAB 1: Live Detection (Unchanged)
with tab1:
    st.subheader("🔴 Real-Time Detection Engine")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("**Upload Network Traffic Data (CSV format)**")
        uploaded_file = st.file_uploader(
            "Select NSL-KDD formatted CSV file",
            type=['csv'],
            help="Upload CSV with NSL-KDD features (122 columns)"
        )
        
        if uploaded_file:
            try:
                # Read uploaded data
                data = pd.read_csv(uploaded_file)
                st.success(f"✅ Loaded {len(data)} network flows")
                
                # Show preview
                with st.expander("📋 Data Preview"):
                    st.dataframe(data.head(10), use_container_width=True)
                
                # Analyze button
                if st.button("🔍 Analyze Traffic", type="primary"):
                    with st.spinner("🔄 Analyzing network traffic..."):
                        # Make predictions
                        predictions = st.session_state.inference_engine.batch_predict(data)
                        
                        # Add to session state
                        for pred in predictions:
                            add_detection(pred)
                        
                        # Show results
                        st.success(f"✅ Analysis complete! Detected {len(predictions)} flows")
                        
                        # Summary stats
                        attack_counts = {}
                        for pred in predictions:
                            attack_type = pred['attack_type']
                            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
                        
                        st.markdown("**Detection Summary:**")
                        for attack_type, count in attack_counts.items():
                            emoji = get_severity_emoji(pred.get('severity', 'Low'))
                            st.write(f"{emoji} **{attack_type}**: {count} instances")
                
            except Exception as e:
                st.error(f"❌ Error processing file: {e}")
    
    with col2:
        st.markdown("**Quick Stats**")
        total_detections = len(st.session_state.get('detections', []))
        recent_high = len([d for d in st.session_state.get('detections', [])[-20:] 
                          if d['severity'] == 'High'])
        
        st.metric("Total Detections", total_detections)
        st.metric("Recent High Severity", recent_high, delta="Last 20")
        
        st.markdown("---")
        st.info("""
        **Expected Format:**
        NSL-KDD dataset features including:
        - duration, protocol_type, service
        - src_bytes, dst_bytes
        - flag, logged_in, count
        - And other 122 features
        """)

# TAB 2: Predictions Table (Fixed Mitigation Logic)
with tab2:
    st.subheader("📊 Detection History")
    
    if st.session_state.get('detections'):
        detections = st.session_state.detections
        
        # Filters
        col_filter1, col_filter2, col_filter3 = st.columns(3)
        
        with col_filter1:
            attack_filter = st.multiselect(
                "Filter by Attack Type",
                options=['DoS', 'Probe', 'R2L', 'U2R', 'Normal'],
                default=['DoS', 'Probe', 'R2L', 'U2R']
            )
        
        with col_filter2:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=['High', 'Medium', 'Low', 'Safe'],
                default=['High', 'Medium']
            )
        
        with col_filter3:
            limit = st.slider("Show last N records", 10, 500, 50)
        
        # Filter data
        filtered = [d for d in detections 
                   if d['attack_type'] in attack_filter 
                   and d['severity'] in severity_filter][-limit:]
        
        # Display table
        if filtered:
            df = pd.DataFrame(filtered)
            
            # Format for display
            display_df = df[['timestamp', 'attack_type', 'severity', 'confidence']].copy()
            display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.1%}")
            display_df['emoji'] = display_df['severity'].apply(get_severity_emoji)
            display_df = display_df[['emoji', 'timestamp', 'attack_type', 'severity', 'confidence']]
            display_df.columns = ['', 'Timestamp', 'Attack Type', 'Severity', 'Confidence']
            
            st.dataframe(display_df, use_container_width=True, height=400)
            
            # Detailed view
            st.markdown("---")
            st.subheader("🔍 Detailed Analysis")
            
            selected_idx = st.selectbox(
                "Select detection for detailed view",
                range(len(filtered)),
                format_func=lambda x: f"{filtered[x]['timestamp']} - {filtered[x]['attack_type']}"
            )
            
            if selected_idx is not None:
                selected = filtered[selected_idx]
                
                col_detail1, col_detail2 = st.columns([1, 1])
                
                with col_detail1:
                    st.markdown(f"""
                    **Detection Details:**
                    - **Attack Type**: {get_severity_emoji(selected['severity'])} {selected['attack_type']}
                    - **Severity**: {selected['severity']}
                    - **Confidence**: {selected['confidence']:.2%}
                    - **Timestamp**: {selected['timestamp']}
                    - **Prediction ID**: {selected.get('prediction_id', 'N/A')}
                    """)
                    
                    # Get description
                    description = st.session_state.inference_engine.get_attack_description(
                        selected['attack_type']
                    )
                    st.info(f"**About this attack:**\n{description}")
                
                with col_detail2:
                    st.markdown("**🤖 AI-Powered Mitigation Steps**")
                    
                    # FIX: Use session state to store and force display the mitigation output
                    if st.button("Generate Recommendations", key=f"gen_rec_{selected_idx}"):
                        if selected['attack_type'] != 'Normal':
                            with st.spinner("🤖 Consulting security AI..."):
                                mitigation = st.session_state.llm_assistant.get_mitigation_steps(
                                    selected['attack_type'],
                                    selected['confidence']
                                )
                                # Store the output persistently
                                st.session_state['current_mitigation_output'] = mitigation
                                
                                # Log action
                                log_audit_event(
                                    action="Generated Mitigation",
                                    user=st.session_state.get('username', 'admin'),
                                    details=f"Attack: {selected['attack_type']}",
                                    severity="INFO"
                                )
                                # Rerun to force display
                                st.rerun()
                        else:
                            st.session_state['current_mitigation_output'] = "No mitigation needed for Normal traffic."
                            st.rerun()

                    # Render the persistent output outside the button click
                    if st.session_state['current_mitigation_output']:
                        st.markdown(st.session_state['current_mitigation_output'])


        else:
            st.info("No detections match the selected filters")
    else:
        st.info("No detections available. Upload and analyze traffic data first.")

# TAB 3: Test with Sample Data (Fixed Mitigation Logic)
with tab3:
    st.subheader("🧪 Test Detection System")
    st.markdown("Generate synthetic network traffic for testing the detection system")
    
    col_test1, col_test2 = st.columns(2)
    
    with col_test1:
        # Default n_samples reduced for faster generation
        n_samples = st.number_input("Number of samples to generate", 10, 1000, 50) 
        # Default attack ratio increased to guarantee detection for demo
        attack_ratio = st.slider("Attack traffic ratio", 0.0, 1.0, 0.8, 0.05) 
    
    with col_test2:
        st.info(f"""
        **Test Configuration:**
        - Total Samples: {n_samples}
        - Expected Attacks: ~{int(n_samples * attack_ratio)}
        - Expected Normal: ~{int(n_samples * (1-attack_ratio))}
        """)
    
    # Analyze button setup
    if st.button("🎲 Generate & Analyze Test Data", type="primary"):
        st.session_state['current_mitigation_output'] = "" # Clear previous mitigation output
        with st.spinner("🔄 Generating synthetic traffic..."):
            # Generate data
            test_data = generate_synthetic_traffic(n_samples, attack_ratio)
            st.success(f"✅ Generated {len(test_data)} synthetic network flows")
            
            # Show sample
            with st.expander("📋 Sample Data"):
                st.dataframe(test_data.head(10), use_container_width=True)
        
        with st.spinner("🔍 Running detection analysis..."):
            # Analyze
            predictions = st.session_state.inference_engine.batch_predict(test_data)
            
            # Add to detections
            for pred in predictions:
                add_detection(pred)
            
            st.success(f"✅ Analysis complete!")
            
            # Store latest predictions temporarily for display/selection
            st.session_state['latest_test_predictions'] = predictions 
            
            # Show results
            result_df = pd.DataFrame(predictions)
            
            # Rerun to display analysis output
            st.rerun() 


    # Section to display results AFTER clicking the button (requires st.session_state check)
    if 'latest_test_predictions' in st.session_state and st.session_state['latest_test_predictions']:
        latest_predictions = st.session_state['latest_test_predictions']
        result_df = pd.DataFrame(latest_predictions)
        
        # --- Start Display ---
        
        # Show table
        display_df = result_df[['timestamp', 'attack_type', 'severity', 'confidence']].copy()
        display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.1%}")
        display_df['emoji'] = display_df['severity'].apply(get_severity_emoji)
        display_df = display_df[['emoji', 'timestamp', 'attack_type', 'severity', 'confidence']]
        display_df.columns = ['', 'Timestamp', 'Attack Type', 'Severity', 'Confidence']
        
        st.markdown("**Detection Results (Latest Batch):**")
        st.dataframe(display_df, use_container_width=True, height=200)

        # Detailed Analysis Section
        st.markdown("---")
        st.subheader("🔍 Detailed Analysis of Latest Batch")

        # Map the predictions list to indices for the selectbox
        selected_idx = st.selectbox(
            "Select flow for detailed view and mitigation",
            range(len(latest_predictions)),
            format_func=lambda x: f"{latest_predictions[x]['timestamp']} - {latest_predictions[x]['attack_type']}",
            key='test_select_box' # Unique key
        )
        
        if selected_idx is not None:
            selected = latest_predictions[selected_idx]
            
            col_detail1, col_detail2 = st.columns([1, 1])
            
            with col_detail1:
                st.markdown(f"""
                **Detection Details:**
                - **Attack Type**: {get_severity_emoji(selected['severity'])} {selected['attack_type']}
                - **Severity**: {selected['severity']}
                - **Confidence**: {selected['confidence']:.2%}
                - **Timestamp**: {selected['timestamp']}
                """)
                
                # Get description
                description = st.session_state.inference_engine.get_attack_description(
                    selected['attack_type']
                )
                st.info(f"**About this attack:**\n{description}")
            
            with col_detail2:
                st.markdown("**🤖 AI-Powered Mitigation Steps**")
                
                # FIX: Use key from session state for button and trigger state change
                if st.button("Generate Recommendations", key="gen_rec_test_tab_run"): 
                    if selected['attack_type'] != 'Normal':
                        with st.spinner("🤖 Consulting security AI..."):
                            mitigation = st.session_state.llm_assistant.get_mitigation_steps(
                                selected['attack_type'],
                                selected['confidence']
                            )
                            # Store result persistently
                            st.session_state['current_mitigation_output'] = mitigation
                            
                            # Log action
                            log_audit_event(
                                action="Generated Mitigation",
                                user=st.session_state.get('username', 'admin'),
                                details=f"Attack: {selected['attack_type']} (Test Tab)",
                                severity="INFO"
                            )
                            st.rerun()
                    else:
                        st.session_state['current_mitigation_output'] = "No mitigation needed for Normal traffic."
                        st.rerun()
                
                # Render the persistent output
                if st.session_state['current_mitigation_output']:
                    st.markdown(st.session_state['current_mitigation_output'])

        # Summary (Moved to the bottom)
        attack_summary = result_df['attack_type'].value_counts()
        severity_summary = result_df['severity'].value_counts()
        
        st.markdown("---")
        col_sum1, col_sum2 = st.columns(2)
        
        with col_sum1:
            st.markdown("**Attack Type Distribution:**")
            for attack, count in attack_summary.items():
                st.write(f"• {attack}: {count}")
        
        with col_sum2:
            st.markdown("**Severity Distribution:**")
            for severity, count in severity_summary.items():
                emoji = get_severity_emoji(severity)
                st.write(f"{emoji} {severity}: {count}")


# Footer
st.markdown("---")
st.caption("🛡️ NIDS Threat Console | Powered by Random Forest ML + Foundation-Sec LLM")
