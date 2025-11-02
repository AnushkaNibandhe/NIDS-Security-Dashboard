"""
LLM Security Assistant Module
Provides AI-powered security guidance using HuggingFace API
"""

import os
from huggingface_hub import InferenceClient
from dotenv import load_dotenv

# Conditionally load dotenv for local development/testing
# This prevents the app from crashing in the cloud environment
if os.getenv('STREAMLIT_SERVER_PORT') is None:
    load_dotenv() 

class SecurityAssistant:
    """LLM-powered security assistant using Foundation-Sec-8B"""
    
    def __init__(self):
        """Initialize the security assistant safely."""
        
        # 1. Final Crash Fix: Local import of streamlit for secure token lookup
        api_key_from_secrets = ""
        try:
            # Import streamlit locally to prevent startup crash during health check
            import streamlit as st 
            api_key_from_secrets = st.secrets.get('HF_TOKEN', '')
        except Exception:
            # Pass silently if st.secrets is not yet initialized (early crash scenario)
            pass

        # 2. Use the found secret key, or fall back to os.getenv (local .env file)
        self.api_key = api_key_from_secrets or os.getenv('HF_TOKEN', '')
        
        self.model_id = "fdtn-ai/Foundation-Sec-8B"
        self.provider = "featherless-ai"
        self.use_llm = True
        
        if not self.api_key:
            print("⚠️ Warning: HF_TOKEN not found in environment. Using fallback responses.")
            self.client = None
        else:
            try:
                # Initialize client only if key is available
                self.client = InferenceClient(
                    provider=self.provider,
                    api_key=self.api_key
                )
                print("✅ LLM Client initialized successfully")
            except Exception as e:
                print(f"⚠️ LLM Client initialization failed: {e}")
                self.client = None

    def get_mitigation_steps(self, attack_type, confidence, row_data=None):
        """Get mitigation steps for detected attack"""
        
        if self.use_llm and self.client:
            try:
                response = self._get_llm_mitigation(attack_type, confidence)
                
                # Validation and formatting logic 
                formatted = self._extract_steps(response)
                
                if len(formatted) >= 4 and all(len(step) > 30 for step in formatted):
                    return self._format_final_output(formatted)
                else:
                    print(f"⚠️ LLM gave poor response. Using fallback.")
                    return self._get_fallback_mitigation(attack_type)
                    
            except Exception as e:
                print(f"⚠️ LLM error: {e}")
                return self._get_fallback_mitigation(attack_type)
        else:
            return self._get_fallback_mitigation(attack_type)
    
    def _get_llm_mitigation(self, attack_type, confidence):
        """Get mitigation from LLM with optimized prompt"""
        
        prompt = f"""As a cybersecurity expert, list 5 mitigation steps for a {attack_type} attack (confidence: {confidence:.0%}).

Step 1: Implement rate limiting to restrict request frequency per IP address
Step 2:"""
        
        try:
            result = self.client.text_generation(
                prompt,
                model=self.model_id,
                max_new_tokens=400,
                temperature=0.7,
                top_p=0.9,
                repetition_penalty=1.2,  # Prevent repetition
                do_sample=True
            )
            
            response = str(result).strip()
            full_response = prompt + " " + response
            
            return full_response
            
        except Exception as e:
            raise Exception(f"LLM call failed: {e}")
    
    def _extract_steps(self, response):
        """Extract numbered steps from response"""
        steps = []
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Look for "Step X:" format
            for i in range(1, 10):
                if f"Step {i}:" in line:
                    content = line.split(f"Step {i}:", 1)[-1].strip()
                    if len(content) > 20: 
                        steps.append(content)
                        break
            
            # Also check for "X." format
            for i in range(1, 10):
                if line.startswith(f"{i}."):
                    content = line.split(".", 1)[-1].strip()
                    if len(content) > 20 and content not in steps:
                        steps.append(content)
                        break
        
        # Remove duplicates while preserving order
        seen = set()
        unique_steps = []
        for step in steps:
            normalized = step.lower().strip()[:50]
            if normalized not in seen:
                seen.add(normalized)
                unique_steps.append(step)
        
        return unique_steps[:5] 
    
    def _format_final_output(self, steps):
        """Format steps into final output"""
        formatted = []
        for i, step in enumerate(steps, 1):
            step = step.strip()
            if step.endswith('.'):
                step = step[:-1]
            formatted.append(f"**{i}. {step}**")
        
        return "\n\n".join(formatted)
    
    def _get_fallback_mitigation(self, attack_type):
        """High-quality fallback responses"""
        mitigation_map = {
            'DoS': """**1. Enable Rate Limiting:** Configure network devices to limit incoming request rates from single IP addresses (e.g., 100 requests/minute) to prevent traffic floods

**2. Activate DDoS Protection:** Deploy cloud-based DDoS mitigation services like Cloudflare or AWS Shield that can absorb and filter attack traffic

**3. Scale Infrastructure:** Temporarily increase bandwidth capacity and add load balancers to distribute traffic across multiple servers

**4. Block Malicious IPs:** Identify attacking IP addresses through traffic analysis and add them to firewall blacklists

**5. Monitor in Real-Time:** Set up dashboards to track traffic patterns and configure automated alerts for unusual spikes exceeding 200% of baseline""",
            
            'Probe': """**1. Configure Port Scan Detection:** Enable IDS rules to detect port scans and automatically block IPs scanning more than 10 ports in 60 seconds

**2. Hide Service Information:** Disable unnecessary services, close unused ports, and configure servers to hide version information in headers

**3. Deploy Honeypots:** Set up decoy systems to attract and trap attackers while gathering intelligence about their methods

**4. Enhanced Logging:** Enable detailed connection logging on firewalls and servers including source IP, timestamp, and targeted ports

**5. Network Segmentation:** Divide network into security zones using VLANs to isolate critical systems from reconnaissance""",
            
            'R2L': """**1. Enforce Multi-Factor Authentication:** Implement mandatory 2FA/MFA for all remote access including SSH, VPN, RDP using authenticator apps or hardware tokens

**2. Monitor Failed Logins:** Set up alerts for repeated failed authentication attempts (5 failures in 10 minutes) and implement account lockout policies

**3. Restrict by IP Range:** Configure remote access services to accept connections only from known IP ranges or use geo-IP filtering

**4. Audit Access Privileges:** Review all remote access accounts, revoke terminated employee credentials, and disable inactive accounts over 90 days old

**5. Deploy IPS Rules:** Enable Intrusion Prevention System to block known R2L attack signatures including brute force and credential stuffing""",
            
            'U2R': """**1. Apply Security Patches:** Immediately update systems with latest patches addressing privilege escalation vulnerabilities, especially kernel and sudo updates

**2. Implement Least Privilege:** Audit all accounts to ensure minimum required permissions, remove unnecessary sudo rights, and disable direct root login

**3. Enable Mandatory Access Controls:** Activate SELinux or AppArmor to enforce security policies preventing processes from escalating privileges

**4. Monitor Privilege Changes:** Set up SIEM alerts for privilege escalation events including sudo usage and changes to user group memberships

**5. Harden Service Configurations:** Ensure services run with dedicated low-privilege accounts, disable SUID/SGID bits, and use containerization""",
            
            'Normal': """**1. Maintain Active Monitoring:** Continue 24/7 network traffic analysis and review security dashboards daily for anomalies

**2. Update Security Baselines:** Review network behavior baselines quarterly documenting peak usage times and typical protocols

**3. Conduct Security Testing:** Schedule quarterly penetration testing and vulnerability assessments to verify security controls

**4. Audit Access Logs:** Perform weekly reviews of authentication and system logs looking for unusual patterns

**5. Keep Posture Current:** Maintain monthly patch schedule, update signatures daily, review policies annually, and conduct disaster recovery drills"""
        }
        
        return mitigation_map.get(attack_type, """**1. Immediate Assessment:** Analyze detected activity scope and severity to understand attack impact

**2. Isolate Systems:** Temporarily disconnect compromised systems from network to prevent lateral movement

**3. Enable Additional Monitoring:** Increase logging verbosity and deploy extra sensors on affected infrastructure

**4. Update Security Controls:** Review and update firewall rules, IDS/IPS signatures based on indicators of compromise

**5. Document Incident:** Create detailed report with timeline, affected systems, and prevention recommendations""")
    
    def chat_response(self, user_message):
        """Generate chatbot response for security queries"""
        
        if self.client:
            try:
                prompt = f"""Question: {user_message}

Answer in 2-3 clear paragraphs:"""
                
                result = self.client.text_generation(
                    prompt,
                    model=self.model_id,
                    max_new_tokens=350,
                    temperature=0.7,
                    top_p=0.9,
                    do_sample=True
                )
                
                response = str(result).strip()
                
                # Clean and validate
                if len(response) > 80 and "Question:" not in response:
                    return response
                else:
                    return self._get_fallback_chat_response(user_message)
                    
            except Exception as e:
                print(f"Chat error: {e}")
                return self._get_fallback_chat_response(user_message)
        else:
            return self._get_fallback_chat_response(user_message)
    
    def _get_fallback_chat_response(self, user_message):
        """Intelligent fallback for common questions"""
        
        message_lower = user_message.lower()
        
        if any(word in message_lower for word in ['firewall', 'configure firewall']):
            return """A firewall is a network security system that monitors and controls incoming and outgoing traffic based on predetermined security rules. 

To configure effectively: Implement default-deny policy (block all, allow only necessary). Create rules for required services like HTTPS (443) and SSH (22). Enable stateful packet inspection and logging for denied connections. Review and update rules regularly.

Deploy both network firewalls (perimeter defense) and host-based firewalls (endpoint protection) for defense in depth."""
        
        elif any(word in message_lower for word in ['dos', 'ddos', 'denial']):
            return """DoS/DDoS attacks overwhelm your services by flooding them with traffic to make them unavailable to legitimate users.

Prevention: Implement rate limiting, use cloud DDoS protection services, deploy load balancers, maintain excess bandwidth capacity, and configure connection limits on web servers to prevent resource exhaustion.

Response: Enable geo-blocking, use CDN services like Cloudflare, implement CAPTCHA challenges, and work with your ISP to filter malicious traffic upstream before it reaches your infrastructure."""
        
        elif any(word in message_lower for word in ['sql injection', 'sqli']):
            return """SQL injection exploits vulnerabilities in database queries by inserting malicious SQL commands through user input fields.

Prevention: Always use parameterized queries or prepared statements (never concatenate user input). Implement input validation with whitelists, use ORM frameworks for automatic escaping, apply least privilege to database accounts, and enable Web Application Firewalls with SQLi detection.

Also: Regularly scan applications for vulnerabilities, keep database software updated, disable detailed error messages in production, and implement comprehensive logging to detect injection attempts."""
        
        elif any(word in message_lower for word in ['password', 'authentication']):
            return """Strong authentication is your first defense against unauthorized access.

Best practices: Require minimum 12 characters with complexity, enforce rotation every 90 days, implement account lockout after failed attempts, use password managers, and hash passwords with bcrypt or Argon2 (never plaintext).

Beyond passwords: Implement MFA everywhere (password + phone/token + biometrics), use passwordless authentication (FIDO2 keys), and require hardware tokens for privileged accounts."""
        
        elif any(word in message_lower for word in ['encrypt', 'encryption']):
            return """Encryption protects data confidentiality by converting readable information into unreadable ciphertext.

Implementation: Use TLS 1.3 for data in transit (HTTPS, SFTP, VPN), AES-256 for data at rest (databases, file systems, backups), and PKI with RSA or ECC for key exchange. Enable full disk encryption on endpoints.

Key management: Store encryption keys separately from encrypted data, use HSMs for key generation and storage, implement key rotation policies, maintain recovery procedures, and never hardcode keys in application code."""
        
        return f"""For questions about "{user_message}", I recommend consulting official security documentation (NIST, CIS benchmarks), vendor security guides, and MITRE ATT&CK framework.

Focus on security fundamentals: Keep systems patched, implement defense in depth with multiple security layers, follow principle of least privilege, enable comprehensive logging and monitoring, and conduct regular security assessments.

Feel free to ask specific questions about firewalls, encryption, access control, network security, or attack types for detailed guidance."""
    
    