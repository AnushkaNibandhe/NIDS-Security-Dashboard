# 🛡️ AI-Powered Network Intrusion Detection System (NIDS)

A complete Security Operations Center (SOC) dashboard with ML-based threat detection and LLM-powered security assistance.

## 🌟 Features

### Core Capabilities
- ✅ **Random Forest ML Model** - 99.7% accuracy on NSL-KDD dataset
- 🤖 **LLM Security Assistant** - AI-powered mitigation guidance (Foundation-Sec-8B)
- 🎯 **Multi-Class Detection** - DoS, Probe, R2L, U2R, Normal traffic
- 📊 **Real-Time Dashboard** - Live threat visualization and analytics
- 🔐 **Role-Based Access** - Separate User and Admin portals
- 📋 **Audit Logging** - Complete system activity tracking
- 🚫 **IP Management** - Block/whitelist capabilities (simulated)
- 📈 **Advanced Analytics** - Heat maps, time series, distribution charts

### User Portal
- 👤 Dashboard with attack statistics
- 🔍 Detection history viewer
- 🤖 Security assistant chatbot
- 📚 Help & documentation

### Admin Portal
- 🛡️ SOC metrics and system health
- ⚠️ Threat console with live detection
- 🔧 Incident response actions
- 📋 Comprehensive audit logs
- ⚙️ System configuration

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- HuggingFace API token (for LLM features)

### Installation

**Step 1: Clone/Create Project**
```bash
mkdir nids-project
cd nids-project
```

**Step 2: Create Folder Structure**
```bash
mkdir -p models shared pages data
touch shared/__init__.py
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 4: Configure Environment**
Create `.env` file:
```bash
cp .env.example .env
```

Edit `.env` and add your HuggingFace token:
```
HF_TOKEN=hf_your_token_here
```

Get free token at: https://huggingface.co/settings/tokens

**Step 5: Generate Sample Data**
```bash
python generate_sample_data.py
```

**Step 6: Run Application**
```bash
streamlit run app.py
```

Application will open at: http://localhost:8501

---

## 🔑 Login Credentials

### User Portal
- **Username:** `user`
- **Password:** `user123`

### Admin Portal
- **Username:** `admin`
- **Password:** `admin123`

---

## 📁 Project Structure

```
nids-project/
├── app.py                          # Main application entry
├── requirements.txt                # Python dependencies
├── .env                           # Environment variables
├── .env.example                   # Environment template
├── generate_sample_data.py        # Sample data generator
│
├── models/                        # ML models (optional)
│   ├── rf_model.pkl              # Trained Random Forest
│   └── scaler.pkl                # Feature scaler
│
├── shared/                        # Core modules
│   ├── __init__.py
│   ├── inference.py              # ML inference engine
│   ├── llm.py                    # LLM security assistant
│   └── utils.py                  # Utility functions
│
├── pages/                         # Streamlit pages
│   ├── 1_👤_User_Dashboard.py
│   ├── 2_🔍_User_Detections.py
│   ├── 3_🤖_Security_Assistant.py
│   ├── 4_🛡️_Admin_Dashboard.py
│   ├── 5_⚠️_Threat_Console.py
│   ├── 6_🔧_Incident_Actions.py
│   ├── 7_📋_Audit_Logs.py
│   └── 8_⚙️_Settings.py
│
└── data/                          # Data files
    └── sample_input.csv          # Sample NSL-KDD data
```

---

## 🔧 Usage Guide

### For Users

**1. View Dashboard**
- Navigate to "User Dashboard"
- View attack statistics and trends
- Monitor system status

**2. Check Detections**
- Go to "User Detections"
- Filter by attack type or severity
- View detection details

**3. Get Security Guidance**
- Open "Security Assistant"
- Ask security questions
- Use quick action buttons for common attacks

### For Administrators

**1. Monitor SOC Dashboard**
- View system health metrics
- Analyze threat heat maps
- Check active incidents

**2. Analyze Threats**
- Open "Threat Console"
- Upload network traffic CSV
- Generate test data
- Get AI-powered mitigation steps

**3. Take Actions**
- Navigate to "Incident Actions"
- Block malicious IPs
- Create incident tickets
- Manage whitelists

**4. Review Audit Logs**
- Go to "Audit Logs"
- Filter by severity or action
- Export logs as CSV

**5. Configure System**
- Open "Settings"
- Upload new ML models
- Adjust detection thresholds
- Configure alerts

---

## 📊 Data Format

### Expected CSV Format (NSL-KDD)

Your CSV should contain these columns (minimum 30 features):

```
duration, protocol_type, service, flag, src_bytes, dst_bytes,
land, wrong_fragment, urgent, hot, num_failed_logins,
logged_in, num_compromised, root_shell, su_attempted,
num_root, num_file_creations, num_shells, num_access_files,
count, srv_count, serror_rate, srv_serror_rate, rerror_rate,
srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate,
dst_host_count, dst_host_srv_count, ...
```

Full NSL-KDD dataset: https://www.unb.ca/cic/datasets/nsl.html

---

## 🤖 Training Your Own Model

To train a Random Forest model on NSL-KDD:

**1. Download NSL-KDD Dataset**
```python
train_url = 'https://raw.githubusercontent.com/merteroglu/NSL-KDD-Network-Instrusion-Detection/master/NSL_KDD_Train.csv'
test_url = 'https://raw.githubusercontent.com/merteroglu/NSL-KDD-Network-Instrusion-Detection/master/NSL_KDD_Test.csv'
```

**2. Train Model** (refer to `nsl_kdd_ml.py` in your files)
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

# Train model (see nsl_kdd_ml.py for full code)
clf = RandomForestClassifier(n_estimators=10, n_jobs=2)
clf.fit(X_train, y_train)

# Save model
joblib.dump(clf, 'models/rf_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
```

**3. Models will be automatically loaded by the system**

---

## 🔒 Security Notes

### Important Disclaimers
- ⚠️ **Demo System**: This is for educational/demonstration purposes
- 🔐 **Authentication**: Uses simple password-based auth (not production-ready)
- 🚫 **Firewall Actions**: IP blocking is **simulated** - not real firewall integration
- 📡 **Network Traffic**: Does not capture live traffic - requires CSV uploads
- 🔑 **API Keys**: Keep HF_TOKEN private, never commit to version control

### For Production Use
- Implement proper authentication (OAuth, SAML, etc.)
- Integrate with real firewalls/network devices
- Use secure secrets management
- Add rate limiting and input validation
- Enable HTTPS/TLS
- Implement proper logging and monitoring

---

## 🐛 Troubleshooting

### Issue: LLM Not Responding
**Solution:** 
- Check `.env` file has valid `HF_TOKEN`
- Verify token at https://huggingface.co/settings/tokens
- Model may be loading (first call takes 20s+)

### Issue: Model Not Found
**Solution:**
- System works with dummy predictions if models missing
- Train and save models to `models/` directory
- Or just use for testing without real models

### Issue: Page Not Loading
**Solution:**
- Restart Streamlit: `Ctrl+C` then `streamlit run app.py`
- Clear cache: `streamlit cache clear`
- Check console for errors

### Issue: Import Errors
**Solution:**
```bash
pip install --upgrade -r requirements.txt
```

---

## 📚 Attack Type Reference

### DoS (Denial of Service)
- **Description**: Overwhelms system resources
- **Examples**: SYN flood, UDP flood, Smurf attack
- **Severity**: HIGH

### Probe
- **Description**: Network reconnaissance and scanning
- **Examples**: Port scan, ping sweep, nmap
- **Severity**: MEDIUM

### R2L (Remote to Local)
- **Description**: Unauthorized remote access attempts
- **Examples**: Password guessing, FTP exploitation
- **Severity**: MEDIUM

### U2R (User to Root)
- **Description**: Privilege escalation attacks
- **Examples**: Buffer overflow, rootkit installation
- **Severity**: HIGH

### Normal
- **Description**: Legitimate network traffic
- **Severity**: SAFE

---

## 🎓 For Academic Use

### Viva/Defense Preparation

**Key Points to Explain:**

1. **Architecture**: Multi-tier (UI → Business Logic → ML Model)
2. **ML Model**: Random Forest with 99.7% accuracy on NSL-KDD
3. **LLM Integration**: Foundation-Sec-8B via HuggingFace API
4. **Features**: Role-based access, real-time detection, audit logging
5. **Security**: Demonstrates IDS concepts, not production-ready

**Sample Questions & Answers:**

Q: *Why Random Forest over other algorithms?*
A: Best performance (99.7% accuracy vs 89% for Logistic Regression), handles multi-class classification well, feature importance analysis

Q: *How does LLM integration work?*
A: Uses HuggingFace Inference API with Foundation-Sec-8B model, provides context-aware mitigation steps

Q: *What's the difference between IDS and IPS?*
A: IDS detects (passive), IPS prevents (active). Our system is IDS - detects and alerts

Q: *How to reduce false positives?*
A: Adjust confidence thresholds, use ensemble methods, continuous model retraining

---

## 🚀 Deployment

### Streamlit Cloud (Free)

1. Push code to GitHub
2. Visit https://streamlit.io/cloud
3. Connect repository
4. Add secrets (HF_TOKEN)
5. Deploy!

### Local Network

```bash
streamlit run app.py --server.address=0.0.0.0 --server.port=8501
```

Access from other devices: `http://YOUR_IP:8501`

---

## 📞 Support

- 📧 Email: your-email@example.com
- 🐛 Issues: Create GitHub issue
- 📖 Docs: See this README

---

## 📄 License

MIT License - Free for academic and educational use

---

## 🙏 Acknowledgments

- **NSL-KDD Dataset**: University of New Brunswick
- **Foundation-Sec-8B**: FDTN AI
- **Streamlit**: Amazing framework
- **HuggingFace**: LLM inference API

---

## ⭐ Features Roadmap

- [ ] Real-time packet capture integration
- [ ] Advanced ensemble models (XGBoost, Neural Networks)
- [ ] Twilio/WhatsApp alert integration
- [ ] MongoDB/PostgreSQL backend
- [ ] Multi-user authentication
- [ ] Advanced MITRE ATT&CK mapping
- [ ] Threat intelligence feeds integration

---

**Built with ❤️ for Cybersecurity Education**

Last Updated: November 2024