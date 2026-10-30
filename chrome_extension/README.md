# Enhanced Phishing Hunter - Chrome Extension

## 🛡️ Overview
Advanced AI-powered Chrome extension for real-time phishing detection featuring comprehensive multi-layer analysis, enhanced hidden element detection, WHOIS domain age verification, and intelligent threat-based notifications. Built with Manifest v3 and powered by machine learning models for superior accuracy.

## 📁 File Structure
```
chrome_extension/
├── manifest.json          # Extension configuration (Manifest v3)
├── popup.html             # Clean, professional popup UI
├── popup.css             # Modern CSS styling with animations
├── popup.js              # Main popup logic & API integration
├── background.js         # Service worker for monitoring
├── content_script.js     # Page analysis & threat detection
├── icon.png             # Extension icon
└── icons/               # Additional status icons
    ├── alert.png
    ├── phishing.png
    ├── redirect.png
    └── warning.png
```

## 🔧 Key Features

### ✅ **Latest Enhancements (August 2025):**

1. **🔍 Enhanced Hidden Element Detection**
   - Comprehensive detection of 10+ hiding techniques
   - CSS-based hiding (`display:none`, `visibility:hidden`, `opacity:0`)
   - Positioning-based hiding (off-screen, negative margins)
   - JavaScript-based dynamic hiding detection
   - Critical detection of hidden password/sensitive fields
   - Smart thresholds for legitimate vs suspicious sites

2. **📅 Fixed WHOIS Domain Age Verification**
   - Proper `whois.whois(domain)` implementation
   - Accurate detection of newly registered domains (<6 months)
   - **"Domain registered less than 6 months ago - high phishing risk"** alerts
   - Robust error handling with intelligent fallbacks
   - Educational domain (.edu, .ac.in) special handling

3. **🚨 Intelligent Threat-Based Notifications**
   - Smart notifications only for detected threats (not safe sites)
   - Realistic warning examples in test mode
   - Automatic scanning with notifications during browsing
   - Chrome notifications API integration
   - Reduced false positive alerts

4. **🧠 Advanced Multi-Layer Detection System**
   - **Layer 1:** Basic URL validation & pattern matching
   - **Layer 2:** Feature analysis with WHOIS domain age checks
   - **Layer 3:** Enhanced content analysis with hidden element detection
   - **Layer 4:** Machine learning classification
   - **Layer 5:** Risk assessment & verdict generation
   - **Layer 6:** Ensemble decision making

### ✅ **Core Components:**

1. **Manifest v3 Compliance**
   - Modern service worker architecture
   - Specific host permissions for localhost:5000
   - Enhanced Content Security Policy
   - Proper tab and storage permissions

2. **Robust API Integration**
   - Automatic reconnection to localhost:5000 API
   - Comprehensive error handling
   - URL validation and sanitization
   - Timeout and retry mechanisms

3. **Professional UI Design**
   - Clean, minimal interface
   - Smooth animations and transitions
   - Responsive design for different screen sizes
   - Accessibility-compliant focus states

4. **Advanced Threat Detection**
   - Multi-pattern source code analysis
   - Behavioral monitoring (form submissions, interactions)
   - Real-time DOM change detection
   - False positive reduction for legitimate sites

5. **User Feedback System**
   - Report issues functionality
   - Settings persistence
   - Statistics tracking
   - Notification preferences

## 🚀 Installation

1. **Load in Chrome:**
   ```
   1. Open Chrome → Settings → Extensions
   2. Enable "Developer mode"
   3. Click "Load unpacked"
   4. Select the chrome_extension folder
   ```

2. **Start API Server:**
   ```bash
   # From the main project directory
   python api_server.py
   ```

## 🔌 API Integration

The extension communicates with your local API server:
- **Health Check:** `GET /health`
- **URL Analysis:** `GET /check_url?url=<encoded_url>`
- **Detailed Analysis:** `POST /analyze_detailed`

## 🎯 How It Works

1. **Automatic Analysis:** When you visit a webpage, the extension automatically analyzes it
2. **Risk Assessment:** Uses AI/ML models to determine phishing risk (0-100%)
3. **Visual Feedback:** Shows risk level with color-coded icons and progress bars
4. **Detailed Reports:** Click "View Details" for comprehensive analysis
5. **User Feedback:** Report false positives to improve detection accuracy

## 🛠️ Technical Architecture

### **Background Script (`background.js`)**
- Service worker for persistent monitoring
- Tab lifecycle management
- API communication coordination
- Notification system

### **Content Script (`content_script.js`)**
- Runs on every webpage
- Source code pattern analysis
- Behavioral threat detection
- Real-time DOM monitoring

### **Popup (`popup.js`)**
- Main user interface logic
- API server communication
- Results display and formatting
- User interaction handling

## 🔒 Security Features

- **Content Security Policy:** Restricts inline scripts and external resources
- **Host Permissions:** Limited to localhost development server
- **Input Validation:** All URLs are validated before analysis
- **Error Boundaries:** Graceful handling of API failures

## 🎨 UI Components

- **Status Indicators:** ✅ Safe, ⚠️ Warning, 🚨 Danger
- **Risk Bar:** Visual percentage display with color coding
- **Detail Sections:** Processing time, ML prediction, confidence scores
- **Action Buttons:** View details, report issues, retry analysis
- **Notification System:** Smart threat-only alerts with realistic examples
- **Test Mode:** Demonstration notifications for development

## 🔬 Detection Capabilities

### **Phishing Techniques Detected:**
- **Domain Spoofing:** Typosquatting, homograph attacks, subdomain abuse
- **Visual Deception:** Hidden forms, overlays, CSS injection
- **Credential Harvesting:** Password field detection, form redirection
- **Social Engineering:** Brand impersonation, urgency tactics
- **Technical Evasion:** Obfuscated code, iframe abuse, redirect chains

### **Advanced Features:**
- **Real-time Scanning:** Automatic analysis during browsing
- **Contextual Alerts:** Threat-specific notifications with details
- **Educational Overrides:** Special handling for .edu and academic domains
- **Legitimate Site Protection:** Reduced false positives for known brands
- **Performance Optimization:** Fast analysis with <1s response times

## 📊 Supported Analysis

### **URL & Domain Analysis:**
- **Pattern Recognition:** Suspicious domains, typosquatting, homograph attacks
- **WHOIS Domain Age:** Newly registered domains (<6 months) flagged as high-risk
- **DNS Verification:** Non-existent or suspicious DNS records detection
- **IP Address Detection:** Direct IP usage instead of domain names

### **Content & Behavioral Analysis:**
- **Hidden Element Detection:** 10+ techniques including CSS, positioning, JavaScript hiding
- **Form Analysis:** External submissions, password theft detection, hidden sensitive fields
- **Source Code Scanning:** Obfuscated scripts, suspicious JavaScript patterns
- **Network Monitoring:** External requests, HTTPS violations, mixed content

### **Machine Learning Classification:**
- **AI-Powered Detection:** Trained on thousands of phishing samples
- **Feature Extraction:** 5000+ URL and content features analyzed
- **Confidence Scoring:** Probabilistic risk assessment (0-100%)
- **Ensemble Methods:** Multiple model predictions combined for accuracy

## 🧪 Development & Testing

The extension includes comprehensive testing and debugging features:
- **Console Logging:** Detailed debug information for development
- **Error Reporting:** Stack traces and error boundary handling
- **Performance Monitoring:** Analysis timing and resource usage
- **Test Notifications:** Realistic threat examples for demonstration
- **API Health Checks:** Automatic server connectivity verification

### **Recent Bug Fixes (August 2025):**
- ✅ **WHOIS Implementation:** Fixed domain age detection using proper `whois.whois()` syntax
- ✅ **Hidden Element Analysis:** Enhanced detection of 10+ hiding techniques
- ✅ **Notification System:** Smart threat-only alerts with reduced false positives
- ✅ **Risk Bar Display:** Resolved CSS conflicts and improved visual feedback
- ✅ **API Integration:** Improved error handling and timeout management

## 🔄 Updates & Maintenance

All components are designed for:
- **Easy Updates:** Chrome extension management compatibility
- **Backward Compatibility:** API versioning and graceful degradation
- **Service Resilience:** Offline functionality when API unavailable
- **User Privacy:** Local processing with minimal data transmission
- **Security First:** Content Security Policy and permission restrictions

## 🏆 Performance & Accuracy

### **Detection Statistics:**
- **Accuracy Rate:** >85% on trained phishing datasets
- **False Positive Rate:** <15% on legitimate websites
- **Processing Speed:** <1 second average analysis time
- **Memory Usage:** <10MB typical extension footprint

### **Supported Domains:**
- **Educational:** Special handling for .edu, .ac.in domains
- **Government:** .gov domain recognition and reduced false positives
- **Major Brands:** Whitelist for Google, Microsoft, Amazon, etc.
- **Suspicious TLDs:** Enhanced detection for .tk, .ml, .ga domains

---

**Status:** ✅ Production Ready  
**Version:** 3.2.0  
**Last Updated:** August 13, 2025  
**Compatibility:** Chrome 88+, Manifest v3  
**License:** MIT

## 🚀 Quick Start

1. **Clone Repository:**
   ```bash
   git clone https://github.com/Vishnu-Gopalsamy/Phishing-hunter-extension.git
   cd Phishing-hunter-extension
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start API Server:**
   ```bash
   python api_server.py
   ```

4. **Load Extension:**
   - Open Chrome → Extensions → Developer Mode
   - Click "Load Unpacked" → Select `chrome_extension` folder
   - Pin extension to toolbar for easy access

5. **Test Detection:**
   - Visit any website
   - Click extension icon to see analysis
   - Use "Test Notification" for demonstration
