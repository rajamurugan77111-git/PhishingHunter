import './api_auth.js';
// Simplified background script for stable service worker operation
console.log('Layered Phishing Detector background script loaded');

// Basic configuration
const MONITORING_CONFIG = {
    enabled: true,
    riskThreshold: 60,   // Risk threshold for notifications
    apiUrl: 'http://localhost:5000',
    emailMonitoring: true  // Enable email monitoring
};

// Global state management
let activeMonitoring = new Map(); // tabId -> monitoring data
let emailAnalysisHistory = []; // Store email analysis results

// Initialize background monitoring
chrome.runtime.onInstalled.addListener(() => {
    console.log('Layered Phishing Detector installed');
    
    // Initialize storage
    chrome.storage.local.set({
        userFeedback: {},
        detectionStats: {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0,
            emailsAnalyzed: 0,
            phishingEmails: 0
        },
        settings: {
            enabled: true,
            notifications: true,
            sensitivity: 'medium',
            emailMonitoring: true
        }
    });
});

// Enhanced tab monitoring with automatic scanning
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (!MONITORING_CONFIG.enabled) return;
    
    // Monitor navigation start for immediate checks
    if (changeInfo.status === 'loading' && tab.url && 
        !tab.url.startsWith('chrome://') && 
        !tab.url.startsWith('chrome-extension://') &&
        !tab.url.startsWith('moz-extension://') &&
        !tab.url.startsWith('about:') &&
        !tab.url.startsWith('data:')) {
        
        console.log(`🔍 Starting scan for tab ${tabId}: ${tab.url}`);
        
        // Store monitoring data immediately
        activeMonitoring.set(tabId, {
            url: tab.url,
            startTime: Date.now(),
            riskScore: 0,
            scanStatus: 'scanning'
        });
        
        // Perform immediate URL analysis
        await performQuickURLCheck(tab.url, tabId);
    }
    
    // Deep analysis when page fully loads
    if (changeInfo.status === 'complete' && tab.url && 
        !tab.url.startsWith('chrome://') && 
        !tab.url.startsWith('chrome-extension://') &&
        !tab.url.startsWith('moz-extension://') &&
        !tab.url.startsWith('about:') &&
        !tab.url.startsWith('data:')) {
        
        console.log(`🔍 Deep scanning tab ${tabId}: ${tab.url}`);
        
        // Update monitoring status
        const monitoring = activeMonitoring.get(tabId);
        if (monitoring) {
            monitoring.scanStatus = 'deep_scanning';
            activeMonitoring.set(tabId, monitoring);
        }
        
        // Perform comprehensive analysis
        await performComprehensiveCheck(tab.url, tabId);
        
        // Inject content script for real-time monitoring
        try {
            await chrome.scripting.executeScript({
                target: { tabId: tabId },
                func: initializeRealTimeMonitoring
            });
        } catch (error) {
            console.log('Content script injection failed:', error.message);
        }
    }
});

// Clean up monitoring data when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    activeMonitoring.delete(tabId);
});

// Handle email composition analysis requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('📨 Received message:', message.action || message.type, 'Full message:', message);
    
    // Debug: Check for debugEmailDetection specifically
    if (message.action === 'debugEmailDetection') {
        console.log('🔍 DEBUG: Found debugEmailDetection message!');
    }
    
    // Handle email-related messages first
    if (message.action === 'analyzeEmailComposition') {
        console.log('📧 Received email composition for analysis:', message.data);
        
        // Handle async operation properly
        (async () => {
            try {
                // Perform email analysis
                const analysisResult = await performEmailCompositionAnalysis(message.data);
                
                // Store analysis result
                emailAnalysisHistory.push({
                    ...message.data,
                    analysis: analysisResult,
                    timestamp: Date.now()
                });
                
                // Limit history size
                if (emailAnalysisHistory.length > 100) {
                    emailAnalysisHistory = emailAnalysisHistory.slice(-100);
                }
                
                // Show notification if threat detected
                if (analysisResult.risk_score >= 70) {
                    await showEmailThreatNotification(message.data, analysisResult);
                }
                
                // Update statistics
                updateEmailStats(analysisResult);
                
                sendResponse({ success: true, analysis: analysisResult });
                
            } catch (error) {
                console.error('❌ Email composition analysis failed:', error);
                sendResponse({ success: false, error: error.message });
            }
        })();
        
        return true; // Keep message channel open for async response
    }
    
    if (message.action === 'getEmailStats') {
        // Handle async operation properly
        (async () => {
            const stats = await getEmailStats();
            sendResponse({ success: true, stats });
        })();
        return true;
    }
    
    if (message.action === 'getEmailHistory') {
        sendResponse({ success: true, history: emailAnalysisHistory });
        return true;
    }
    
    if (message.action === 'getEmailCompositionData') {
        // Get current email composition data from content script
        // Handle async operation properly
        (async () => {
            try {
                console.log('📧 Getting email composition data from content script...');
                
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (!tab) {
                    console.error('❌ No active tab found');
                    sendResponse({ success: false, error: 'No active tab found' });
                    return;
                }
                
                console.log('📧 Active tab found:', tab.url, 'Tab ID:', tab.id);
                
                // Check if content script is accessible
                try {
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'getEmailCompositionData'
                    });
                    
                    console.log('📧 Content script response:', response);
                    
                    if (response && response.success) {
                        sendResponse({ success: true, data: response.data });
                    } else {
                        console.warn('⚠️ Content script responded but no data:', response);
                        sendResponse({ 
                            success: false, 
                            error: 'No email composition data available',
                            details: 'Email composition not detected or no content available'
                        });
                    }
                } catch (contentScriptError) {
                    console.error('❌ Content script communication failed:', contentScriptError);
                    
                    // Check if this is a content script not loaded error
                    if (contentScriptError.message.includes('Could not establish connection')) {
                        sendResponse({ 
                            success: false, 
                            error: 'Content script not loaded on this page',
                            details: 'Please refresh the page and try again'
                        });
                    } else {
                        sendResponse({ 
                            success: false, 
                            error: 'Failed to communicate with content script',
                            details: contentScriptError.message
                        });
                    }
                }
            } catch (error) {
                console.error('❌ getEmailCompositionData failed:', error);
                sendResponse({ 
                    success: false, 
                    error: 'Failed to get email composition data',
                    details: error.message
                });
            }
        })();
        return true;
    }
    
    if (message.action === 'checkEmailDetectionStatus') {
        // Check email detection status from content script
        // Handle async operation properly
        (async () => {
            try {
                console.log('📧 Checking email detection status...');
                
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (!tab) {
                    sendResponse({ success: false, error: 'No active tab found' });
                    return;
                }
                
                try {
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'checkEmailDetectionStatus'
                    });
                    
                    console.log('📧 Email detection status:', response);
                    sendResponse(response);
                    
                } catch (contentScriptError) {
                    console.error('❌ Failed to check email detection status:', contentScriptError);
                    
                    // Try to inject content script if it's not accessible
                    if (contentScriptError.message.includes('Receiving end does not exist')) {
                        console.log('🔄 Attempting to inject content script...');
                        try {
                            await chrome.scripting.executeScript({
                                target: { tabId: tab.id },
                                files: ['content_script.js']
                            });
                            console.log('✅ Content script injected successfully');
                            
                            // Wait a moment for script to initialize, then try again
                            setTimeout(async () => {
                                try {
                                    const retryResponse = await chrome.tabs.sendMessage(tab.id, {
                                        action: 'checkEmailDetectionStatus'
                                    });
                                    console.log('📧 Retry successful:', retryResponse);
                                    sendResponse(retryResponse);
                                } catch (retryError) {
                                    console.error('❌ Retry failed:', retryError);
                                    sendResponse({ 
                                        success: false, 
                                        error: 'Content script injection failed',
                                        details: retryError.message
                                    });
                                }
                            }, 1000);
                            return; // Don't send response yet, wait for retry
                        } catch (injectionError) {
                            console.error('❌ Content script injection failed:', injectionError);
                        }
                    }
                    
                    sendResponse({ 
                        success: false, 
                        error: 'Content script not accessible',
                        details: contentScriptError.message
                    });
                }
            } catch (error) {
                console.error('❌ checkEmailDetectionStatus failed:', error);
                sendResponse({ 
                    success: false, 
                    error: 'Failed to check status',
                    details: error.message
                });
            }
        })();
        return true;
    }
    
    if (message.action === 'debugEmailDetection') {
        console.log('🔍 DEBUG: debugEmailDetection handler reached!');
        // Forward debug request to content script
        // Handle async operation properly
        (async () => {
            try {
                console.log('🔍 Forwarding debug request to content script...');
                
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (!tab) {
                    sendResponse({ success: false, error: 'No active tab found' });
                    return;
                }
                
                try {
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'debugEmailDetection'
                    });
                    
                    console.log('🔍 Debug response:', response);
                    console.log('🔍 Debug response details:', JSON.stringify(response, null, 2));
                    sendResponse(response);
                    
                } catch (contentScriptError) {
                    console.error('❌ Failed to send debug request:', contentScriptError);
                    
                    // Try to inject content script if it's not accessible
                    if (contentScriptError.message.includes('Receiving end does not exist')) {
                        console.log('🔄 Attempting to inject content script for debug...');
                        try {
                            await chrome.scripting.executeScript({
                                target: { tabId: tab.id },
                                files: ['content_script.js']
                            });
                            console.log('✅ Content script injected for debug');
                            
                            // Wait a moment for script to initialize, then try again
                            setTimeout(async () => {
                                try {
                                    const retryResponse = await chrome.tabs.sendMessage(tab.id, {
                                        action: 'debugEmailDetection'
                                    });
                                    console.log('🔍 Debug retry successful:', retryResponse);
                                    sendResponse(retryResponse);
                                } catch (retryError) {
                                    console.error('❌ Debug retry failed:', retryError);
                                    sendResponse({ 
                                        success: false, 
                                        error: 'Content script injection failed',
                                        details: retryError.message
                                    });
                                }
                            }, 1000);
                            return; // Don't send response yet, wait for retry
                        } catch (injectionError) {
                            console.error('❌ Content script injection failed for debug:', injectionError);
                        }
                    }
                    
                    sendResponse({ 
                        success: false, 
                        error: 'Content script not accessible',
                        details: contentScriptError.message
                    });
                }
            } catch (error) {
                console.error('❌ debugEmailDetection failed:', error);
                sendResponse({ 
                    success: false, 
                    error: 'Failed to trigger debug',
                    details: error.message
                });
            }
        })();
        return true;
    }
    
    if (message.action === 'contentScriptReady') {
        console.log('✅ Content script ready on:', message.url);
        sendResponse({ success: true, message: 'Content script ready' });
        return true;
    }
    
    // Force email detection
    if (message.action === 'forceEmailDetection') {
        (async () => {
            try {
                console.log('🚀 Force email detection requested');
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                
                if (!tab) {
                    sendResponse({ success: false, error: 'No active tab found' });
                    return;
                }
                
                console.log('🔍 Sending force detection request to content script...');
                const response = await chrome.tabs.sendMessage(tab.id, { action: 'forceEmailDetection' });
                
                if (response && response.success) {
                    console.log('✅ Force detection successful:', response.data);
                    sendResponse({ success: true, data: response.data });
                } else {
                    console.log('❌ Force detection failed:', response?.error);
                    sendResponse({ success: false, error: response?.error || 'Force detection failed' });
                }
            } catch (contentScriptError) {
                if (contentScriptError.message.includes('Receiving end does not exist')) {
                    console.log('🔄 Attempting to inject content script...');
                    try {
                        await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            files: ['content_script.js']
                        });
                        
                        // Wait a bit for the script to initialize
                        await new Promise(resolve => setTimeout(resolve, 500));
                        
                        // Try again
                        const retryResponse = await chrome.tabs.sendMessage(tab.id, { action: 'forceEmailDetection' });
                        if (retryResponse && retryResponse.success) {
                            sendResponse({ success: true, data: retryResponse.data });
                        } else {
                            sendResponse({ success: false, error: retryResponse?.error || 'Force detection failed after injection' });
                        }
                    } catch (injectionError) {
                        console.error('❌ Content script injection failed:', injectionError);
                        sendResponse({ success: false, error: 'Content script injection failed' });
                    }
                } else {
                    console.error('❌ Failed to send force detection request:', contentScriptError);
                    sendResponse({ success: false, error: 'Failed to send force detection request', details: contentScriptError.message });
                }
            }
        })();
        return true;
    }
    
    // Force refresh email detection
    if (message.action === 'forceRefreshEmailDetection') {
        (async () => {
            try {
                console.log('🔄 Force refresh email detection requested');
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                
                if (!tab) {
                    sendResponse({ success: false, error: 'No active tab found' });
                    return;
                }
                
                console.log('🔍 Sending force refresh request to content script...');
                const response = await chrome.tabs.sendMessage(tab.id, { action: 'forceRefreshEmailDetection' });
                
                if (response && response.success) {
                    console.log('✅ Force refresh successful:', response.data);
                    sendResponse({ success: true, data: response.data });
                } else {
                    console.log('❌ Force refresh failed:', response?.error);
                    sendResponse({ success: false, error: response?.error || 'Force refresh failed' });
                }
            } catch (contentScriptError) {
                if (contentScriptError.message.includes('Receiving end does not exist')) {
                    console.log('🔄 Attempting to inject content script...');
                    try {
                        await chrome.scripting.executeScript({
                            target: { tabId: tab.id },
                            files: ['content_script.js']
                        });
                        
                        // Wait a bit for the script to initialize
                        await new Promise(resolve => setTimeout(resolve, 500));
                        
                        // Try again
                        const retryResponse = await chrome.tabs.sendMessage(tab.id, { action: 'forceRefreshEmailDetection' });
                        if (retryResponse && retryResponse.success) {
                            sendResponse({ success: true, data: retryResponse.data });
                        } else {
                            sendResponse({ success: false, error: retryResponse?.error || 'Force refresh failed after injection' });
                        }
                    } catch (injectionError) {
                        console.error('❌ Content script injection failed:', injectionError);
                        sendResponse({ success: false, error: 'Content script injection failed' });
                    }
                } else {
                    console.error('❌ Failed to send force refresh request:', contentScriptError);
                    sendResponse({ success: false, error: 'Failed to send force refresh request', details: contentScriptError.message });
                }
            }
        })();
        return true;
    }
    
    // Handle other message types...
    switch (message.action || message.type) {
        case 'ANALYSIS_RESULT':
        case 'sourceCodeAnalysisResult':
            // Store analysis result
            const tabId = sender.tab?.id;
            if (tabId && activeMonitoring.has(tabId)) {
                const monitoring = activeMonitoring.get(tabId);
                monitoring.analysisResult = message.data;
                monitoring.lastAnalysis = Date.now();
                activeMonitoring.set(tabId, monitoring);
            }
            sendResponse({ success: true });
            break;
            
        case 'GET_MONITORING_DATA':
        case 'getMonitoringData':
            const requestTabId = message.tabId;
            const data = activeMonitoring.get(requestTabId) || null;
            sendResponse({ data });
            break;
            
        case 'behaviorAlert':
            // Handle behavior alerts from content script
            console.log('🚨 Behavior alert:', message.type, 'on', message.url);
            const alertTabId = sender.tab?.id;
            if (alertTabId && activeMonitoring.has(alertTabId)) {
                const monitoring = activeMonitoring.get(alertTabId);
                monitoring.behaviorAlerts = monitoring.behaviorAlerts || [];
                monitoring.behaviorAlerts.push({
                    type: message.type,
                    timestamp: message.timestamp,
                    details: message.details
                });
                
                // Increase risk based on alert type
                let riskIncrease = 0;
                switch (message.type) {
                    case 'external_sensitive_form':
                        riskIncrease = 40;
                        break;
                    case 'external_password_form':
                        riskIncrease = 35;
                        break;
                    case 'hidden_password_form':
                        riskIncrease = 30;
                        break;
                    case 'rapid_redirects':
                        riskIncrease = 25;
                        break;
                    case 'clipboard_access':
                        riskIncrease = 15;
                        break;
                    case 'rapid_typing':
                        riskIncrease = 10;
                        break;
                    default:
                        riskIncrease = 15;
                }
                
                monitoring.riskScore = (monitoring.riskScore || 0) + riskIncrease;
                monitoring.finalRiskScore = Math.max(
                    monitoring.finalRiskScore || 0,
                    monitoring.riskScore
                );
                activeMonitoring.set(alertTabId, monitoring);
                
                // Show immediate notification ONLY for critical behavior threats
                const criticalAlerts = [
                    'external_sensitive_form', 
                    'external_password_form', 
                    'hidden_password_form'
                ];
                
                // Only show notification for actual critical behavioral threats
                if (criticalAlerts.includes(message.type)) {
                    console.log('🚨 Critical behavioral threat detected, showing notification');
                    showThreatNotification(
                        message.url, 
                        monitoring.finalRiskScore, 
                        'high',
                        [message.type]
                    ).catch(console.error);
                } else {
                    console.log('📊 Behavioral alert logged but not critical enough for notification:', message.type);
                }
                
                // Update badge immediately
                updateExtensionBadge(monitoring.finalRiskScore, alertTabId)
                    .catch(console.error);
            }
            sendResponse({ success: true });
            break;
            
        case 'getDebugInfo':
            // Get debug information
            const debugInfo = {
                activeMonitoring: Array.from(activeMonitoring.entries()),
                config: MONITORING_CONFIG
            };
            sendResponse(debugInfo);
            break;
            
        case 'updateUserFeedback':
            // Handle user feedback from popup
            handleUserFeedback(message.feedback, sendResponse);
            break;
            
        case 'monitorEmail':
            // Handle email monitoring requests
            if (message.emailData) {
                monitorEmailActivity(sender.tab?.id, message.emailData);
                sendResponse({ success: true, message: 'Email monitoring started' });
            } else {
                sendResponse({ success: false, error: 'No email data provided' });
            }
            break;
            
        case 'getNotificationSettings':
            // Get notification settings
            chrome.storage.local.get(['notificationSettings'], (result) => {
                sendResponse(result.notificationSettings || {
                    enabled: true,
                    contextAware: true,
                    frequency: 'medium'
                });
            });
            break;
            
        case 'updateNotificationSettings':
            // Update notification settings
            chrome.storage.local.set({ notificationSettings: message.settings }, () => {
                sendResponse({ success: true });
            });
            break;
            
        default:
            console.warn('Unknown message action:', message.action || message.type);
            sendResponse({ success: false, error: 'Unknown action' });
    }
    
    return true; // Keep message channel open for async response
});

// Email composition analysis function
async function performEmailCompositionAnalysis(emailData) {
    try {
        console.log('🔍 Analyzing email composition:', emailData);
        
        // Call the API for email analysis
        const response = await fetch(`${MONITORING_CONFIG.apiUrl}/analyze_email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                content: emailData.content,
                subject: emailData.subject,
                sender: emailData.sender || 'composing_user@example.com'
            })
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }
        
        const analysisResult = await response.json();
        console.log('✅ Email composition analysis completed:', analysisResult);
        
        return analysisResult;
        
    } catch (error) {
        console.error('❌ Email composition analysis failed:', error);
        
        // Fallback to basic pattern analysis
        return basicEmailPatternCheck(emailData);
    }
}

// Email monitoring functionality
async function monitorEmailActivity(tabId, emailData) {
    if (!MONITORING_CONFIG.emailMonitoring) return;
    
    try {
        console.log('📧 Monitoring email activity:', emailData);
        
        // Quick email check
        const quickResult = await performQuickEmailCheck(emailData);
        
        // Store email analysis
        const emailAnalysis = {
            tabId: tabId,
            timestamp: Date.now(),
            sender: emailData.sender,
            subject: emailData.subject,
            quickResult: quickResult,
            fullAnalysis: null
        };
        
        emailAnalysisHistory.push(emailAnalysis);
        
        // Keep only last 100 email analyses
        if (emailAnalysisHistory.length > 100) {
            emailAnalysisHistory.splice(0, emailAnalysisHistory.length - 100);
        }
        
        // Show notification if threat detected
        if (quickResult.is_phishing || quickResult.risk_score >= 70) {
            await showEmailThreatNotification(emailData, quickResult);
        }
        
        // Update stats
        await updateEmailStats(quickResult);
        
    } catch (error) {
        console.error('Email monitoring failed:', error);
    }
}

// Quick email check for background monitoring
async function performQuickEmailCheck(emailData) {
    try {
        const response = await fetch(
            `${MONITORING_CONFIG.apiUrl}/check_email_quick`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    sender: emailData.sender || '',
                    subject: emailData.subject || '',
                    content: emailData.content || ''
                }),
                timeout: 5000
            }
        );
        
        if (response.ok) {
            return await response.json();
        } else {
            throw new Error(`API request failed: ${response.status}`);
        }
        
    } catch (error) {
        console.error('Quick email check failed:', error);
        // Return basic pattern-based result
        return basicEmailPatternCheck(emailData);
    }
}

// Basic email pattern checking as fallback
function basicEmailPatternCheck(emailData) {
    let riskScore = 0;
    let threats = [];
    
    const subject = (emailData.subject || '').toLowerCase();
    const content = (emailData.content || '').toLowerCase();
    const sender = (emailData.sender || '').toLowerCase();
    
    // Check for urgent language
    const urgentWords = ['urgent', 'immediate', 'asap', 'account suspended', 'verify now'];
    for (const word of urgentWords) {
        if (subject.includes(word) || content.includes(word)) {
            riskScore += 15;
            threats.push(`urgent_language: ${word}`);
        }
    }
    
    // Check for financial pressure
    const financialWords = ['payment', 'invoice', 'refund', 'credit card', 'bank account'];
    for (const word of financialWords) {
        if (subject.includes(word) || content.includes(word)) {
            riskScore += 20;
            threats.push(`financial_pressure: ${word}`);
        }
    }
    
    // Check for credential requests
    if (content.includes('password') || content.includes('username') || content.includes('login')) {
        riskScore += 25;
        threats.push('credential_request');
    }
    
    // Check for suspicious links
    if (content.includes('click here') || content.includes('click below')) {
        riskScore += 20;
        threats.push('suspicious_links');
    }
    
    // Check sender domain
    if (sender.includes('@')) {
        const domain = sender.split('@')[1];
        if (domain.includes('.tk') || domain.includes('.ml') || domain.includes('.ga')) {
            riskScore += 30;
            threats.push('suspicious_tld');
        }
    }
    
    return {
        is_phishing: riskScore >= 50,
        risk_score: Math.min(riskScore, 100),
        threats: threats,
        confidence: Math.min(0.8, riskScore / 100),
        analysis_method: 'basic_pattern',
        timestamp: Date.now()
    };
}

// Show email threat notification
async function showEmailThreatNotification(emailData, analysisResult) {
    try {
        const riskScore = analysisResult.risk_score || 0;
        const threats = analysisResult.threats || [];
        
        let title, message, iconUrl, severity;
        
        if (riskScore >= 80 || analysisResult.is_phishing) {
            severity = 'critical';
            title = '🚨 PHISHING EMAIL DETECTED';
            message = `High-risk email from ${emailData.sender || 'unknown sender'}!\nSubject: ${emailData.subject || 'No subject'}\nRisk: ${riskScore}%`;
            iconUrl = 'icons/alert.png';
        } else if (riskScore >= 60) {
            severity = 'high';
            title = '⚠️ SUSPICIOUS EMAIL WARNING';
            message = `Suspicious email detected!\nFrom: ${emailData.sender || 'unknown'}\nRisk: ${riskScore}%`;
            iconUrl = 'icons/warning.png';
        } else {
            severity = 'medium';
            title = '🔍 EMAIL SECURITY NOTICE';
            message = `Email security concerns detected\nRisk: ${riskScore}%`;
            iconUrl = 'icons/phishing.png';
        }
        
        // Create notification with buttons for email threats
        const notificationId = `email_threat_${Date.now()}`;
        const notificationOptions = {
            type: 'basic',
            iconUrl: iconUrl,
            title: title,
            message: message,
            priority: severity === 'critical' ? 2 : (severity === 'high' ? 1 : 0),
            requireInteraction: severity === 'critical' || severity === 'high'
        };
        
        // Add buttons for high and critical threats
        if (severity === 'critical' || severity === 'high') {
            notificationOptions.buttons = [
                {
                    title: 'View Details',
                    iconUrl: 'icons/alert.png'
                },
                {
                    title: 'Mark as Safe',
                    iconUrl: 'icons/safe.png'
                }
            ];
        }
        
        await chrome.notifications.create(notificationId, notificationOptions);
        
        console.log('✅ Email threat notification created:', notificationId);
        
        // Store notification data for button handling
        await chrome.storage.local.set({
            [`notification_${notificationId}`]: {
                emailData,
                analysisResult,
                timestamp: Date.now()
            }
        });
        
        // Log email threat
        await logEmailThreat(emailData, analysisResult, severity);
        
    } catch (error) {
        console.error('Failed to show email threat notification:', error);
    }
}

// Handle notification button clicks for email threats
chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
    try {
        if (notificationId.startsWith('email_threat_')) {
            const notificationData = await chrome.storage.local.get(`notification_${notificationId}`);
            const data = notificationData[`notification_${notificationId}`];
            
            if (buttonIndex === 0) { // View Details
                // Open popup with email analysis details
                chrome.action.openPopup();
            } else if (buttonIndex === 1) { // Mark as Safe
                // Mark email as safe and update stats
                if (data) {
                    await updateEmailStats({ ...data.analysisResult, marked_safe: true });
                    console.log('✅ Email marked as safe by user');
                }
            }
            
            // Clear notification
            chrome.notifications.clear(notificationId);
            chrome.storage.local.remove(`notification_${notificationId}`);
        }
        
    } catch (error) {
        console.error('❌ Email notification button handling failed:', error);
    }
});

// Log email threat for analytics
async function logEmailThreat(emailData, analysisResult, severity) {
    try {
        const threat = {
            type: 'email_threat',
            sender: emailData.sender,
            subject: emailData.subject,
            riskScore: analysisResult.risk_score,
            severity: severity,
            threats: analysisResult.threats,
            timestamp: Date.now(),
            analysisMethod: analysisResult.analysis_method
        };
        
        // Store in local storage
        const result = await chrome.storage.local.get(['emailThreatLog']);
        const threatLog = result.emailThreatLog || [];
        threatLog.unshift(threat);
        
        // Keep only last 50 email threats
        if (threatLog.length > 50) {
            threatLog.splice(50);
        }
        
        await chrome.storage.local.set({ emailThreatLog: threatLog });
        
        // Update email statistics
        const statsResult = await chrome.storage.local.get(['detectionStats']);
        const stats = statsResult.detectionStats || {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0,
            emailsAnalyzed: 0,
            phishingEmails: 0
        };
        
        stats.emailsAnalyzed++;
        if (analysisResult.is_phishing || analysisResult.risk_score >= 70) {
            stats.phishingEmails++;
        }
        
        await chrome.storage.local.set({ detectionStats: stats });
        
    } catch (error) {
        console.log('Email threat logging failed:', error.message);
    }
}

// Update email statistics
async function updateEmailStats(analysisResult) {
    try {
        const statsResult = await chrome.storage.local.get(['detectionStats']);
        const stats = statsResult.detectionStats || {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0,
            emailsAnalyzed: 0,
            phishingEmails: 0
        };
        
        stats.emailsAnalyzed++;
        if (analysisResult.is_phishing || analysisResult.risk_score >= 70) {
            stats.phishingEmails++;
        }
        
        await chrome.storage.local.set({ detectionStats: stats });
        
    } catch (error) {
        console.log('Failed to update email stats:', error.message);
    }
}

// Get email statistics
async function getEmailStats() {
    try {
        const statsResult = await chrome.storage.local.get(['detectionStats']);
        const stats = statsResult.detectionStats || {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0,
            emailsAnalyzed: 0,
            phishingEmails: 0
        };
        
        return {
            emailsAnalyzed: stats.emailsAnalyzed || 0,
            phishingEmails: stats.phishingEmails || 0,
            emailThreats: emailAnalysisHistory.length,
            lastEmailAnalysis: emailAnalysisHistory.length > 0 ? emailAnalysisHistory[emailAnalysisHistory.length - 1].timestamp : null
        };
        
    } catch (error) {
        console.error('Failed to get email stats:', error);
        return {
            emailsAnalyzed: 0,
            phishingEmails: 0,
            emailThreats: 0,
            lastEmailAnalysis: null
        };
    }
}

// Enhanced suspicious pattern detection
function containsSuspiciousPatterns(url) {
    const suspiciousPatterns = [
        /\.tk$/i,
        /\.ml$/i, 
        /\.ga$/i,
        /\.cf$/i,
        /phishing/i,
        /secure.*verify/i,
        /login.*urgent/i,
        /account.*suspend/i,
        /verify.*account/i,
        /update.*payment/i,
        /confirm.*identity/i,
        /security.*alert/i,
        /paypal.*security/i,
        /amazon.*account/i,
        /microsoft.*verify/i,
        /apple.*id.*lock/i,
        /bank.*alert/i,
        /suspicious.*activity/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
}

// Quick URL analysis for immediate threat detection
async function performQuickURLCheck(url, tabId) {
    try {
        // Check URL patterns first (instant)
        let riskScore = 0;
        let threats = [];
        
        // Domain analysis
        const domain = new URL(url).hostname;
        
        // Check for suspicious TLDs
        if (/\.(tk|ml|ga|cf|bit\.ly)$/i.test(domain)) {
            riskScore += 40;
            threats.push('suspicious_tld');
        }
        
        // Check for suspicious keywords in URL
        if (containsSuspiciousPatterns(url)) {
            riskScore += 30;
            threats.push('suspicious_keywords');
        }
        
        // Check for URL shorteners
        if (/^https?:\/\/(bit\.ly|tinyurl|t\.co|goo\.gl|short\.link)/i.test(url)) {
            riskScore += 20;
            threats.push('url_shortener');
        }
        
        // Check for suspicious subdomains
        if (/(?:secure|verify|account|login|update)-[a-z0-9-]+\./i.test(domain)) {
            riskScore += 25;
            threats.push('suspicious_subdomain');
        }
        
        // Update monitoring data
        const monitoring = activeMonitoring.get(tabId);
        if (monitoring) {
            monitoring.riskScore = riskScore;
            monitoring.quickThreats = threats;
            monitoring.quickScanComplete = true;
            activeMonitoring.set(tabId, monitoring);
        }

        // Show immediate notification ONLY for detected threats, not just risk scores
        if (threats.length > 0) {
            if (threats.includes('suspicious_tld') || riskScore >= 60) {
                console.log('🚨 Quick scan detected actual threats, showing immediate notification');
                await showThreatNotification(url, riskScore, 'immediate', threats);
            } else if (riskScore >= 40) {
                console.log('⚠️ Quick scan detected potential threats, showing notification');
                await showThreatNotification(url, riskScore, 'medium', threats);
            }
        } else {
            console.log('✅ Quick scan completed, no threats detected - no notification shown');
        }    } catch (error) {
        console.log('Quick URL check failed:', error.message);
    }
}

// Comprehensive analysis using API
async function performComprehensiveCheck(url, tabId) {
    try {
        console.log('🔍 Starting comprehensive check for:', url);
        
        const response = await fetch(
            `${MONITORING_CONFIG.apiUrl}/check_url?url=${encodeURIComponent(url)}`,
            { 
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                timeout: 10000
            }
        );
        
        console.log('📡 API response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('📊 API analysis result:', data);
            
            // Update monitoring data with API results
            const monitoring = activeMonitoring.get(tabId);
            if (monitoring) {
                monitoring.apiRiskScore = data.risk_percentage || 0;
                monitoring.apiResult = data;
                monitoring.scanStatus = 'complete';
                monitoring.finalRiskScore = Math.max(
                    monitoring.riskScore || 0, 
                    data.risk_percentage || 0
                );
                monitoring.lastCheck = Date.now();
                activeMonitoring.set(tabId, monitoring);
                
                console.log('📋 Updated monitoring data:', monitoring);
                
                // Show notification based on final risk assessment
                await evaluateAndNotify(url, monitoring, data);
            } else {
                console.warn('⚠️ No monitoring data found for tab:', tabId);
            }
        } else {
            console.error('❌ API check failed with status:', response.status);
        }
    } catch (error) {
        console.error('❌ Comprehensive check failed:', error.message);
        
        // Update monitoring with error status
        const monitoring = activeMonitoring.get(tabId);
        if (monitoring) {
            monitoring.scanStatus = 'error';
            monitoring.error = error.message;
            activeMonitoring.set(tabId, monitoring);
        }
    }
}

// Evaluate risk and show appropriate notifications
async function evaluateAndNotify(url, monitoring, apiData) {
    const finalRiskScore = monitoring.finalRiskScore || 0;
    const threats = [...(monitoring.quickThreats || [])];
    
    console.log('🎯 Evaluating and notifying:', { url, finalRiskScore, threats, apiData });
    
    // Add API-detected threats
    if (!apiData.safe) {
        threats.push('api_detected_threat');
    }
    if (apiData.reason && apiData.reason.includes('phishing')) {
        threats.push('phishing_detected');
    }
    
    console.log('📋 Final threats list:', threats);
    
    // Only show notifications for ACTUAL DETECTED THREATS, not just risk scores
    const hasRealThreats = threats.length > 0 || !apiData.safe || apiData.verdict === 'HIGH' || apiData.verdict === 'CRITICAL';
    
    if (hasRealThreats) {
        console.log('🚨 Real threats detected, determining notification level');
        
        // Determine severity based on scan results, not just risk score
        let notificationSeverity = 'medium';
        
        if (apiData.verdict === 'CRITICAL' || finalRiskScore >= 80 || threats.includes('phishing_detected')) {
            notificationSeverity = 'critical';
            console.log('🚨 Showing critical threat notification for detected threats');
        } else if (apiData.verdict === 'HIGH' || finalRiskScore >= 60 || threats.includes('suspicious_tld') || threats.includes('api_detected_threat')) {
            notificationSeverity = 'high';
            console.log('⚠️ Showing high risk notification for detected threats');
        } else if (finalRiskScore >= 40 || threats.length > 0) {
            notificationSeverity = 'medium';
            console.log('⚠️ Showing medium risk notification for detected threats');
        }
        
        // Show notification only when threats are actually detected
        await showThreatNotification(url, finalRiskScore, notificationSeverity, threats);
    } else {
        console.log('✅ No threats detected - site is safe, no notification needed');
    }
    
    // Update extension badge
    await updateExtensionBadge(finalRiskScore, monitoring.tabId || Object.keys(chrome.tabs).find(id => activeMonitoring.get(parseInt(id))?.url === url));
}

// Enhanced notification system
async function showThreatNotification(url, riskPercentage, severity, threats = []) {
    try {
        console.log('🔔 Showing notification for detected threats:', { url, riskPercentage, severity, threats });
        
        // Check user notification preferences
        const settings = await chrome.storage.local.get(['notificationSettings', 'phishingHunterSettings']);
        const notificationSettings = settings.notificationSettings || { enabled: true };
        const hunterSettings = settings.phishingHunterSettings || {};
        
        console.log('📋 Notification settings:', notificationSettings);
        console.log('📋 Hunter settings:', hunterSettings);
        
        // Check if notifications are enabled (multiple ways for compatibility)
        const notificationsEnabled = notificationSettings.enabled !== false && 
                                    hunterSettings.autoThreatAlerts !== false &&
                                    hunterSettings.showNotifications !== false;
        
        console.log('🔔 Notifications enabled check:', notificationsEnabled);
        
        if (!notificationsEnabled) {
            console.log('❌ Notifications disabled by user settings');
            return;
        }
        
        // Check if low risk notifications are disabled
        if (severity === 'low' && hunterSettings.lowRiskNotifications !== true) {
            console.log('❌ Low risk notifications disabled');
            return;
        }
        
        // Determine notification content based on severity
        let title, message, iconUrl;
        
        switch (severity) {
            case 'immediate':
            case 'critical':
                title = '🚨 CRITICAL THREAT DETECTED';
                message = `Extremely dangerous site detected! Risk: ${Math.round(riskPercentage)}%\nDo NOT enter personal information!`;
                iconUrl = 'icons/alert.png';
                break;
            case 'high':
                title = '⚠️ HIGH RISK WARNING';
                message = `Potentially dangerous site detected! Risk: ${Math.round(riskPercentage)}%\nProceed with extreme caution.`;
                iconUrl = 'icons/warning.png';
                break;
            case 'medium':
                title = '⚠️ Suspicious Activity';
                message = `Suspicious website detected. Risk: ${Math.round(riskPercentage)}%\nBe cautious with personal information.`;
                iconUrl = 'icons/warning.png';
                break;
            case 'low':
                title = '🔍 Security Notice';
                message = `Minor security concerns detected. Risk: ${Math.round(riskPercentage)}%`;
                iconUrl = 'icons/phishing.png';
                break;
            default:
                title = '🛡️ Security Scan';
                message = `Risk level: ${Math.round(riskPercentage)}%`;
                iconUrl = 'icon.png';
        }
        
        console.log('📨 Creating notification:', { title, message, iconUrl });
        
        // Create rich notification
        const notificationId = `threat_${Date.now()}`;
        await chrome.notifications.create(notificationId, {
            type: 'basic',
            iconUrl: iconUrl,
            title: title,
            message: message,
            priority: severity === 'critical' || severity === 'immediate' ? 2 : (severity === 'high' ? 1 : 0),
            requireInteraction: severity === 'critical' || severity === 'immediate' || severity === 'high'
        });
        
        console.log('✅ Notification created successfully:', notificationId);
        
        // Play sound for critical threats (if enabled)
        if ((severity === 'critical' || severity === 'immediate') && hunterSettings.criticalSounds !== false) {
            console.log('🔊 Creating audio alert notification');
            await chrome.notifications.create(`sound_${Date.now()}`, {
                type: 'basic',
                iconUrl: 'icons/alert.png',
                title: '🔊 AUDIO ALERT',
                message: 'Critical security threat detected on current page!',
                priority: 2,
                requireInteraction: true
            });
        }
        
        // Log threat for analytics
        await logThreatDetection(url, riskPercentage, severity, threats);
        
    } catch (error) {
        console.error('❌ Notification failed:', error);
        console.error('Error details:', error.message, error.stack);
    }
}

// Update extension badge with risk indicator
async function updateExtensionBadge(riskScore, tabId) {
    try {
        let badgeText = '';
        let badgeColor = '#4CAF50'; // Green for safe
        
        if (riskScore >= 80) {
            badgeText = '🚨';
            badgeColor = '#F44336'; // Red for critical
        } else if (riskScore >= 60) {
            badgeText = '⚠️';
            badgeColor = '#FF9800'; // Orange for high risk
        } else if (riskScore >= 40) {
            badgeText = '⚠';
            badgeColor = '#FFC107'; // Yellow for medium risk
        } else if (riskScore >= 20) {
            badgeText = '!';
            badgeColor = '#2196F3'; // Blue for low risk
        }
        
        await chrome.action.setBadgeText({ 
            text: badgeText,
            tabId: tabId 
        });
        
        await chrome.action.setBadgeBackgroundColor({ 
            color: badgeColor,
            tabId: tabId 
        });
        
    } catch (error) {
        console.log('Badge update failed:', error.message);
    }
}

// Log threat detection for analytics and user feedback
async function logThreatDetection(url, riskScore, severity, threats) {
    try {
        const detection = {
            url: url,
            domain: new URL(url).hostname,
            riskScore: riskScore,
            severity: severity,
            threats: threats,
            timestamp: Date.now(),
            userAgent: 'Extension Background'
        };
        
        // Store in local storage for user review
        const result = await chrome.storage.local.get(['threatLog']);
        const threatLog = result.threatLog || [];
        threatLog.unshift(detection); // Add to beginning
        
        // Keep only last 100 detections
        if (threatLog.length > 100) {
            threatLog.splice(100);
        }
        
        await chrome.storage.local.set({ threatLog });
        
        // Update statistics
        const statsResult = await chrome.storage.local.get(['detectionStats']);
        const stats = statsResult.detectionStats || {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0,
            lastThreatDetection: null
        };
        
        stats.threatsDetected++;
        stats.lastThreatDetection = Date.now();
        
        await chrome.storage.local.set({ detectionStats: stats });
        
    } catch (error) {
        console.log('Threat logging failed:', error.message);
    }
}

// Function to inject into content script for real-time monitoring
function initializeRealTimeMonitoring() {
    // This function will be injected into the content script
    if (window.phishingHunterMonitoring) return; // Already initialized
    
    window.phishingHunterMonitoring = true;
    
    // Monitor for suspicious form submissions
    document.addEventListener('submit', async (event) => {
        const form = event.target;
        if (form.tagName === 'FORM') {
            const action = form.getAttribute('action');
            const method = form.getAttribute('method') || 'GET';
            
            // Check for external form submissions with sensitive data
            if (action && !action.startsWith(window.location.origin)) {
                const hasPasswordField = form.querySelector('input[type="password"]');
                const hasSensitiveFields = form.querySelector('input[type="email"], input[name*="card"], input[name*="ssn"]');
                
                if (hasPasswordField || hasSensitiveFields) {
                    // Alert about external form submission
                    try {
                        chrome.runtime.sendMessage({
                            action: 'behaviorAlert',
                            type: 'external_sensitive_form',
                            url: window.location.href,
                            timestamp: Date.now(),
                            details: { action: action, method: method }
                        });
                    } catch (error) {
                        console.log('Failed to send form alert:', error);
                    }
                }
            }
        }
    });
    
    // Monitor for rapid redirects
    let redirectCount = 0;
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(...args) {
        redirectCount++;
        if (redirectCount > 3) {
            try {
                chrome.runtime.sendMessage({
                    action: 'behaviorAlert',
                    type: 'rapid_redirects',
                    url: window.location.href,
                    timestamp: Date.now(),
                    details: { redirectCount: redirectCount }
                });
            } catch (error) {
                console.log('Failed to send redirect alert:', error);
            }
        }
        return originalPushState.apply(this, args);
    };
    
    history.replaceState = function(...args) {
        redirectCount++;
        if (redirectCount > 3) {
            try {
                chrome.runtime.sendMessage({
                    action: 'behaviorAlert',
                    type: 'rapid_redirects',
                    url: window.location.href,
                    timestamp: Date.now(),
                    details: { redirectCount: redirectCount }
                });
            } catch (error) {
                console.log('Failed to send redirect alert:', error);
            }
        }
        return originalReplaceState.apply(this, args);
    };
    
    // Monitor for clipboard access attempts
    document.addEventListener('copy', () => {
        try {
            chrome.runtime.sendMessage({
                action: 'behaviorAlert',
                type: 'clipboard_access',
                url: window.location.href,
                timestamp: Date.now()
            });
        } catch (error) {
            console.log('Failed to send clipboard alert:', error);
        }
    });
    
    // Monitor for suspicious key combinations
    let keySequence = [];
    document.addEventListener('keydown', (event) => {
        keySequence.push(event.key);
        if (keySequence.length > 10) {
            keySequence.shift();
        }
        
        // Check for suspicious key patterns (rapid typing that might be automated)
        if (keySequence.length >= 5) {
            const timings = [];
            const now = Date.now();
            if (keySequence.every((key, index) => {
                if (index === 0) return true;
                timings.push(now - (keySequence.length - index) * 50); // Estimate timing
                return timings[timings.length - 1] < 100; // Very fast typing
            })) {
                try {
                    chrome.runtime.sendMessage({
                        action: 'behaviorAlert',
                        type: 'rapid_typing',
                        url: window.location.href,
                        timestamp: Date.now()
                    });
                } catch (error) {
                    console.log('Failed to send typing alert:', error);
                }
            }
        }
    });
    
    console.log('🛡️ Real-time phishing monitoring initialized');
}

// Handle user feedback storage and processing
async function handleUserFeedback(feedback, sendResponse) {
    try {
        // Get existing feedback data
        const result = await chrome.storage.local.get(['phishingHunterFeedback']);
        const feedbackList = result.phishingHunterFeedback || [];
        
        // Add new feedback with timestamp
        feedback.id = Date.now().toString();
        feedback.processed = false;
        feedbackList.push(feedback);
        
        // Store updated feedback
        await chrome.storage.local.set({ phishingHunterFeedback: feedbackList });
        
        // Update stats
        const statsResult = await chrome.storage.local.get(['detectionStats']);
        const stats = statsResult.detectionStats || {
            totalAnalyses: 0,
            threatsDetected: 0,
            falsePositives: 0
        };
        
        if (feedback.response === 'incorrect') {
            stats.falsePositives++;
        }
        
        await chrome.storage.local.set({ detectionStats: stats });
        
        sendResponse({ success: true, id: feedback.id });
        
        console.log('User feedback stored:', feedback.type, 'for', feedback.url);
        
    } catch (error) {
        console.error('Failed to handle user feedback:', error);
        sendResponse({ success: false, error: error.message });
    }
}

// Listen for tab updates to ensure content script is injected on Gmail
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        const url = new URL(tab.url);
        if (url.hostname.includes('mail.google.com') || 
            url.hostname.includes('outlook.live.com') || 
            url.hostname.includes('mail.yahoo.com')) {
            
            console.log('📧 Email provider detected, ensuring content script is injected:', url.hostname);
            
            // Inject content script if not already present
            chrome.scripting.executeScript({
                target: { tabId: tabId },
                files: ['content_script.js']
            }).then(() => {
                console.log('✅ Content script injected on email provider:', url.hostname);
            }).catch((error) => {
                console.log('ℹ️ Content script already present or injection failed:', error.message);
            });
        }
    }
});

console.log('🚀 Enhanced Phishing Hunter Background Script Loaded');
