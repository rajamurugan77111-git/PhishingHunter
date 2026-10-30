/**
 * Content Script for Enhanced Phishing Detection
 * Analyzes page source code for phishing indicators with advanced detection
 * Integrates with background monitoring and user feedback system
 */

// Define comprehensive suspicious patterns with improved accuracy
const SUSPICIOUS_PATTERNS = {
    // More specific obfuscated JavaScript patterns (reduce false positives)
    obfuscatedJS: /eval\s*\(\s*(['"][^'"]{50,}['"]|[a-zA-Z_$][a-zA-Z0-9_$]*\s*\+\s*[a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)|String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){10,}\s*\)|\\x[0-9a-f]{2}[^'"]*\\x[0-9a-f]{2}[^'"]*\\x[0-9a-f]{2}/i,
    
    // Hidden elements - be more specific to avoid false positives
    hiddenElements: /style\s*=\s*["'][^"']*(?:display\s*:\s*none[^"']*(?:position\s*:\s*absolute|z-index\s*:\s*-?\d+)|visibility\s*:\s*hidden[^"']*(?:position\s*:\s*absolute|z-index\s*:\s*-?\d+))[^"']*/i,
    
    // Password fields in hidden elements (credential theft) - more specific
    passwordFieldsInHiddenElements: /<input[^>]*type\s*=\s*["']password["'][^>]*style\s*=\s*["'][^"']*(?:visibility\s*:\s*hidden|display\s*:\s*none|opacity\s*:\s*0)[^"']*["']/i,
    
    // Forms that submit to external domains - improved to avoid false positives
    externalForms: /<form[^>]*action\s*=\s*["']https?:\/\/(?!(?:www\.)?(?:google|microsoft|apple|amazon|github|stackoverflow|youtube|paypal|ebay)\.com)[^"']*\.(?:tk|ml|ga|cf|bit\.ly)["']/i,
    
    // Suspicious script sources - more targeted
    suspiciousScripts: /<script[^>]*src\s*=\s*["'](?:data:text\/javascript[^"']{100,}|[^"']*\.(?:tk|ml|ga|cf)\/[^"']*\.js)/i,
    
    // Multiple redirects or meta refresh to suspicious domains
    metaRefresh: /<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*[^"']*\.(?:tk|ml|ga|cf)/i,
    
    // Suspicious iframes - more specific
    suspiciousIframes: /<iframe[^>]*src\s*=\s*["'](?:javascript:[^"']{20,}|data:[^"']{100,}|[^"']*\.(?:tk|ml|ga|cf))/i,
    
    // Long encoded strings (possible malware) - higher threshold
    longEncodedStrings: /(?:eval|atob)\s*\(\s*["'][A-Za-z0-9+\/=]{500,}["']\s*\)/i,
    
    // Keylogger patterns - more specific to avoid false positives
    keyloggerPatterns: /(?:document\.addEventListener|window\.addEventListener)\s*\(\s*["'](?:keydown|keyup|keypress)["'][^)]*(?:keyCode|which|charCode)[^)]*\)[^;]*(?:send|post|ajax|fetch)/i,
    
    // Cookie stealing patterns - more specific
    cookieTheft: /document\.cookie\s*\+\s*=\s*["'][^"']*(?:session|auth|token|login)["']|document\.cookie\.match\([^)]*\)\.(?:send|post)/i
};

// Legitimate brand patterns for false positive reduction
const LEGITIMATE_PATTERNS = {
    // Known legitimate domains - expanded list
    legitimateDomains: /^(?:https?:\/\/)?(?:(?:www|mail|drive|docs|maps|photos|play|store|support|developer|cloud|workspace)\.)?(?:google|youtube|facebook|twitter|instagram|linkedin|microsoft|apple|amazon|netflix|github|stackoverflow|reddit|wikipedia|paypal|ebay|adobe|dropbox|spotify|zoom|slack|discord|whatsapp|telegram|mozilla|chrome|firefox|edge|safari)\.(?:com|org|net|edu|gov)(?:\/|$)/i,
    
    // Common legitimate JavaScript libraries and frameworks
    legitimateLibraries: /(?:jquery|bootstrap|react|angular|vue|lodash|moment|axios|socket\.io|chartjs|d3|three|gsap|typescript|babel|webpack|rollup|vite)[\.\-]/i,
    
    // Common CDN patterns - expanded
    legitimateCDNs: /(?:cdnjs\.cloudflare\.com|unpkg\.com|jsdelivr\.net|ajax\.googleapis\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|fonts\.googleapis\.com|apis\.google\.com)/i,
    
    // Common legitimate analytics and tracking (not malicious)
    legitimateTracking: /(?:google-analytics\.com|googletagmanager\.com|doubleclick\.net|googlesyndication\.com|gstatic\.com)/i
};

// Risk scoring weights
const RISK_WEIGHTS = {
    obfuscatedJS: 25,
    hiddenElements: 15,
    passwordFieldsInHiddenElements: 40,
    externalForms: 30,
    suspiciousScripts: 20,
    metaRefresh: 15,
    suspiciousIframes: 20,
    longEncodedStrings: 35,
    keyloggerPatterns: 45,
    cookieTheft: 35
};

// Global variables
let analysisResults = {
    threatIndicators: [],
    riskScore: 0,
    isLegitimate: false,
    brandName: null,
    threatDetails: {}
};

let pageLoadTime = Date.now();
let monitoringActive = false;
let formSubmissionAttempts = 0;
let userInteractionCount = 0;

// Content Script for Email Phishing Detection
// Automatically detects email composition and extracts content

(function() {
    'use strict';
    
    console.log('🔍 Email Phishing Detection Content Script Loaded');
    console.log('📍 Current URL:', window.location.href);
    console.log('📍 Hostname:', window.location.hostname);
    
 
    // Configuration
    const EMAIL_DETECTION_CONFIG = {
        // Gmail selectors - Updated for current Gmail interface (2024)
        gmail: {
            composeButton: '[data-tooltip="Compose"], [aria-label="Compose"], .T-I.T-I-KE, button[aria-label*="Compose"], [role="button"][aria-label*="Compose"]',
            subjectField: 'input[name="subjectbox"], input[placeholder*="Subject"], input[aria-label*="Subject"], .aoD.az6 input[name="subjectbox"], [data-test-id="compose-subject"], .subject-input',
            bodyField: 'div[role="textbox"], div[contenteditable="true"], .Am.Al.editable, .editable[contenteditable="true"], [data-test-id="compose-body"], .rn_editor, .DShyMc-AHe6Kc-OiiCO',
            sendButton: 'div[data-tooltip="Send"], [aria-label="Send"], .T-I.J-J5-Ji.aoO.T-I-atl.L3, button[aria-label*="Send"], [role="button"][aria-label*="Send"]',
            recipientField: 'input[name="to"], input[placeholder*="To"], input[aria-label*="To"], .aoD.az6 input[name="to"], [data-test-id="compose-to"]',
            // Enhanced Gmail reading selectors for better content extraction (avoiding UI elements)
            readingSubject: [
                'h2.hP', 'h2.bog', 'h2[data-thread-id]', '.ha h2', '[role="main"] h2', 
                '.subject-line', '.hP', '.bog', 'h1', 'h2', 'h3',
                '[data-legacy-message-id] h2', '.message-subject', '.email-subject'
            ].join(', '),
            readingBody: [
                // Primary content selectors - actual email body based on provided HTML structure
                'div.a3s.aiL div[dir="ltr"]', 'div.a3s.aiL div[dir="rtl"]', 'div.a3s.aiL div[dir]',
                '.a3s.aiL:not(.undefined)', '.ii.gt .a3s.aiL:not(.undefined)', 
                '.AdL .a3s', '[data-message-id] .a3s:not(.undefined)', 
                // More specific selectors to avoid UI
                '.a3s:not(.undefined):not([class*="button"]):not([class*="toolbar"])', 
                '.ii.gt:not([class*="toolbar"]) .a3s', 
                // Message content specific
                '.msgBody .a3s', '.message-body .a3s', '.email-content .a3s',
                // Content with direction attributes (actual email content)
                '[data-legacy-message-id] .a3s:not(.undefined)', 
                '[data-message-id] div[dir]:not([class*="button"]):not([class*="toolbar"])',
                '.message-content div[dir]:not([class*="ui"]):not([class*="button"])', 
                '.email-body div[dir]:not([class*="control"])',
                // Main content areas
                '[role="main"] div[dir]:not([class*="toolbar"]):not([class*="button"]):not([class*="header"])',
                // Fallback to general content but exclude known UI containers
                '.a3s:not([class*="toolbar"]):not([class*="button"]):not([class*="header"]):not(.undefined)'
            ].join(', '),
            readingSender: [
                '.go .g2', '.gD', '[email]', '[data-hovercard-id]', 
                '.qu .go span[email]', '.sender', '.from', '.sender-info', 
                '.from-address', '.email-sender', '[data-sender]'
            ].join(', '),
            emailThread: '.nH.if, [data-thread-id], .Cp .aDM, .thread, .message-thread, [role="main"], .email-thread, .conversation',
            messageContainer: '.adn.ads, .ii.gt, [data-message-id], .message, .msg, [role="main"] .a3s, .message-content, .email-message, .msg-container'
        },
        // Outlook selectors - Enhanced for better compatibility
        outlook: {
            composeButton: '[aria-label="New mail"], .ms-Button--primary, [data-automation-id="newMailButton"], [title*="New"], [title*="Compose"]',
            subjectField: 'input[aria-label*="Subject"], input[name="subject"], .ms-TextField-input, [placeholder*="Subject"], [data-automation-id="subject"]',
            bodyField: 'div[role="textbox"], div[contenteditable="true"], .ms-Editor-outer, [data-automation-id="bodyEditor"], .editor-content',
            sendButton: '[aria-label="Send"], [data-automation-id="sendButton"], .ms-Button--primary, [title*="Send"]',
            recipientField: 'input[aria-label*="To"], input[name="to"], .ms-TextField-input, [placeholder*="To"], [data-automation-id="to"]',
            readingSubject: '.subject, .message-subject, [data-automation-id="subject"], h1, h2, h3',
            readingBody: '.message-body, .email-body, [data-automation-id="body"], .body-content, [role="main"]',
            readingSender: '.sender, .from, [data-automation-id="from"], .sender-info'
        },
        // Yahoo Mail selectors - Enhanced
        yahoo: {
            composeButton: '[aria-label="Compose"], .btn-compose, [data-test-id="compose-button"], [title*="Compose"], [title*="New"]',
            subjectField: 'input[name="subject"], input[placeholder*="Subject"], [data-test-id="subject"], [aria-label*="Subject"]',
            bodyField: 'div[contenteditable="true"], .editor-content, [data-test-id="compose-body"], [role="textbox"], .compose-body',
            sendButton: '[aria-label="Send"], .btn-send, [data-test-id="send-button"], [title*="Send"]',
            recipientField: 'input[name="to"], input[placeholder*="To"], [data-test-id="to"], [aria-label*="To"]',
            readingSubject: '.subject, .message-subject, h1, h2, h3, .email-subject',
            readingBody: '.message-body, .email-body, .body-content, [role="main"], .msg-body',
            readingSender: '.sender, .from, .sender-info, .from-address'
        },
        // ProtonMail selectors
        protonmail: {
            composeButton: '[data-testid="sidebar:compose"], .button--primary, [title*="Compose"]',
            subjectField: '[data-testid="composer:subject"], input[placeholder*="Subject"]',
            bodyField: '[data-testid="rooster-editor"], .editor-content, [contenteditable="true"]',
            sendButton: '[data-testid="composer:send-button"], .button--primary',
            recipientField: '[data-testid="composer:to"], input[placeholder*="To"]'
        },
        // Generic email selectors - Enhanced fallback
        generic: {
            composeButton: [
                'button[title*="compose"]', 'button[title*="new"]', '.compose', '.new-mail',
                '[aria-label*="Compose"]', '[aria-label*="New"]', '.btn-compose',
                'a[href*="compose"]', 'button[data-action="compose"]'
            ].join(', '),
            subjectField: [
                'input[name="subject"]', 'input[placeholder*="subject" i]', 'input[title*="subject" i]',
                'input[aria-label*="subject" i]', '.subject-input', '[data-field="subject"]'
            ].join(', '),
            bodyField: [
                'textarea[name="body"]', 'div[contenteditable="true"]', '.email-body',
                '[role="textbox"]', '.editor-content', '.compose-body', '.message-body',
                'iframe[title*="editor" i]', '.wysiwyg-editor'
            ].join(', '),
            sendButton: [
                'button[title*="send" i]', 'button[type="submit"]', '.send-button',
                '[aria-label*="Send"]', '.btn-send', 'input[value*="Send" i]'
            ].join(', '),
            recipientField: [
                'input[name="to"]', 'input[placeholder*="to" i]', 'input[title*="to" i]',
                'input[aria-label*="to" i]', '.to-field', '[data-field="to"]'
            ].join(', '),
            readingSubject: 'h1, h2, h3, .subject, .email-subject, .message-subject, .title',
            readingBody: '.message-body, .email-body, .body-content, [role="main"], .content, .msg-body',
            readingSender: '.sender, .from, .sender-info, .from-address, .email-sender'
        }
    };
    
    // Email detection state
    let emailDetectionState = {
        isComposing: false,
        isReading: false,
        currentEmailData: null,
        detectedProvider: null,
        lastScanTime: 0,
        scanInterval: null
    };
    
    // Debug function to check email detection status
    function debugEmailDetection() {
        console.log('🔍 EMAIL DETECTION DEBUG REPORT');
        console.log('================================');
        
        console.log('📍 Current Page:', window.location.href);
        console.log('🏠 Hostname:', window.location.hostname);
        console.log('📧 Detected Provider:', emailDetectionState.detectedProvider);
        console.log('✍️ Is Composing:', emailDetectionState.isComposing);
        console.log('👁️ Is Reading:', emailDetectionState.isReading);
        console.log('📄 Has Email Data:', emailDetectionState.currentEmailData !== null);
        
        if (emailDetectionState.currentEmailData) {
            console.log('📧 Current Email Data:', emailDetectionState.currentEmailData);
        }
        
        // Check if we can find email elements
        const provider = emailDetectionState.detectedProvider;
        if (provider && EMAIL_DETECTION_CONFIG[provider]) {
            const selectors = EMAIL_DETECTION_CONFIG[provider];
            console.log('🔍 Checking Email Elements:');
            
            // Check composition elements
            console.log('  📝 Composition Elements:');
            ['composeButton', 'subjectField', 'bodyField', 'recipientField'].forEach(fieldType => {
                if (selectors[fieldType]) {
                    const elements = document.querySelectorAll(selectors[fieldType]);
                    console.log(`    ${fieldType}: ${elements.length} elements found`);
                }
            });
            
            // Check reading elements
            console.log('  👁️ Reading Elements:');
            ['readingSubject', 'readingBody', 'readingSender', 'emailThread', 'messageContainer'].forEach(fieldType => {
                if (selectors[fieldType]) {
                    const elements = document.querySelectorAll(selectors[fieldType]);
                    console.log(`    ${fieldType}: ${elements.length} elements found`);
                }
            });
        }
        
        // Force email detection check
        console.log('🔍 Force checking for email content...');
        forceEmailDetection();
        
        console.log('================================');
    }
    
    // Force email detection - manually trigger content extraction
    function forceEmailDetection() {
        console.log('🚀 Force email detection triggered');
        
        // Reset detection state
        emailDetectionState.isComposing = false;
        emailDetectionState.isReading = false;
        emailDetectionState.currentEmailData = null;
        
        // Force a fresh detection
        setTimeout(() => {
            checkForEmailComposition(document.body);
        }, 100);
        
        // Try to extract content immediately with multiple strategies
        console.log('🔍 Strategy 1: Try reading email extraction...');
        const readingContent = extractReadingEmailContent();
        if (readingContent && readingContent.content && readingContent.content.length > 10) {
            emailDetectionState.isReading = true;
            emailDetectionState.currentEmailData = readingContent;
            console.log('✅ Force detection successful - Reading email:', readingContent);
            return readingContent;
        }
        
        console.log('🔍 Strategy 2: Try composition email extraction...');
        const composeContent = extractEmailContent();
        if (composeContent && composeContent.content && composeContent.content.length > 10) {
            emailDetectionState.isComposing = true;
            emailDetectionState.currentEmailData = composeContent;
            console.log('✅ Force detection successful - Composing email:', composeContent);
            return composeContent;
        }
        
        console.log('🔍 Strategy 3: Try page analysis as fallback...');
        const pageContent = analyzePageForEmailContent();
        if (pageContent && pageContent.content && pageContent.content.length > 10) {
            emailDetectionState.isReading = true;
            emailDetectionState.currentEmailData = pageContent;
            console.log('✅ Force detection successful - Page analysis:', pageContent);
            return pageContent;
        }
        
        console.log('🔍 Strategy 4: Try manual DOM traversal...');
        const manualContent = extractEmailContentManually();
        if (manualContent && manualContent.content && manualContent.content.length > 10) {
            emailDetectionState.isReading = true;
            emailDetectionState.currentEmailData = manualContent;
            console.log('✅ Force detection successful - Manual extraction:', manualContent);
            return manualContent;
        }
        
        console.log('❌ Force detection failed - no email content found with any strategy');
        return null;
    }
    
    // NEW: Force refresh email detection with page analysis
    function forceRefreshEmailDetection() {
        console.log('🔄 Force refreshing email detection...');
        
        // Clear any cached data
        emailDetectionState.currentEmailData = null;
        
        // Analyze the entire page for email content
        const pageAnalysis = analyzePageForEmailContent();
        
        if (pageAnalysis) {
            emailDetectionState.currentEmailData = pageAnalysis;
            emailDetectionState.isReading = true;
            emailDetectionState.isComposing = false;
            console.log('✅ Page analysis successful:', pageAnalysis);
            return pageAnalysis;
        }
        
        console.log('❌ Page analysis failed - no email content found');
        return null;
    }
    
    // NEW: Analyze entire page for email content
    function analyzePageForEmailContent() {
        console.log('🔍 Analyzing entire page for email content...');
        
        // Get all text content from the page
        const pageText = document.body.textContent || '';
        
        // Look for email patterns
        const emailPatterns = [
            /Subject:\s*(.+?)(?:\n|$)/i,
            /From:\s*(.+?)(?:\n|$)/i,
            /To:\s*(.+?)(?:\n|$)/i,
            /Date:\s*(.+?)(?:\n|$)/i
        ];
        
        let subject = '';
        let sender = '';
        let content = '';
        
        // Extract subject
        const subjectMatch = pageText.match(emailPatterns[0]);
        if (subjectMatch) {
            subject = subjectMatch[1].trim();
            console.log('✅ Subject found in page text:', subject);
        }
        
        // Extract sender
        const senderMatch = pageText.match(emailPatterns[1]);
        if (senderMatch) {
            sender = senderMatch[1].trim();
            console.log('✅ Sender found in page text:', sender);
        }
        
        // Extract content by finding the main text after headers
        const lines = pageText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        
        // Find where the actual email content starts (after headers)
        let contentStartIndex = 0;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.length > 30 && 
                !line.includes('Subject:') && 
                !line.includes('From:') && 
                !line.includes('To:') && 
                !line.includes('Date:') &&
                !line.includes('@') &&
                !line.includes('http')) {
                contentStartIndex = i;
                break;
            }
        }
        
        // Extract content from the start point
        if (contentStartIndex < lines.length) {
            const contentLines = lines.slice(contentStartIndex);
            content = contentLines.join('\n').substring(0, 3000);
            console.log('✅ Content extracted from page text, length:', content.length);
        }
        
        // Only return if we have meaningful content
        if (subject || (content && content.length > 50) || sender) {
            return {
                subject: subject || 'No subject',
                sender: sender || 'Unknown sender',
                content: content || 'No content available',
                isReading: true,
                timestamp: Date.now(),
                source: 'page_analysis'
            };
        }
        
        return null;
    }
    
    // Initialize email detection
    function initializeEmailDetection() {
        console.log('🚀 Initializing Email Detection...');
        
        // Detect email provider
        detectEmailProvider();
        
        // Set up mutation observer for dynamic content
        setupMutationObserver();
        
        // Set up event listeners
        setupEventListeners();
        
        // Start monitoring
        startEmailMonitoring();
        
        console.log('✅ Email Detection Initialized');
        
        // Add debug report after 2 seconds to let page load
        setTimeout(() => {
            debugEmailDetection();
        }, 2000);
    }
    
    // Detect which email provider we're on
    function detectEmailProvider() {
        const hostname = window.location.hostname.toLowerCase();
        
        if (hostname.includes('gmail.com') || hostname.includes('mail.google.com')) {
            emailDetectionState.detectedProvider = 'gmail';
            console.log('📧 Detected Gmail');
        } else if (hostname.includes('outlook.com') || hostname.includes('mail.live.com') || hostname.includes('office365.com')) {
            emailDetectionState.detectedProvider = 'outlook';
            console.log('📧 Detected Outlook');
        } else if (hostname.includes('yahoo.com') || hostname.includes('mail.yahoo.com')) {
            emailDetectionState.detectedProvider = 'yahoo';
            console.log('📧 Detected Yahoo Mail');
        } else {
            emailDetectionState.detectedProvider = 'generic';
            console.log('📧 Detected Generic Email Provider');
        }
    }
    
    // Extract email content when reading emails - COMPLETELY REWRITTEN for better accuracy
    function extractReadingEmailContent() {
        const provider = emailDetectionState.detectedProvider;
        if (!provider || !EMAIL_DETECTION_CONFIG[provider]) {
            console.log('❌ No provider detected or provider not supported');
            return null;
        }
        
        const selectors = EMAIL_DETECTION_CONFIG[provider];
        
        try {
            console.log('🔍 Starting email content extraction for provider:', provider);
            
            // For Gmail, use a more comprehensive approach
            if (provider === 'gmail') {
                return extractGmailReadingContent();
            }
            
            // For other providers, use the standard approach
            return extractGenericReadingContent(selectors);
            
        } catch (error) {
            console.error('❌ Error extracting reading email content:', error);
            return null;
        }
    }
    
    // NEW: Specialized Gmail reading content extraction
    function extractGmailReadingContent() {
        console.log('🔍 Extracting Gmail reading content...');
        
        // Check if we're actually on a Gmail page
        if (!window.location.hostname.includes('mail.google.com')) {
            console.log('❌ Not on Gmail page');
            return null;
        }
        
        // Look for the main content area
        const mainContent = document.querySelector('[role="main"]');
        if (!mainContent) {
            console.log('❌ No main content area found');
            return null;
        }
        
        console.log('✅ Main content area found');
        
        // Extract subject using multiple strategies
        let subject = extractGmailSubject(mainContent);
        console.log('📧 Subject extracted:', subject);
        
        // Extract sender using multiple strategies
        let sender = extractGmailSender(mainContent);
        console.log('👤 Sender extracted:', sender);
        
        // Extract body content using multiple strategies
        let content = extractGmailBody(mainContent);
        console.log('📝 Content length:', content ? content.length : 0);
        
        // Validate that we have meaningful content
        if (!subject && !content && !sender) {
            console.log('❌ No meaningful content found');
            return null;
        }
        
        // Clean up the content
        if (content) {
            content = cleanGmailContent(content, subject, sender);
        }
        
        const result = {
            subject: subject || 'No subject',
            sender: sender || 'Unknown sender',
            content: content || 'No content available',
            isReading: true,
            timestamp: Date.now()
        };
        
        console.log('✅ Gmail content extraction complete:', {
            subject: result.subject,
            sender: result.sender,
            contentLength: result.content.length,
            contentPreview: result.content.substring(0, 100) + '...'
        });
        
        return result;
    }
    
    // NEW: Extract Gmail subject with multiple fallback strategies
    function extractGmailSubject(mainContent) {
        const subjectSelectors = [
            'h2.hP', 'h2.bog', 'h2[data-thread-id]', '.ha h2', 
            '[role="main"] h2', '.subject-line', '.hP', '.bog',
            'h1', 'h2', 'h3', '[data-thread-id] h2', '.thread-subject',
            // Additional modern Gmail selectors
            '[data-legacy-message-id] h2', '.hP', '.bog', '.subject',
            '[role="main"] h1', '[role="main"] h2', '[role="main"] h3',
            '.thread-subject', '.message-subject', '.email-subject',
            // Look for any heading in the main area
            '[role="main"] [role="heading"]', '[role="main"] h1, [role="main"] h2, [role="main"] h3'
        ];
        
        for (const selector of subjectSelectors) {
            const elements = mainContent.querySelectorAll(selector);
            for (const el of elements) {
                const text = el.textContent?.trim();
                if (text && text.length > 3 && text.length < 300) {
                    console.log('✅ Subject found with selector:', selector, 'Text:', text);
                    return text;
                }
            }
        }
        
        // Fallback: look for any text that looks like a subject
        const allText = mainContent.textContent || '';
        const lines = allText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        
        for (const line of lines) {
            if (line.length > 5 && line.length < 200 && 
                !line.includes('@') && !line.includes('http') && 
                !line.includes('From:') && !line.includes('To:') &&
                !line.includes('Date:') && !line.includes('Subject:') &&
                !line.includes('Gmail') && !line.includes('Inbox') &&
                !line.includes('Compose') && !line.includes('Search')) {
                console.log('✅ Subject found in text lines:', line);
                return line;
            }
        }
        
        return '';
    }
    
    // NEW: Extract Gmail sender with multiple fallback strategies
    function extractGmailSender(mainContent) {
        const senderSelectors = [
            '.go .g2', '.gD', '[email]', '[data-hovercard-id]', 
            '.qu .go span[email]', '.gD', '.go', '[data-hovercard-id]', 
            '.sender', '.from', '.gD', '.go', '.sender-info', '.from-address'
        ];
        
        for (const selector of senderSelectors) {
            const elements = mainContent.querySelectorAll(selector);
            for (const el of elements) {
                const email = el.getAttribute('email') || el.textContent?.trim();
                if (email && email.includes('@')) {
                    console.log('✅ Sender found with selector:', selector, 'Email:', email);
                    return email;
                }
            }
        }
        
        // Fallback: look for email patterns in the content
        const allText = mainContent.textContent || '';
        const emailMatch = allText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (emailMatch) {
            console.log('✅ Sender found with email pattern:', emailMatch[0]);
            return emailMatch[0];
        }
        
        return '';
    }
    
    // Enhanced Gmail body extraction with improved UI filtering
    function extractGmailBody(mainContent) {
        const bodySelectors = [
            // Most specific selectors first - actual email content based on the provided HTML structure
            'div.a3s.aiL div[dir="ltr"]', 
            'div.a3s.aiL div[dir="rtl"]',
            'div.a3s.aiL div[dir]',
            '.a3s.aiL:not(.undefined)', 
            '[data-message-id] .a3s:not(.undefined):not([class*="toolbar"])', 
            '.AdL .a3s:not(.undefined)', 
            // Content with direction attributes (actual email text)
            '.ii.gt div[dir]:not([class*="toolbar"]):not([class*="button"]):not([id*="toolbar"])',
            '[data-message-id] div[dir]:not([class*="button"]):not([class*="toolbar"])',
            // More general but filtered
            '.a3s:not(.undefined):not([class*="toolbar"]):not([class*="button"]):not([class*="header"])',
            '.ii.gt:not([class*="toolbar"]) .a3s', 
            '[role="main"] .a3s:not(.undefined)', 
            '.msgBody', '.message-body', '.email-content'
        ];
        
        let content = '';
        
        // Try each selector with enhanced filtering
        for (const selector of bodySelectors) {
            try {
                const elements = mainContent.querySelectorAll(selector);
                if (elements.length > 0) {
                    const validTexts = [];
                    
                    elements.forEach(el => {
                        // Get the text content, preserving some formatting
                        let text = extractTextWithFormatting(el);
                        text = cleanTextContent(text);
                        
                        if (text && text.length > 10) {
                            // Enhanced filtering for Gmail UI elements
                            if (isValidEmailContent(text)) {
                                validTexts.push(text);
                            }
                        }
                    });
                    
                    if (validTexts.length > 0) {
                        content = validTexts.join('\n\n');
                        console.log('✅ Gmail body found with selector:', selector, 'Length:', content.length);
                        break;
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with Gmail body selector:', selector, e);
            }
        }
        
        // If no content found with selectors, try to extract from main content
        if (!content || content.length < 20) {
            content = extractFromMainContentFiltered(mainContent);
        }
        
        // If still no content, try a more aggressive approach
        if (!content || content.length < 20) {
            content = extractFromMainContentAggressive(mainContent);
        }
        
        return content;
    }

    // Extract text while preserving some formatting (like line breaks)
    function extractTextWithFormatting(element) {
        if (!element) return '';
        
        // Clone the element to avoid modifying the original
        const clone = element.cloneNode(true);
        
        // Replace <br> tags with newlines
        const brTags = clone.querySelectorAll('br');
        brTags.forEach(br => {
            br.replaceWith('\n');
        });
        
        // Replace <div> and <p> tags with newlines if they contain content
        const blockElements = clone.querySelectorAll('div, p');
        blockElements.forEach(block => {
            if (block.textContent.trim()) {
                block.insertAdjacentText('afterend', '\n');
            }
        });
        
        // Remove unwanted elements (like images, unless they're important)
        const unwantedElements = clone.querySelectorAll('img:not([alt*="🔗"]):not([data-emoji]), script, style, .adL');
        unwantedElements.forEach(el => el.remove());
        
        return clone.textContent || clone.innerText || '';
    }

    // Check if text is valid email content (not UI elements)
    function isValidEmailContent(text) {
        if (!text || text.length < 10) return false;
        
        const lowerText = text.toLowerCase().trim();
        
        // Gmail UI patterns to exclude
        const gmailUIPatterns = [
            // Action buttons and controls
            /^(reply|forward|archive|delete|spam|important|starred|add reaction)$/,
            /^(print all|in new window|show original|show trimmed content)$/,
            /^(mark as read|mark as unread|more actions|labels|move to)$/,
            
            // Timestamp and metadata patterns
            /^\d{1,2}:\d{2}\s*(am|pm)\s*\(\d+\s*(minute|hour|day)s?\s*ago\)$/,
            /^(to me|cc:|bcc:)$/,
            /^(show details|hide details|translate message)$/,
            
            // Navigation and Gmail branding
            /^(gmail|inbox|compose|sent|drafts|search|settings|help)$/,
            /^(sign out|account|menu|navigation|toolbar)$/
        ];
        
        // Check against UI patterns
        const isUIPattern = gmailUIPatterns.some(pattern => pattern.test(lowerText));
        if (isUIPattern) {
            console.log('🚫 Filtered UI pattern:', text.substring(0, 30) + '...');
            return false;
        }
        
        // Check for repetitive UI text (like "Reply Forward" repeated)
        const words = lowerText.split(/\s+/);
        if (words.length < 3 && words.every(word => 
            ['reply', 'forward', 'archive', 'delete', 'print', 'all', 'new', 'window', 'reaction', 'add'].includes(word)
        )) {
            console.log('🚫 Filtered repetitive UI text:', text);
            return false;
        }
        
        // Check if it's just Gmail metadata
        if (lowerText.includes('to me') && lowerText.length < 50) {
            return false;
        }
        
        // Check for email content indicators (positive signals)
        const emailIndicators = [
            'dear', 'hello', 'hi', 'regards', 'sincerely', 'thank you', 'please',
            'urgent', 'important', 'account', 'verify', 'click', 'link', 'password',
            'security', 'suspended', 'confirm', 'update', 'login'
        ];
        
        const hasEmailIndicators = emailIndicators.some(indicator => 
            lowerText.includes(indicator)
        );
        
        // If text is longer than 50 chars or has email indicators, it's likely valid content
        return text.length > 50 || hasEmailIndicators;
    }

    // Extract content from main area with better filtering
    function extractFromMainContentFiltered(mainContent) {
        console.log('🔄 Trying filtered main content extraction...');
        
        const allElements = mainContent.querySelectorAll('div, p, span');
        const contentCandidates = [];
        
        for (const el of allElements) {
            const text = cleanTextContent(el.textContent || '');
            
            if (text && text.length > 30 && text.length < 5000) {
                if (isValidEmailContent(text)) {
                    contentCandidates.push({
                        text: text,
                        score: calculateContentScore(text),
                        element: el.tagName
                    });
                }
            }
        }
        
        if (contentCandidates.length > 0) {
            // Sort by score and get the best content
            contentCandidates.sort((a, b) => b.score - a.score);
            const bestContent = contentCandidates[0].text.substring(0, 3000);
            console.log('✅ Filtered main content extracted, length:', bestContent.length);
            return bestContent;
        }
        
        return '';
    }
    
    // NEW: Extract content from main content area as fallback
    function extractFromMainContent(mainContent) {
        console.log('🔄 Trying to extract from main content area...');
        
        const mainText = mainContent.textContent?.trim() || '';
        if (mainText.length < 50) {
            return '';
        }
        
        // Split into lines and find the main content
        const lines = mainText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        
        // Find the start of the main email content (after headers)
        let contentStartIndex = 0;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.length > 20 && 
                !line.includes('@') && 
                !line.includes('http') && 
                !line.includes('From:') && 
                !line.includes('To:') && 
                !line.includes('Date:') && 
                !line.includes('Subject:')) {
                contentStartIndex = i;
                break;
            }
        }
        
        // Extract content from the start point
        const contentLines = lines.slice(contentStartIndex);
        const content = contentLines.join('\n').substring(0, 3000); // Limit to 3000 chars
        
        console.log('✅ Content extracted from main area, length:', content.length);
        return content;
    }
    
    // NEW: More aggressive content extraction
    function extractFromMainContentAggressive(mainContent) {
        console.log('🔄 Trying aggressive content extraction...');
        
        // Look for any element with substantial text content
        const allElements = mainContent.querySelectorAll('*');
        const contentCandidates = [];
        
        for (const el of allElements) {
            const text = el.textContent?.trim();
            if (text && text.length > 100 && text.length < 10000) {
                // Skip navigation and UI elements
                if (!text.includes('Gmail') && !text.includes('Inbox') && 
                    !text.includes('Compose') && !text.includes('Search') &&
                    !text.includes('Sent') && !text.includes('Drafts') &&
                    !text.includes('Settings') && !text.includes('Help')) {
                    
                    // Check if this looks like email content
                    const lines = text.split('\n');
                    const meaningfulLines = lines.filter(line => 
                        line.length > 20 && 
                        !line.includes('@') && 
                        !line.includes('http') &&
                        !line.includes('From:') && 
                        !line.includes('To:') && 
                        !line.includes('Date:') && 
                        !line.includes('Subject:')
                    );
                    
                    if (meaningfulLines.length > 2) {
                        contentCandidates.push({
                            text: text,
                            score: meaningfulLines.length * meaningfulLines.reduce((sum, line) => sum + line.length, 0)
                        });
                    }
                }
            }
        }
        
        // Sort by score and pick the best candidate
        if (contentCandidates.length > 0) {
            contentCandidates.sort((a, b) => b.score - a.score);
            const bestContent = contentCandidates[0].text.substring(0, 3000);
            console.log('✅ Aggressive extraction successful, length:', bestContent.length);
            return bestContent;
        }
        
        return '';
    }
    
    // NEW: Clean up Gmail content by removing redundant information
    function cleanGmailContent(content, subject, sender) {
        if (!content) return '';
        
        let cleanContent = content;
        
        // Remove subject if it appears in content
        if (subject) {
            cleanContent = cleanContent.replace(new RegExp(subject.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '');
        }
        
        // Remove sender if it appears in content
        if (sender) {
            cleanContent = cleanContent.replace(new RegExp(sender.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '');
        }
        
        // Remove common Gmail artifacts
        cleanContent = cleanContent
            .replace(/Gmail.*?Google/g, '')
            .replace(/This email was sent.*?Google/g, '')
            .replace(/To unsubscribe.*?Google/g, '')
            .replace(/You received this email.*?Google/g, '');
        
        // Clean up extra whitespace
        cleanContent = cleanContent
            .replace(/\n\s*\n\s*\n/g, '\n\n')
            .replace(/^\s+|\s+$/g, '')
            .trim();
        
        return cleanContent;
    }
    
    // NEW: Manual email content extraction as last resort
    function extractEmailContentManually() {
        console.log('🔍 Manual email content extraction...');
        
        let subject = '';
        let sender = '';
        let content = '';
        
        // Enhanced subject extraction
        const headingSelectors = [
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
            '.subject', '.title', '[role="heading"]',
            '.email-subject', '.mail-subject', '.subject-line',
            '[data-testid*="subject"]', '[aria-label*="Subject"]'
        ];
        
        for (const selector of headingSelectors) {
            try {
                const headings = document.querySelectorAll(selector);
                for (const heading of headings) {
                    const text = cleanTextContent(heading.textContent || '');
                    if (text && text.length > 5 && text.length < 200 && 
                        !text.includes('@') && !text.includes('http') && 
                        !text.toLowerCase().includes('from:') && 
                        !text.toLowerCase().includes('to:') &&
                        !text.toLowerCase().includes('gmail') &&
                        !text.toLowerCase().includes('inbox')) {
                        subject = text;
                        console.log('✅ Subject found manually:', subject);
                        break;
                    }
                }
                if (subject) break;
            } catch (e) {
                console.log('⚠️ Error with heading selector:', selector, e);
            }
        }
        
        // Enhanced sender extraction with better email pattern matching
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
        const senderSelectors = [
            '[email]', '[data-hovercard-id]', '.sender', '.from', 
            '.sender-info', '.from-address', '.email-sender',
            '[data-testid*="sender"]', '[aria-label*="From"]'
        ];
        
        for (const selector of senderSelectors) {
            try {
                const elements = document.querySelectorAll(selector);
                for (const el of elements) {
                    const email = el.getAttribute('email') || cleanTextContent(el.textContent || '');
                    const emailMatch = email.match(emailPattern);
                    if (emailMatch && emailMatch[0]) {
                        sender = emailMatch[0];
                        console.log('✅ Sender found manually:', sender);
                        break;
                    }
                }
                if (sender) break;
            } catch (e) {
                console.log('⚠️ Error with sender selector:', selector, e);
            }
        }
        
        // If no sender found, search in all text
        if (!sender) {
            const allText = document.body.textContent || '';
            const emailMatches = allText.match(emailPattern);
            if (emailMatches && emailMatches.length > 0) {
                // Pick the first email that looks like a sender (not recipient)
                for (const email of emailMatches) {
                    if (!email.includes('noreply') && !email.includes('no-reply')) {
                        sender = email;
                        console.log('✅ Sender found in text:', sender);
                        break;
                    }
                }
            }
        }
        
        // Enhanced content extraction with better filtering
        const contentCandidates = [];
        const contentSelectors = [
            '.email-body', '.mail-content', '.message-body',
            '.email-content', '.msg-body', '[role="main"]',
            '.a3s:not(.undefined)', '.ii.gt', '.message-content',
            'main', 'article', '.content', '.body'
        ];
        
        // Try specific content selectors first
        for (const selector of contentSelectors) {
            try {
                const elements = document.querySelectorAll(selector);
                for (const el of elements) {
                    const text = extractAndFilterContent(el);
                    if (text && text.length > 50 && isValidEmailContent(text)) {
                        contentCandidates.push({
                            text: text,
                            score: calculateContentScore(text),
                            source: `selector:${selector}`
                        });
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with content selector:', selector, e);
            }
        }
        
        // If no content found with selectors, use enhanced tree walker approach
        if (contentCandidates.length === 0) {
            try {
                const walker = document.createTreeWalker(
                    document.body,
                    NodeFilter.SHOW_TEXT,
                    {
                        acceptNode: function(node) {
                            const text = cleanTextContent(node.textContent || '');
                            if (text && text.length > 30 && text.length < 5000) {
                                // Check if this looks like valid email content
                                if (isValidEmailContent(text)) {
                                    return NodeFilter.FILTER_ACCEPT;
                                }
                            }
                            return NodeFilter.FILTER_REJECT;
                        }
                    }
                );
                
                let node;
                while (node = walker.nextNode()) {
                    const text = cleanTextContent(node.textContent || '');
                    if (text && text.length > 30) {
                        contentCandidates.push({
                            text: text,
                            score: calculateContentScore(text),
                            source: 'enhanced_tree_walker'
                        });
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with enhanced tree walker:', e);
            }
        }
        
        // Find the best content candidate
        if (contentCandidates.length > 0) {
            contentCandidates.sort((a, b) => b.score - a.score);
            content = contentCandidates[0].text.substring(0, 3000);
            console.log('✅ Content found manually, length:', content.length, 'source:', contentCandidates[0].source);
        }
        
        // Only return if we have meaningful content
        if (subject || (content && content.length > 20) || sender) {
            return {
                subject: subject || 'No subject',
                sender: sender || 'Unknown sender',
                content: content || 'No content available',
                isReading: true,
                timestamp: Date.now(),
                source: 'manual_extraction'
            };
        }
        
        return null;
    }

    // Extract and filter content from an element
    function extractAndFilterContent(element) {
        if (!element) return '';
        
        const text = cleanTextContent(element.textContent || '');
        
        // Enhanced UI filtering - more comprehensive Gmail UI detection
        const uiKeywords = [
            'print all', 'in new window', 'reply', 'forward', 'add reaction',
            'gmail', 'inbox', 'compose', 'sent', 'drafts', 'search',
            'settings', 'help', 'sign out', 'account', 'menu',
            'navigation', 'toolbar', 'sidebar', 'footer', 'header',
            'archive', 'delete', 'spam', 'important', 'starred',
            'more actions', 'labels', 'move to', 'snooze',
            'mark as read', 'mark as unread', 'show original',
            'show trimmed content', 'show quoted text',
            '(11 minutes ago)', 'to me', 'pm (', 'am (',
            'show details', 'hide details', 'translate message'
        ];
        
        const lowerText = text.toLowerCase();
        
        // Check for UI keywords
        const hasUIKeywords = uiKeywords.some(keyword => lowerText.includes(keyword.toLowerCase()));
        
        // Check for timestamp patterns (e.g., "3:35 PM (11 minutes ago)")
        const hasTimestamp = /\d{1,2}:\d{2}\s*(AM|PM)\s*\(\d+\s*(minute|hour|day)s?\s*ago\)/i.test(text);
        
        // Check for "to me" pattern
        const hasToMePattern = /\bto\s+me\b/i.test(text);
        
        // Check for action button patterns
        const hasActionButtons = /^(reply|forward|archive|delete|spam|important|starred)$/i.test(text.trim());
        
        // If text is very short and contains UI elements, likely UI
        if ((hasUIKeywords || hasTimestamp || hasToMePattern || hasActionButtons) && text.length < 300) {
            console.log('🚫 Filtered out UI text:', text.substring(0, 50) + '...');
            return '';
        }
        
        // Remove common Gmail UI patterns from the text
        let cleanedText = text;
        
        // Remove timestamp patterns
        cleanedText = cleanedText.replace(/\d{1,2}:\d{2}\s*(AM|PM)\s*\(\d+\s*(minute|hour|day)s?\s*ago\)/gi, '');
        
        // Remove "to me" patterns
        cleanedText = cleanedText.replace(/\b[\w\s]+\s+to\s+me\b/gi, '');
        
        // Remove action button text
        cleanedText = cleanedText.replace(/\b(reply|forward|archive|delete|spam|important|starred|add reaction)\b/gi, '');
        
        // Remove print and window controls
        cleanedText = cleanedText.replace(/\b(print all|in new window|show original|show trimmed content|show quoted text)\b/gi, '');
        
        return removeEmailArtifacts(cleanedText).trim();
    }

    // Check if text looks like email content (legacy function - now uses enhanced version)
    function isLikelyEmailContent(text) {
        return isValidEmailContent(text);
    }

    // Calculate content quality score
    function calculateContentScore(text) {
        if (!text) return 0;
        
        let score = text.length;
        
        // Bonus for email-like content
        const emailWords = ['dear', 'hello', 'regards', 'sincerely', 'thank you', 'please'];
        emailWords.forEach(word => {
            if (text.toLowerCase().includes(word)) {
                score += 50;
            }
        });
        
        // Penalty for UI-like content
        const uiWords = ['gmail', 'inbox', 'compose', 'menu', 'navigation'];
        uiWords.forEach(word => {
            if (text.toLowerCase().includes(word)) {
                score -= 100;
            }
        });
        
        // Bonus for having sentences
        const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 10);
        score += sentences.length * 20;
        
        return Math.max(0, score);
    }
    
    // NEW: Generic reading content extraction for other providers
    function extractGenericReadingContent(selectors) {
        console.log('🔍 Using generic extraction for provider');
        
        let subject = '';
        let sender = '';
        let content = '';
        
        // Extract subject
        if (selectors.readingSubject) {
            const subjectElements = document.querySelectorAll(selectors.readingSubject);
            if (subjectElements.length > 0) {
                subject = subjectElements[0].textContent?.trim() || '';
            }
        }
        
        // Extract sender
        if (selectors.readingSender) {
            const senderElements = document.querySelectorAll(selectors.readingSender);
            for (let senderEl of senderElements) {
                const email = senderEl.getAttribute('email') || senderEl.textContent?.trim();
                if (email && email.includes('@')) {
                    sender = email;
                    break;
                }
            }
        }
        
        // Extract body content
        if (selectors.readingBody) {
            const bodyElements = document.querySelectorAll(selectors.readingBody);
            const bodyTexts = [];
            bodyElements.forEach(bodyEl => {
                const text = bodyEl.textContent?.trim();
                if (text && text.length > 10) {
                    bodyTexts.push(text);
                }
            });
            content = bodyTexts.join('\n\n').substring(0, 2000);
        }
        
        if (subject || (content && content.length > 20) || sender) {
            return {
                subject: subject || 'No subject',
                sender: sender || 'Unknown sender',
                content: content || 'No content available',
                isReading: true,
                timestamp: Date.now()
            };
        }
        
        return null;
    }
    
    // Set up mutation observer to detect dynamic content changes
    // Legacy function - now redirects to enhanced version
    function setupMutationObserver() {
        console.log('🔄 Using enhanced mutation observer...');
        return setupEnhancedMutationObserver();
    }
    
    // Set up event listeners for email composition
    function setupEventListeners() {
        // Listen for clicks on compose buttons
        document.addEventListener('click', (e) => {
            if (isComposeButton(e.target)) {
                console.log('📝 Compose button clicked');
                setTimeout(() => {
                    checkForEmailComposition(document.body);
                    // Use enhanced extraction with retry for new compose windows
                    setTimeout(() => {
                        extractEmailContentWithRetry(3, 1000);
                    }, 1000);
                }, 500); // Wait for compose window to load
            }
        });
        
        // Enhanced form submission listener
        document.addEventListener('submit', (e) => {
            if (isEmailForm(e.target)) {
                console.log('📤 Email form submission detected');
                // Final content extraction before sending
                extractEmailContentWithRetry(1, 100);
            }
        });
        
        // Listen for input events on email fields
        document.addEventListener('input', debounce((e) => {
            if (isEmailField(e.target)) {
                console.log('📝 Email field input detected');
                extractEmailContentWithRetry(1, 200);
            }
        }, 1000));
        
        // Listen for focus events to detect email composition
        document.addEventListener('focus', (e) => {
            if (isEmailField(e.target)) {
                console.log('📝 Email field focused');
                emailDetectionState.isComposing = true;
                setTimeout(() => {
                    extractEmailContentWithRetry(2, 500);
                }, 300);
            }
        });
    }

    // Check if an element is an email field
    function isEmailField(element) {
        if (!element) return false;
        
        const emailFieldSelectors = [
            'input[name*="subject"]', 'input[name*="to"]', 'input[name*="body"]',
            '[contenteditable="true"]', '[role="textbox"]',
            'textarea[name*="body"]', 'textarea[name*="message"]'
        ];
        
        return emailFieldSelectors.some(selector => {
            try {
                return element.matches(selector);
            } catch (e) {
                return false;
            }
        });
    }

    // Debounce function to prevent excessive function calls
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    // Check if an element is a compose button
    function isComposeButton(element) {
        const provider = emailDetectionState.detectedProvider;
        const selectors = EMAIL_DETECTION_CONFIG[provider];
        
        if (!selectors) return false;
        
        return element.matches(selectors.composeButton) ||
               element.closest(selectors.composeButton);
    }
    
    // Check if an element is a send button
    function isSendButton(element) {
        const provider = emailDetectionState.detectedProvider;
        const selectors = EMAIL_DETECTION_CONFIG[provider];
        
        if (!selectors) return false;
        
        return element.matches(selectors.sendButton) ||
               element.closest(selectors.sendButton);
    }
    
    // Check if an element is an email form
    function isEmailForm(element) {
        return element.tagName === 'FORM' && (
            element.querySelector('input[name="to"]') ||
            element.querySelector('input[name="subject"]') ||
            element.querySelector('textarea[name="body"]')
        );
    }
    
    // Check for email composition in the DOM
    function checkForEmailComposition(rootElement) {
        const provider = emailDetectionState.detectedProvider;
        const selectors = EMAIL_DETECTION_CONFIG[provider];
        
        if (!selectors) return;
        
        // Check if compose window is open
        const subjectField = rootElement.querySelector(selectors.subjectField);
        const bodyField = rootElement.querySelector(selectors.bodyField);
        const recipientField = rootElement.querySelector(selectors.recipientField);
        
        // Check if reading an email
        const emailThread = rootElement.querySelector(selectors.emailThread);
        const messageContainer = rootElement.querySelector(selectors.messageContainer);
        const readingSubject = rootElement.querySelector(selectors.readingSubject);
        
        // Handle email composition
        if (subjectField || bodyField || recipientField) {
            if (!emailDetectionState.isComposing) {
                console.log('📝 Email composition detected');
                emailDetectionState.isComposing = true;
                emailDetectionState.isReading = false; // Not reading when composing
                startContentMonitoring();
            }
        } else {
            if (emailDetectionState.isComposing) {
                console.log('📝 Email composition ended');
                emailDetectionState.isComposing = false;
                stopContentMonitoring();
            }
        }
        
        // Handle email reading
        if (emailThread || messageContainer || readingSubject) {
            if (!emailDetectionState.isReading && !emailDetectionState.isComposing) {
                console.log('👁️ Email reading detected');
                emailDetectionState.isReading = true;
                startContentMonitoring();
            }
        } else {
            // For Gmail, try alternative detection methods
            if (provider === 'gmail' && !emailDetectionState.isReading && !emailDetectionState.isComposing) {
                // Check if we're on a Gmail page with email content
                const isGmailPage = window.location.hostname.includes('mail.google.com');
                const hasEmailContent = document.body.textContent?.includes('@') || 
                                      document.body.textContent?.includes('Subject:') ||
                                      document.body.textContent?.includes('From:');
                
                if (isGmailPage && hasEmailContent) {
                    console.log('👁️ Gmail email reading detected (alternative method)');
                    emailDetectionState.isReading = true;
                    startContentMonitoring();
                }
            }
            
            if (emailDetectionState.isReading) {
                console.log('👁️ Email reading ended');
                emailDetectionState.isReading = false;
                if (!emailDetectionState.isComposing) {
                    stopContentMonitoring();
                }
            }
        }
    }
    
    // Start monitoring email content for changes
    function startContentMonitoring() {
        if (emailDetectionState.scanInterval) {
            clearInterval(emailDetectionState.scanInterval);
        }
        
        // Monitor content every 2 seconds while composing
        emailDetectionState.scanInterval = setInterval(() => {
            if (emailDetectionState.isComposing) {
                extractEmailContent();
            }
        }, 2000);
        
        console.log('🔍 Started content monitoring');
    }
    
    // Stop monitoring email content
    function stopContentMonitoring() {
        if (emailDetectionState.scanInterval) {
            clearInterval(emailDetectionState.scanInterval);
            emailDetectionState.scanInterval = null;
        }
        console.log('🔍 Stopped content monitoring');
    }
    
    // Extract email content for analysis
    function extractEmailContent() {
        const provider = emailDetectionState.detectedProvider;
        const selectors = EMAIL_DETECTION_CONFIG[provider];
        
        if (!selectors) return;
        
        try {
            // Check if we're reading an email instead of composing
            if (emailDetectionState.isReading && !emailDetectionState.isComposing) {
                const readingData = extractReadingEmailContent();
                if (readingData) {
                    emailDetectionState.currentEmailData = readingData;
                    console.log('📧 Reading email content extracted');
                }
                return;
            }
            
            // Handle email composition (existing logic)
            const subjectField = document.querySelector(selectors.subjectField);
            const bodyField = document.querySelector(selectors.bodyField);
            const recipientField = document.querySelector(selectors.recipientField);
            
            if (!subjectField && !bodyField) {
                console.log('❌ No email fields found with standard selectors, trying enhanced extraction...');
                
                // Enhanced fallback extraction
                const enhancedData = extractEmailContentEnhanced();
                if (enhancedData) {
                    emailDetectionState.currentEmailData = enhancedData;
                    sendEmailForAnalysis(enhancedData);
                }
                return;
            }
            
            // Extract content with improved handling
            let subject = '';
            let content = '';
            let recipient = '';
            
            if (subjectField) {
                subject = cleanTextContent(subjectField.value || subjectField.textContent || subjectField.innerText || '');
            }
            
            if (bodyField) {
                content = extractBodyContent(bodyField);
            }
            
            if (recipientField) {
                recipient = cleanTextContent(recipientField.value || recipientField.textContent || recipientField.innerText || '');
            }
            
            const emailData = {
                subject: subject,
                content: content,
                sender: '', // We're composing, so no sender
                recipient: recipient,
                timestamp: Date.now(),
                provider: provider,
                url: window.location.href,
                isReading: false
            };
            
            // Only scan if content has changed significantly
            if (hasContentChanged(emailData)) {
                console.log('📧 Extracted email content:', emailData);
                emailDetectionState.currentEmailData = emailData;
                
                // Send to background script for analysis
                sendEmailForAnalysis(emailData);
            }
            
        } catch (error) {
            console.error('❌ Error extracting email content:', error);
            
            // Final fallback - try manual extraction
            try {
                const manualData = extractEmailContentManually();
                if (manualData) {
                    emailDetectionState.currentEmailData = manualData;
                    sendEmailForAnalysis(manualData);
                }
            } catch (fallbackError) {
                console.error('❌ Fallback extraction also failed:', fallbackError);
            }
        }
    }
    
    // Check if email content has changed significantly
    function hasContentChanged(newEmailData) {
        const oldData = emailDetectionState.currentEmailData;
        
        if (!oldData) return true;
        
        // Check if subject or content has changed
        const subjectChanged = newEmailData.subject !== oldData.subject;
        const contentChanged = newEmailData.content !== oldData.content;
        const recipientChanged = newEmailData.recipient !== oldData.recipient;
        
        // Check if enough time has passed since last scan
        const timeSinceLastScan = Date.now() - emailDetectionState.lastScanTime;
        const shouldScan = timeSinceLastScan > 5000; // 5 seconds minimum between scans
        
        return (subjectChanged || contentChanged || recipientChanged) && shouldScan;
    }

    // Enhanced email content extraction for better reliability
    function extractEmailContentEnhanced() {
        console.log('🔍 Enhanced email content extraction...');
        
        let subject = '';
        let content = '';
        let recipient = '';
        let sender = '';
        
        // Enhanced selectors for different email providers and interfaces
        const enhancedSelectors = {
            subject: [
                'input[name="subjectbox"]', 'input[placeholder*="Subject"]', 'input[aria-label*="Subject"]',
                '.aoD.az6 input[name="subjectbox"]', '[data-test-id="compose-subject"]',
                '.subject-input', '.compose-subject', '[name="subject"]', '[placeholder="Subject"]',
                'h1', 'h2', 'h3', '.email-subject', '.mail-subject', '.subject-line'
            ],
            body: [
                'div[role="textbox"]', 'div[contenteditable="true"]', '.Am.Al.editable',
                '.editable[contenteditable="true"]', '[data-test-id="compose-body"]',
                '.compose-body', '.email-body', '.mail-content', 'textarea[name="body"]',
                '.rn_editor', '.DShyMc-AHe6Kc-OiiCO', '.Am.Al.editable', '.editable',
                '.ii.gt .a3s.aiL', '.a3s', '.message-body', '.email-content'
            ],
            recipient: [
                'input[name="to"]', '[data-test-id="compose-to"]', '.to-field',
                '.compose-to', '.recipient-input', '[placeholder*="To"]', '[aria-label*="To"]'
            ]
        };
        
        // Try to extract subject
        for (const selector of enhancedSelectors.subject) {
            try {
                const element = document.querySelector(selector);
                if (element) {
                    const text = cleanTextContent(
                        element.value || element.textContent || element.innerText || ''
                    );
                    if (text && text.length > 0 && text.length < 500) {
                        subject = text;
                        console.log('✅ Enhanced subject found:', subject);
                        break;
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with subject selector:', selector, e);
            }
        }
        
        // Try to extract body content
        for (const selector of enhancedSelectors.body) {
            try {
                const element = document.querySelector(selector);
                if (element) {
                    const text = extractBodyContent(element);
                    if (text && text.length > 10) {
                        content = text;
                        console.log('✅ Enhanced body found, length:', content.length);
                        break;
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with body selector:', selector, e);
            }
        }
        
        // Try to extract recipient
        for (const selector of enhancedSelectors.recipient) {
            try {
                const element = document.querySelector(selector);
                if (element) {
                    const text = cleanTextContent(
                        element.value || element.textContent || element.innerText || ''
                    );
                    if (text && text.includes('@')) {
                        recipient = text;
                        console.log('✅ Enhanced recipient found:', recipient);
                        break;
                    }
                }
            } catch (e) {
                console.log('⚠️ Error with recipient selector:', selector, e);
            }
        }
        
        // If we found any content, return it
        if (subject || content || recipient) {
            return {
                subject: subject || 'No subject',
                content: content || 'No content available',
                sender: sender || '',
                recipient: recipient || '',
                timestamp: Date.now(),
                provider: emailDetectionState.detectedProvider || 'unknown',
                url: window.location.href,
                isReading: false,
                source: 'enhanced_extraction'
            };
        }
        
        return null;
    }

    // Clean and normalize text content
    function cleanTextContent(text) {
        if (!text) return '';
        
        return text
            .replace(/\u00A0/g, ' ') // Replace non-breaking spaces
            .replace(/\u200B/g, '') // Remove zero-width spaces
            .replace(/\u2060/g, '') // Remove word joiners
            .replace(/[\r\n\t]+/g, ' ') // Normalize whitespace
            .replace(/\s{2,}/g, ' ') // Remove multiple spaces
            .trim();
    }

    // Extract body content with better handling of different element types
    function extractBodyContent(element) {
        if (!element) return '';
        
        let content = '';
        
        // Handle different types of elements
        if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
            content = element.value || '';
        } else if (element.contentEditable === 'true' || element.getAttribute('contenteditable') === 'true') {
            // For contenteditable elements, prefer innerText over textContent for better formatting
            content = element.innerText || element.textContent || '';
        } else {
            content = element.textContent || element.innerText || '';
        }
        
        // Clean and process the content
        content = cleanTextContent(content);
        
        // Remove common email signatures and footers
        content = removeEmailArtifacts(content);
        
        // Limit content length to prevent overwhelming the API
        if (content.length > 5000) {
            content = content.substring(0, 5000) + '...';
        }
        
        return content;
    }

    // Remove common email artifacts and signatures
    function removeEmailArtifacts(content) {
        if (!content) return '';
        
        let cleanContent = content;
        
        // Remove common email artifacts
        const artifacts = [
            /Gmail.*?Google/gi,
            /This email was sent.*?Google/gi,
            /To unsubscribe.*?Google/gi,
            /You received this email.*?Google/gi,
            /Sent from my iPhone/gi,
            /Sent from my Android/gi,
            /Get Outlook for iOS/gi,
            /Get Outlook for Android/gi,
            /--\s*\r?\n.*$/s, // Remove signature blocks starting with --
            /_{10,}/g, // Remove long underscores
            /\*{10,}/g, // Remove long asterisks
            /-{10,}/g, // Remove long dashes
        ];
        
        artifacts.forEach(pattern => {
            cleanContent = cleanContent.replace(pattern, '');
        });
        
        return cleanContent.trim();
    }
    
    // Send email data to background script for analysis
    function sendEmailForAnalysis(emailData) {
        try {
            chrome.runtime.sendMessage({
                action: 'analyzeEmailComposition',
                data: emailData
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.log('📧 Email sent for analysis (no response expected)');
                } else if (response && response.success) {
                    console.log('✅ Email analysis completed');
                    emailDetectionState.lastScanTime = Date.now();
                }
            });
        } catch (error) {
            console.error('❌ Error sending email for analysis:', error);
        }
    }

    // Enhanced extraction with retry logic and timeout handling
    function extractEmailContentWithRetry(maxRetries = 3, delay = 1000) {
        let retryCount = 0;
        
        function attemptExtraction() {
            console.log(`🔄 Email extraction attempt ${retryCount + 1}/${maxRetries}`);
            
            // Try primary extraction
            extractEmailContent();
            
            // Check if we got meaningful content
            const hasContent = emailDetectionState.currentEmailData && 
                              (emailDetectionState.currentEmailData.subject || 
                               emailDetectionState.currentEmailData.content);
            
            if (!hasContent && retryCount < maxRetries - 1) {
                retryCount++;
                console.log(`⏳ Retrying extraction in ${delay}ms...`);
                setTimeout(attemptExtraction, delay);
            } else if (!hasContent) {
                console.log('⚠️ All extraction attempts failed, trying manual extraction...');
                const manualData = extractEmailContentManually();
                if (manualData) {
                    emailDetectionState.currentEmailData = manualData;
                    sendEmailForAnalysis(manualData);
                }
            }
        }
        
        attemptExtraction();
    }

    // Wait for content to load before extraction
    function waitForContentAndExtract(selector, timeout = 5000) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            
            function checkForContent() {
                const element = document.querySelector(selector);
                
                if (element && (element.textContent || element.value)) {
                    console.log('✅ Content found after waiting');
                    resolve(element);
                } else if (Date.now() - startTime >= timeout) {
                    console.log('⚠️ Timeout waiting for content');
                    reject(new Error('Timeout waiting for content'));
                } else {
                    setTimeout(checkForContent, 100);
                }
            }
            
            checkForContent();
        });
    }
    
    // Start email monitoring
    function startEmailMonitoring() {
        console.log('🔍 Starting enhanced email monitoring...');
        
        // Initial check for email composition
        checkForEmailComposition(document.body);
        
        // Enhanced periodic checks with different intervals
        setInterval(() => {
            checkForEmailComposition(document.body);
        }, 3000);
        
        // More frequent checks for compose windows
        setInterval(() => {
            if (emailDetectionState.isComposing) {
                extractEmailContentWithRetry(2, 500);
            }
        }, 1500);
        
        // Setup enhanced mutation observer
        setupEnhancedMutationObserver();
    }

    // Enhanced mutation observer for better content change detection
    function setupEnhancedMutationObserver() {
        const observer = new MutationObserver((mutations) => {
            let shouldCheckEmail = false;
            
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    // Check for new compose windows or email forms
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if this looks like email-related content
                            if (isEmailRelatedNode(node)) {
                                shouldCheckEmail = true;
                                checkForEmailComposition(node);
                            }
                        }
                    });
                } else if (mutation.type === 'attributes') {
                    // Check for attribute changes that might indicate content changes
                    if (mutation.attributeName === 'class' || 
                        mutation.attributeName === 'style' ||
                        mutation.attributeName === 'data-message-id') {
                        shouldCheckEmail = true;
                    }
                }
            });
            
            // Debounced email check
            if (shouldCheckEmail) {
                clearTimeout(observer.emailCheckTimeout);
                observer.emailCheckTimeout = setTimeout(() => {
                    extractEmailContentWithRetry(1, 200);
                }, 500);
            }
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['class', 'style', 'data-message-id', 'contenteditable']
        });
        
        return observer;
    }

    // Check if a node is email-related
    function isEmailRelatedNode(node) {
        if (!node.querySelector) return false;
        
        const emailSelectors = [
            '[role="textbox"]', '[contenteditable="true"]', 
            'input[name*="subject"]', 'input[name*="to"]',
            '.compose', '.email', '.message', '.mail',
            '[data-test-id*="compose"]', '[aria-label*="Compose"]'
        ];
        
        return emailSelectors.some(selector => {
            try {
                return node.querySelector(selector) !== null;
            } catch (e) {
                return false;
            }
        });
    }
    
    // Listen for messages from popup/background
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log('📨 Content script received message:', message.action);
        
        if (message.action === 'forceEmailDetection') {
            const result = forceEmailDetection();
            sendResponse({ success: true, data: result });
        } else if (message.action === 'forceRefreshEmailDetection') {
            const result = forceRefreshEmailDetection();
            sendResponse({ success: true, data: result });
        } else if (message.action === 'debugEmailDetection') {
            const result = debugEmailDetection();
            sendResponse({ success: true, data: result });
        } else if (message.action === 'checkEmailDetectionStatus') {
            const result = getEmailDetectionState();
            sendResponse({ success: true, data: result });
        }
    });
    
    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeEmailDetection);
    } else {
        initializeEmailDetection();
    }
    
    // Also initialize after a short delay to catch dynamic content
    setTimeout(initializeEmailDetection, 1000);
    
    // Debug function to test email extraction
    function debugEmailExtraction() {
        console.log('🔧 DEBUG: Testing email extraction...');
        
        // Test enhanced extraction
        const enhancedResult = extractEmailContentEnhanced();
        console.log('Enhanced extraction result:', enhancedResult);
        
        // Test manual extraction
        const manualResult = extractEmailContentManually();
        console.log('Manual extraction result:', manualResult);
        
        // Test Gmail specific extraction if we're on Gmail
        if (window.location.hostname.includes('gmail') || window.location.hostname.includes('google')) {
            const mainContent = document.querySelector('[role="main"]') || document.body;
            
            console.log('Gmail specific tests:');
            console.log('Subject:', extractGmailSubject(mainContent));
            console.log('Sender:', extractGmailSender(mainContent));
            console.log('Body:', extractGmailBody(mainContent));
            
            // Test specific selector for the HTML structure you showed
            console.log('🔍 Testing specific Gmail selectors for your HTML structure:');
            
            // Test the exact selector from your HTML
            const specificContent = document.querySelector('div.a3s.aiL div[dir="ltr"]');
            if (specificContent) {
                const extractedText = extractTextWithFormatting(specificContent);
                console.log('✅ Found content with specific selector div.a3s.aiL div[dir="ltr"]:', extractedText.substring(0, 200) + '...');
                
                // Test if it passes validation
                console.log('✅ Content validation result:', isValidEmailContent(extractedText));
            } else {
                console.log('❌ No content found with specific selector div.a3s.aiL div[dir="ltr"]');
            }
            
            // Test alternative selectors
            const alternativeSelectors = [
                'div.a3s.aiL',
                '.a3s.aiL',
                'div[id*=":"] div[dir="ltr"]',
                'div[class*="a3s"] div[dir]'
            ];
            
            alternativeSelectors.forEach(selector => {
                const element = document.querySelector(selector);
                if (element) {
                    const text = extractTextWithFormatting(element);
                    console.log(`✅ Alternative selector "${selector}" found content:`, text.substring(0, 100) + '...');
                }
            });
        }
        
        // Test current detection state
        console.log('Detection state:', emailDetectionState);
        
        return {
            enhanced: enhancedResult,
            manual: manualResult,
            state: emailDetectionState
        };
    }

    // Test function specifically for the HTML structure you provided
    function testSpecificGmailExtraction() {
        console.log('🧪 Testing extraction for specific Gmail HTML structure...');
        
        // Look for the exact structure from your HTML
        const emailContainer = document.querySelector('div[id*=":"].a3s.aiL') || 
                              document.querySelector('div.a3s.aiL');
        
        if (!emailContainer) {
            console.log('❌ No email container found');
            return null;
        }
        
        console.log('✅ Email container found:', emailContainer);
        
        // Extract content from the div[dir="ltr"] inside
        const contentDiv = emailContainer.querySelector('div[dir="ltr"]') || 
                           emailContainer.querySelector('div[dir]') ||
                           emailContainer;
        
        if (contentDiv) {
            const extractedContent = extractTextWithFormatting(contentDiv);
            const cleanedContent = cleanTextContent(extractedContent);
            
            console.log('📧 Extracted content:', cleanedContent);
            console.log('✅ Content validation:', isValidEmailContent(cleanedContent));
            console.log('📏 Content length:', cleanedContent.length);
            
            return {
                success: true,
                content: cleanedContent,
                isValid: isValidEmailContent(cleanedContent),
                length: cleanedContent.length
            };
        } else {
            console.log('❌ No content div found inside email container');
            return null;
        }
    }

    // EXPOSE FUNCTIONS GLOBALLY FOR TESTING
    window.checkForEmailComposition = checkForEmailComposition;
    window.extractEmailContent = extractEmailContent;
    window.extractReadingEmailContent = extractReadingEmailContent;
    window.forceEmailDetection = forceEmailDetection;
    window.debugEmailDetection = debugEmailDetection;
    window.debugEmailExtraction = debugEmailExtraction;
    window.testSpecificGmailExtraction = testSpecificGmailExtraction;
    window.getEmailDetectionState = () => emailDetectionState;
    window.extractEmailContentManually = extractEmailContentManually;
    window.extractFromMainContentAggressive = extractFromMainContentAggressive;
    window.isValidEmailContent = isValidEmailContent;
    window.extractTextWithFormatting = extractTextWithFormatting;
    
    console.log('🌐 Email detection functions exposed globally for testing');
    
})();

// Initialize content script
function initializeContentScript() {
    console.log('🔍 Enhanced Phishing Detection Content Script Initializing...');
    
    // Initialize email detection
    initializeEmailDetection();
    
    // Initialize other phishing detection features
    if (typeof initializePhishingDetection === 'function') {
        initializePhishingDetection();
    }
    
    console.log('✅ Content script initialization complete');
}

// Perform comprehensive source code analysis
function performSourceCodeAnalysis() {
    try {
        const pageSource = document.documentElement.outerHTML;
        const currentUrl = window.location.href;
        
        // Reset analysis results
        analysisResults = {
            threatIndicators: [],
            riskScore: 0,
            isLegitimate: false,
            brandName: null,
            threatDetails: {
                forms: {},
                scripts: {},
                elements: {},
                network: {}
            }
        };
        
        // Check if this is a legitimate site first
        checkLegitimacy(currentUrl);
        
        // Analyze source code for threats
        analyzeSourceCode(pageSource);
        
        // Analyze forms in detail
        analyzeForms();
        
        // Analyze scripts
        analyzeScripts();
        
        // Analyze network requests
        analyzeNetworkRequests();
        
        // Calculate final risk score
        calculateFinalRiskScore();
        
        // Send results to background script
        sendAnalysisResults();
        
        console.log('📊 Source code analysis complete:', analysisResults);
        
    } catch (error) {
        console.error('❌ Source code analysis failed:', error);
    }
}

// Check if the current site is legitimate
function checkLegitimacy(url) {
    const domain = extractDomain(url);
    
    // Check against known legitimate domains
    if (LEGITIMATE_PATTERNS.legitimateDomains.test(url)) {
        analysisResults.isLegitimate = true;
        analysisResults.brandName = extractBrandName(domain);
        analysisResults.riskScore -= 20; // Reduce risk for legitimate sites
        return;
    }
    
    // Check for legitimate patterns in domain
    const legitimateIndicators = [
        /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.(?:com|org|net|edu|gov)$/,
        /^(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.(?:co\.uk|com\.au|com\.ca)$/
    ];
    
    for (const pattern of legitimateIndicators) {
        if (pattern.test(domain)) {
            analysisResults.isLegitimate = true;
            break;
        }
    }
}

// Extract brand name from domain
function extractBrandName(domain) {
    const brandMap = {
        'google.com': 'Google',
        'facebook.com': 'Facebook',
        'microsoft.com': 'Microsoft',
        'apple.com': 'Apple',
        'amazon.com': 'Amazon',
        'paypal.com': 'PayPal',
        'ebay.com': 'eBay',
        'netflix.com': 'Netflix',
        'github.com': 'GitHub'
    };
    
    return brandMap[domain] || null;
}

// Analyze source code for suspicious patterns
function analyzeSourceCode(source) {
    const indicators = [];
    let riskScore = 0;
    
    // If this is a legitimate site, be much more conservative
    const isLegitimate = analysisResults.isLegitimate;
    
    // Check each suspicious pattern
    for (const [patternName, pattern] of Object.entries(SUSPICIOUS_PATTERNS)) {
        if (pattern.test(source)) {
            // For legitimate sites, only report severe threats
            if (isLegitimate) {
                const severeThreats = ['passwordFieldsInHiddenElements', 'cookieTheft', 'suspiciousScripts'];
                if (severeThreats.includes(patternName)) {
                    indicators.push(patternName);
                    riskScore += (RISK_WEIGHTS[patternName] || 10) * 0.3; // Reduced weight for legitimate sites
                    console.warn(`⚠️ Potential threat on legitimate site: ${patternName}`);
                }
                // Skip reporting minor patterns on legitimate sites
            } else {
                indicators.push(patternName);
                riskScore += RISK_WEIGHTS[patternName] || 10;
                console.warn(`🚨 Threat detected: ${patternName}`);
            }
        }
    }
    
    // Check for legitimate patterns that reduce risk
    if (LEGITIMATE_PATTERNS.legitimateLibraries.test(source)) {
        riskScore = Math.max(0, riskScore - 15);
    }
    
    if (LEGITIMATE_PATTERNS.legitimateCDNs.test(source)) {
        riskScore = Math.max(0, riskScore - 10);
    }
    
    if (LEGITIMATE_PATTERNS.legitimateTracking.test(source)) {
        riskScore = Math.max(0, riskScore - 5);
    }
    
    // Further reduce risk for legitimate sites
    if (isLegitimate) {
        riskScore = Math.max(0, riskScore - 40);
    }
    
    analysisResults.threatIndicators = indicators;
    analysisResults.riskScore += riskScore;
}

// Analyze forms for credential theft indicators
function analyzeForms() {
    const forms = document.querySelectorAll('form');
    const formAnalysis = {
        totalForms: forms.length,
        passwordFieldsCount: 0,
        credentialStealingForms: 0,
        externalSubmissions: 0,
        hiddenFields: 0
    };
    
    forms.forEach((form, index) => {
        const passwordFields = form.querySelectorAll('input[type="password"]');
        formAnalysis.passwordFieldsCount += passwordFields.length;
        
        // Check form action
        const action = form.getAttribute('action');
        if (action) {
            const currentDomain = extractDomain(window.location.href);
            const actionDomain = extractDomain(action);
            
            if (actionDomain && actionDomain !== currentDomain) {
                formAnalysis.externalSubmissions++;
                analysisResults.threatIndicators.push('credentialStealingForms');
                analysisResults.riskScore += 30;
            }
        }
        
        // Check for hidden form fields
        const hiddenFields = form.querySelectorAll('input[type="hidden"]');
        formAnalysis.hiddenFields += hiddenFields.length;
        
        // Check for forms with suspicious IDs or classes
        const formId = form.id ? form.id.toLowerCase() : '';
        const formClass = form.className ? form.className.toLowerCase() : '';
        
        if (formId.includes('phish') || formClass.includes('phish') || 
            formId.includes('steal') || formClass.includes('steal')) {
            analysisResults.threatIndicators.push('suspiciousFormNames');
            analysisResults.riskScore += 25;
        }
    });
    
    // Special handling for multiple forms with password fields
    if (formAnalysis.passwordFieldsCount > 1 && forms.length > 1) {
        analysisResults.threatIndicators.push('multipleSuspiciousForms');
        analysisResults.riskScore += 20;
    }
    
    analysisResults.threatDetails.forms = formAnalysis;
}

// Analyze scripts for malicious behavior
function analyzeScripts() {
    const scripts = document.querySelectorAll('script');
    const scriptAnalysis = {
        totalScripts: scripts.length,
        inlineScripts: 0,
        externalScripts: 0,
        suspicious: 0,
        obfuscated: 0
    };
    
    scripts.forEach(script => {
        const src = script.getAttribute('src');
        const content = script.textContent || script.innerHTML;
        
        if (src) {
            scriptAnalysis.externalScripts++;
            
            // Check for suspicious external scripts
            if (SUSPICIOUS_PATTERNS.suspiciousScripts.test(src)) {
                scriptAnalysis.suspicious++;
                analysisResults.riskScore += 15;
            }
        } else if (content) {
            scriptAnalysis.inlineScripts++;
            
            // Check for obfuscated content
            if (SUSPICIOUS_PATTERNS.obfuscatedJS.test(content) ||
                SUSPICIOUS_PATTERNS.longEncodedStrings.test(content)) {
                scriptAnalysis.obfuscated++;
                analysisResults.riskScore += 20;
            }
            
            // Check for keylogger patterns
            if (SUSPICIOUS_PATTERNS.keyloggerPatterns.test(content)) {
                scriptAnalysis.suspicious++;
                analysisResults.threatIndicators.push('keyloggerDetected');
                analysisResults.riskScore += 35;
            }
            
            // Check for cookie theft
            if (SUSPICIOUS_PATTERNS.cookieTheft.test(content)) {
                scriptAnalysis.suspicious++;
                analysisResults.threatIndicators.push('cookieTheft');
                analysisResults.riskScore += 25;
            }
        }
    });
    
    analysisResults.threatDetails.scripts = scriptAnalysis;
}

// Analyze network requests and external resources
function analyzeNetworkRequests() {
    const networkAnalysis = {
        externalDomains: new Set(),
        suspiciousRequests: 0,
        httpsViolations: 0
    };
    
    // Analyze all external resources
    const externalResources = document.querySelectorAll('[src], [href]');
    
    externalResources.forEach(element => {
        const url = element.getAttribute('src') || element.getAttribute('href');
        if (url && url.startsWith('http')) {
            const domain = extractDomain(url);
            if (domain && domain !== extractDomain(window.location.href)) {
                networkAnalysis.externalDomains.add(domain);
                
                // Check for suspicious domains
                if (url.includes('.tk') || url.includes('.ml') || 
                    url.includes('.ga') || url.includes('.cf')) {
                    networkAnalysis.suspiciousRequests++;
                    analysisResults.riskScore += 15;
                }
                
                // Check for HTTPS violations
                if (window.location.protocol === 'https:' && url.startsWith('http:')) {
                    networkAnalysis.httpsViolations++;
                    analysisResults.riskScore += 10;
                }
            }
        }
    });
    
    // Flag sites with too many external domains
    if (networkAnalysis.externalDomains.size > 15) {
        analysisResults.threatIndicators.push('multipleExternalDomains');
        analysisResults.riskScore += 20;
    }
    
    analysisResults.threatDetails.network = {
        externalDomains: Array.from(networkAnalysis.externalDomains),
        suspiciousRequests: networkAnalysis.suspiciousRequests,
        httpsViolations: networkAnalysis.httpsViolations
    };
}

// Calculate final risk score with adjustments
function calculateFinalRiskScore() {
    // Apply legitimate site bonus
    if (analysisResults.isLegitimate) {
        analysisResults.riskScore = Math.max(0, analysisResults.riskScore - 25);
    }
    
    // Cap risk score at 100
    analysisResults.riskScore = Math.min(100, Math.max(0, analysisResults.riskScore));
    
    // Remove duplicate threat indicators
    analysisResults.threatIndicators = [...new Set(analysisResults.threatIndicators)];
}

// Set up behavior monitoring
function setupBehaviorMonitoring() {
    // Monitor user interactions
    document.addEventListener('click', () => {
        userInteractionCount++;
    });
    
    document.addEventListener('keydown', () => {
        userInteractionCount++;
    });
    
    // Monitor form submissions
    document.addEventListener('submit', (event) => {
        formSubmissionAttempts++;
        
        // Check for rapid form submissions
        const now = Date.now();
        if (formSubmissionAttempts > 1 && (now - pageLoadTime) < 5000) {
            analysisResults.threatIndicators.push('rapidFormSubmission');
            analysisResults.riskScore += 20;
            
            // Notify background script
            sendBehaviorAlert('rapid_form_submission');
        }
    });
    
    // Monitor page visibility changes
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            // Page was hidden - might be trying to steal focus
            sendBehaviorAlert('page_hidden');
        }
    });
}

// Set up form monitoring for real-time detection
function setupFormMonitoring() {
    document.addEventListener('input', (event) => {
        if (event.target.type === 'password') {
            // Password field interaction detected
            const form = event.target.closest('form');
            if (form) {
                const action = form.getAttribute('action');
                if (action && !action.startsWith(window.location.origin)) {
                    // Password being entered in form that submits externally
                    sendBehaviorAlert('external_password_form');
                }
            }
        }
    });
}

// Set up real-time monitoring
function setupRealTimeMonitoring() {
    // Monitor DOM changes
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'childList') {
                // Check for dynamically added suspicious elements
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        checkDynamicElement(node);
                    }
                });
            }
        });
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    monitoringActive = true;
}

// Check dynamically added elements
function checkDynamicElement(element) {
    // Check for suspicious scripts
    if (element.tagName === 'SCRIPT') {
        const content = element.textContent || element.innerHTML;
        if (SUSPICIOUS_PATTERNS.obfuscatedJS.test(content)) {
            analysisResults.threatIndicators.push('dynamicSuspiciousScript');
            analysisResults.riskScore += 25;
            sendBehaviorAlert('dynamic_suspicious_script');
        }
    }
    
    // Check for suspicious iframes
    if (element.tagName === 'IFRAME') {
        const src = element.getAttribute('src');
        if (src && SUSPICIOUS_PATTERNS.suspiciousIframes.test(src)) {
            analysisResults.threatIndicators.push('suspiciousIframe');
            analysisResults.riskScore += 20;
            sendBehaviorAlert('suspicious_iframe');
        }
    }
    
    // Check for hidden forms
    if (element.tagName === 'FORM' && element.style.display === 'none') {
        const passwordFields = element.querySelectorAll('input[type="password"]');
        if (passwordFields.length > 0) {
            analysisResults.threatIndicators.push('hiddenPasswordForm');
            analysisResults.riskScore += 30;
            sendBehaviorAlert('hidden_password_form');
        }
    }
}

// Set up message listener for communication
function setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        try {
            switch (message.action) {
                case 'analyzeSourceCode':
                    performSourceCodeAnalysis();
                    sendResponse(analysisResults);
                    break;
                    
                case 'getAnalysisResults':
                    sendResponse(analysisResults);
                    break;
                    
                case 'getSourceCodeAnalysis':
                    // Return current analysis results for popup
                    sendResponse({ data: analysisResults });
                    break;
                    
                case 'getBehaviorData':
                    sendResponse({
                        userInteractionCount,
                        formSubmissionAttempts,
                        pageLoadTime,
                        monitoringActive
                    });
                    break;
                    
                case 'updateThreatLevel':
                    if (message.level) {
                        analysisResults.riskScore = Math.max(analysisResults.riskScore, message.level);
                        sendAnalysisResults();
                    }
                    sendResponse({ success: true });
                    break;
                    
                case 'refreshAnalysis':
                    // Re-run analysis for updated results
                    performSourceCodeAnalysis();
                    sendResponse(analysisResults);
                    break;
                    
                default:
                    console.warn('Unknown message action:', message.action);
                    sendResponse({ success: false, error: 'Unknown action' });
            }
        } catch (error) {
            console.error('Error handling message:', error);
            sendResponse({ success: false, error: error.message });
        }
        
        return true; // Keep message channel open
    });
}

// Send analysis results to background script
function sendAnalysisResults() {
    try {
        chrome.runtime.sendMessage({
            action: 'sourceCodeAnalysisResult',
            data: analysisResults
        });
    } catch (error) {
        console.error('Failed to send analysis results:', error);
    }
}

// Send behavior alert to background script
function sendBehaviorAlert(alertType) {
    try {
        chrome.runtime.sendMessage({
            action: 'behaviorAlert',
            type: alertType,
            url: window.location.href,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Failed to send behavior alert:', error);
    }
}

// Utility function to extract domain from URL
function extractDomain(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname;
    } catch (error) {
        console.error('Invalid URL:', url);
        return null;
    }
}

// Utility function to get page metadata
function getPageMetadata() {
    return {
        title: document.title,
        url: window.location.href,
        domain: window.location.hostname,
        protocol: window.location.protocol,
        userAgent: navigator.userAgent,
        language: navigator.language,
        timestamp: new Date().toISOString()
    };
}

// Enhanced threat detection for specific patterns
function detectAdvancedThreats() {
    const threats = [];
    
    // Check for clipboard hijacking
    if (document.querySelector('script[src*="clipboard"]') || 
        document.documentElement.innerHTML.includes('clipboard')) {
        threats.push('clipboardHijacking');
    }
    
    // Check for fake captcha
    if (document.querySelector('img[src*="captcha"]') && 
        document.querySelector('input[name*="captcha"]')) {
        threats.push('fakeCaptcha');
    }
    
    // Check for fake loading screens
    if (document.querySelector('.loading') || document.querySelector('.spinner')) {
        const loadingElements = document.querySelectorAll('[class*="loading"], [class*="spinner"]');
        if (loadingElements.length > 3) {
            threats.push('fakeLoadingScreen');
        }
    }
    
    return threats;
}

// Initialize the content script when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeContentScript);
} else {
    initializeContentScript();
}

// Also initialize after a short delay to catch dynamic content
setTimeout(initializeContentScript, 1000);

// Export for testing purposes
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        performSourceCodeAnalysis,
        checkLegitimacy,
        analyzeSourceCode,
        SUSPICIOUS_PATTERNS,
        RISK_WEIGHTS
    };
}

// NEW: Test function for debugging email extraction
function testEmailExtraction() {
    console.log('🧪 Testing email extraction...');
    
    // Test the new Gmail extraction
    const gmailResult = extractGmailReadingContent();
    console.log('📧 Gmail extraction result:', gmailResult);
    
    // Test page analysis
    const pageResult = analyzePageForEmailContent();
    console.log('📄 Page analysis result:', pageResult);
    
    // Test manual extraction
    const manualResult = extractEmailContentManually();
    console.log('🔧 Manual extraction result:', manualResult);
    
    // Test force detection
    const forceResult = forceEmailDetection();
    console.log('🚀 Force detection result:', forceResult);
    
    // Test force refresh
    const refreshResult = forceRefreshEmailDetection();
    console.log('🔄 Force refresh result:', refreshResult);
    
    return {
        gmail: gmailResult,
        page: pageResult,
        manual: manualResult,
        force: forceResult,
        refresh: refreshResult
    };
}

// Expose functions to window for debugging
window.phishingDetection = {
    checkForEmailComposition,
    extractEmailContent,
    extractReadingEmailContent,
    forceEmailDetection,
    forceRefreshEmailDetection,
    analyzePageForEmailContent,
    debugEmailDetection,
    getEmailDetectionState,
    // Add new functions
    extractGmailReadingContent,
    extractGmailSubject,
    extractGmailSender,
    extractGmailBody,
    cleanGmailContent,
    extractEmailContentManually,
    extractFromMainContentAggressive,
    // Add test function
    testEmailExtraction
};

console.log('🛡️ Enhanced Phishing Detection Content Script Ready');

// Send a ready message to background script
try {
    chrome.runtime.sendMessage({
        action: 'contentScriptReady',
        url: window.location.href,
        timestamp: Date.now()
    });
    console.log('✅ Ready message sent to background script');
} catch (error) {
    console.log('ℹ️ Background script not accessible yet:', error.message);
}
