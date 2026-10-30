// Global variables for feedback
let currentFeedback = null;
let currentAnalysisData = null;
let currentUrl = null;
let apiServerUrl = 'http://localhost:5000';
let apiConnected = false;

// Performance optimization variables
let animationFrameId = null;
let componentCache = new Map();
let loadedComponents = new Set();
let resizeTimeoutId = null;

// Debug mode
const DEBUG = true;
function debugLog(...args) {
  if (DEBUG) console.log('[Phishing Hunter]', ...args);
}

// Utility functions for performance optimization
const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

const throttle = (func, limit) => {
  let inThrottle;
  return function() {
    const args = arguments;
    const context = this;
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};

// Lazy loading utility
const lazyLoad = (componentName, loader) => {
  if (loadedComponents.has(componentName)) {
    return Promise.resolve(componentCache.get(componentName));
  }
  
  return loader().then(component => {
    componentCache.set(componentName, component);
    loadedComponents.add(componentName);
    return component;
  });
};

// RequestAnimationFrame wrapper for smooth animations
const smoothAnimation = (callback) => {
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
  }
  animationFrameId = requestAnimationFrame(callback);
};

// Optimized Neural Network Background Generator with lazy loading
const createNeuralNetwork = debounce(() => {
  lazyLoad('neuralNetwork', async () => {
    const neuralNetwork = document.getElementById('neuralNetwork');
    if (!neuralNetwork) return null;
    
    // Use DocumentFragment for efficient DOM manipulation
    const fragment = document.createDocumentFragment();
    
    const width = Math.min(window.innerWidth || 450, 450);
    const height = Math.min(window.innerHeight || 580, 580);
    
    // Reduce node count for better performance
    const nodeCount = Math.min(Math.floor((width * height) / 35000), 20);
    const nodes = [];
    
    // Batch DOM operations
    for (let i = 0; i < nodeCount; i++) {
      const node = document.createElement('div');
      node.className = 'neural-node';
      
      const x = Math.random() * (width - 20) + 10;
      const y = Math.random() * (height - 20) + 10;
      
      // Use transform instead of left/top for better performance
      node.style.transform = `translate(${x}px, ${y}px)`;
      node.style.animationDelay = Math.random() * 3 + 's';
      
      // Reduce color variations for better performance
      const colorIndex = Math.floor(Math.random() * 2);
      const colors = ['var(--accent-primary)', 'var(--accent-secondary)'];
      const color = colors[colorIndex];
      node.style.background = color;
      node.style.boxShadow = `0 0 8px ${color}`;
      
      fragment.appendChild(node);
      nodes.push({ element: node, x, y });
    }
    
    // Clear and update in one operation
    neuralNetwork.innerHTML = '';
    neuralNetwork.appendChild(fragment);
    
    // Optimized connection creation with reduced complexity
    createConnections(neuralNetwork, nodes);
    
    return neuralNetwork;
  });
}, 300);

// Separate function for creating connections with better performance
function createConnections(container, nodes) {
  const maxDistance = 120; // Reduced for performance
  const connectionFragment = document.createDocumentFragment();
  const maxConnections = 15; // Limit connections
  let connectionCount = 0;
  
  for (let i = 0; i < nodes.length && connectionCount < maxConnections; i++) {
    for (let j = i + 1; j < nodes.length && connectionCount < maxConnections; j++) {
      const nodeA = nodes[i];
      const nodeB = nodes[j];
      
      const distance = Math.sqrt(
        Math.pow(nodeA.x - nodeB.x, 2) + 
        Math.pow(nodeA.y - nodeB.y, 2)
      );
      
      if (distance < maxDistance && Math.random() > 0.8) {
        const connection = document.createElement('div');
        connection.className = 'neural-connection';
        
        const angle = Math.atan2(nodeB.y - nodeA.y, nodeB.x - nodeA.x);
        
        // Use transform for better performance
        connection.style.transform = `translate(${nodeA.x}px, ${nodeA.y}px) rotate(${angle}rad)`;
        connection.style.width = distance + 'px';
        connection.style.animationDelay = Math.random() * 4 + 's';
        
        connectionFragment.appendChild(connection);
        connectionCount++;
      }
    }
  }
  
  container.appendChild(connectionFragment);
  
  // Throttled animation updates
  const animateConnections = throttle(() => {
    const connections = container.querySelectorAll('.neural-connection');
    connections.forEach(connection => {
      if (Math.random() > 0.95) { // Reduced frequency
        smoothAnimation(() => {
          connection.style.animation = 'none';
          setTimeout(() => {
            connection.style.animation = 'connectionFlow 4s linear infinite';
          }, 10);
        });
      }
    });
  }, 3000); // Increased interval
  
  // Set up periodic animation with cleanup
  const intervalId = setInterval(animateConnections, 3000);
  
  // Store interval ID for cleanup
  if (!window.phishingHunterIntervals) {
    window.phishingHunterIntervals = [];
  }
  window.phishingHunterIntervals.push(intervalId);
}

// Optimized Enhanced Loading Animation with lazy loading
const createEnhancedSpinner = (() => {
  let stylesInjected = false;
  
  return lazyLoad('enhancedSpinner', async () => {
    const loading = document.getElementById('loading');
    if (!loading) return null;
    
    // Inject styles only once
    if (!stylesInjected) {
      const style = document.createElement('style');
      style.id = 'enhanced-spinner-styles';
      style.textContent = `
        .advanced-loader {
          position: relative;
          width: 100px;
          height: 100px;
          margin: 0 auto;
          will-change: transform;
        }
        
        .loader-ring {
          position: absolute;
          border: 2px solid transparent;
          border-radius: 50%;
          animation: rotate 2s linear infinite;
          will-change: transform;
        }
        
        .loader-ring:nth-child(1) {
          width: 70px;
          height: 70px;
          top: 15px;
          left: 15px;
          border-top-color: var(--accent-primary);
          animation-duration: 1.5s;
        }
        
        .loader-ring:nth-child(2) {
          width: 50px;
          height: 50px;
          top: 25px;
          left: 25px;
          border-right-color: var(--accent-secondary);
          animation-duration: 2s;
          animation-direction: reverse;
        }
        
        .loader-ring:nth-child(3) {
          width: 30px;
          height: 30px;
          top: 35px;
          left: 35px;
          border-bottom-color: var(--success);
          animation-duration: 1s;
        }
        
        .loader-text {
          position: absolute;
          top: 80px;
          left: 50%;
          transform: translateX(-50%);
          font-family: 'Orbitron', monospace;
          font-size: 0.8em;
          font-weight: 600;
          color: var(--accent-primary);
          text-shadow: 0 0 8px var(--accent-primary);
          animation: textGlow 2s ease-in-out infinite alternate;
          will-change: opacity;
        }
        
        .loader-subtext {
          position: absolute;
          top: 95px;
          left: 50%;
          transform: translateX(-50%);
          font-size: 0.5em;
          color: var(--text-muted);
          white-space: nowrap;
          animation: fadeInOut 3s ease-in-out infinite;
          will-change: opacity;
        }
        
        @keyframes rotate {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        @keyframes textGlow {
          0% { opacity: 0.8; }
          100% { opacity: 1; }
        }
        
        @keyframes fadeInOut {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
      `;
      
      document.head.appendChild(style);
      stylesInjected = true;
    }
    
    // Use template for better performance
    const spinnerTemplate = `
      <div class="advanced-loader">
        <div class="loader-ring"></div>
        <div class="loader-ring"></div>
        <div class="loader-ring"></div>
        <div class="loader-text">ANALYZING...</div>
        <div class="loader-subtext">Neural networks processing threat data</div>
      </div>
    `;
    
    loading.innerHTML = spinnerTemplate;
    return loading;
  });
});

// Test API server connection
async function testApiConnection() {
  try {
    console.log('Testing API server connection...');
    const response = await fetch(`${apiServerUrl}/health`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (response.ok) {
      const healthData = await response.json();
      console.log('API server connected:', healthData);
      apiConnected = true;
      return true;
    } else {
      throw new Error(`Health check failed: ${response.status}`);
    }
  } catch (error) {
    console.error('API server connection failed:', error);
    apiConnected = false;
    showError('Cannot connect to analysis server. Please ensure the API server is running on localhost:5000');
    return false;
  }
}

// Analyze current page
async function analyzeCurrentPage() {
  if (!apiConnected) {
    await testApiConnection(); // Try to reconnect
    if (!apiConnected) {
      showError('API server not connected. Please ensure the API server is running on localhost:5000');
      return;
    }
  }
  
  if (!currentUrl || !currentUrl.startsWith('http')) {
    showError('Invalid URL for analysis. Please ensure you are on a valid web page.');
    return;
  }
  
  showLoading();
  
  try {
    const analysisData = await performAnalysis(currentUrl);
    showResult(analysisData);
    showAiExplanation(currentUrl);
  } catch (error) {
    console.error('Analysis failed:', error);
    showError(`Analysis failed: ${error.message}`);
  }
}

// Perform URL analysis with the API server
async function performAnalysis(url) {
  try {
    console.log("Sending analysis request for URL:", url);
    const response = await fetch(`${apiServerUrl}/check_url?url=${encodeURIComponent(url)}`, {
      method: 'GET',
      mode: 'cors',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Server error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    console.log("Analysis response:", data);
    
    // Store for feedback purposes
    currentAnalysisData = data;
    
    return data;
  } catch (error) {
    console.error("Analysis request failed:", error);
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error('Cannot connect to analysis server. Please ensure it is running.');
    }
    throw error;
  }
}

// Optimized DOM manipulation functions with efficient updates
const showLoading = (() => {
  let loadingElement = null;
  let resultElement = null;
  let errorElement = null;
  
  return () => {
    // Cache DOM elements for better performance
    if (!loadingElement) loadingElement = document.getElementById('loading');
    if (!resultElement) resultElement = document.getElementById('result');
    if (!errorElement) errorElement = document.getElementById('error');
    
    // Use requestAnimationFrame for smooth transitions
    smoothAnimation(() => {
      if (loadingElement) {
        loadingElement.classList.remove('hidden');
        loadingElement.style.display = 'block';
      }
      if (resultElement) {
        resultElement.classList.add('hidden');
        resultElement.style.display = 'none';
      }
      if (errorElement) {
        errorElement.classList.add('hidden');
        errorElement.style.display = 'none';
      }
    });
  };
})();

const showError = (() => {
  let loadingElement = null;
  let resultElement = null;
  let errorElement = null;
  
  return (msg) => {
    // Cache DOM elements
    if (!loadingElement) loadingElement = document.getElementById('loading');
    if (!resultElement) resultElement = document.getElementById('result');
    if (!errorElement) errorElement = document.getElementById('error');
    
    smoothAnimation(() => {
      if (loadingElement) {
        loadingElement.classList.add('hidden');
        loadingElement.style.display = 'none';
      }
      if (resultElement) {
        resultElement.classList.add('hidden');
        resultElement.style.display = 'none';
      }
      if (errorElement) {
        errorElement.classList.remove('hidden');
        errorElement.style.display = 'block';
        
        // Efficient message update
        const errorMessage = errorElement.querySelector('.error-message');
        const errorDetails = errorElement.querySelector('.error-details');
        
        if (errorMessage) {
          errorMessage.textContent = 'Analysis Error';
        }
        if (errorDetails) {
          errorDetails.textContent = msg;
        }
      } else {
        console.error('Error:', msg);
      }
    });
  };
})();

// Optimized monitoring status with lazy loading
const displayMonitoringStatus = debounce(() => {
  console.log('Monitoring status requested');
  // Lazy load monitoring components when needed
}, 500);

// Optimized initialization with code splitting and lazy loading
document.addEventListener('DOMContentLoaded', async () => {
  debugLog('Popup loaded, initializing...');
  
  // Phase 1: Critical UI initialization (immediate)
  try {
    await initializeCriticalUI();
  } catch (error) {
    debugLog('Critical UI initialization failed:', error);
  }
  
  // Phase 2: Non-critical components (lazy loaded)
  requestIdleCallback(() => {
    initializeNonCriticalComponents();
  });
  
  // Phase 3: Analysis functionality (deferred)
  setTimeout(() => {
    initializeAnalysis();
  }, 100);
});

// Phase 1: Critical UI components that must load immediately
async function initializeCriticalUI() {
  try {
    // Initialize tab navigation first (most important for UX)
    initializeTabNavigation();
    
    // Load essential settings
    loadSettings();
    
    // Initialize basic UI components
    initializeUIComponents();
    
    // Initialize email components
    initializeEmailComponents();
    
    // Initialize real-time monitoring status
    await initializeMonitoringStatus();
  } catch (error) {
    debugLog('Critical UI initialization error:', error);
    throw error;
  }
}

// Phase 2: Non-critical components loaded when browser is idle
async function initializeNonCriticalComponents() {
  try {
    // Enhanced loading spinner (lazy loaded)
    await createEnhancedSpinner();
    
    // Neural network background (lazy loaded)
    setTimeout(() => {
      createNeuralNetwork();
    }, 200);
    
    // Load statistics
    loadStats();
  } catch (error) {
    debugLog('Non-critical components initialization failed:', error);
  }
}

// Initialize analysis function
async function initializeAnalysis() {
  debugLog('Starting analysis initialization...');
  
  // Test API server connection first
  const connected = await testApiConnection();
  if (!connected) {
    debugLog('API connection failed, analysis stopped');
    return;
  }
  
  // Get current tab and start analysis
  try {
    // Check if chrome.tabs is available
    if (!chrome || !chrome.tabs) {
      debugLog('Chrome tabs API not available');
      showError('Extension API not available. Please reload the extension.');
      return;
    }
    
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
      currentUrl = tab.url;
      debugLog('Current URL:', currentUrl);
      await analyzeCurrentPage();
    } else {
      showError('Cannot analyze this page (system page or extension page)');
    }
  } catch (error) {
    debugLog('Failed to get current tab:', error);
    showError('Failed to get current page information');
  }
}

// Optimized global function to show results with efficient DOM updates
const showResult = (() => {
  let cachedElements = {};
  
  const getCachedElement = (id) => {
    if (!cachedElements[id]) {
      cachedElements[id] = document.getElementById(id);
    }
    return cachedElements[id];
  };
  
  return (data) => {
    if (!data) {
      showError('Invalid or empty response data');
      return;
    }
    
    // Store current analysis data for feedback
    currentAnalysisData = data;
    
    // Update statistics asynchronously
    requestIdleCallback(() => {
      if (data.safe) {
        updateStats('safe');
      } else if (data.risk_percentage > 60) {
        updateStats('threat');
      } else {
        updateStats('scan');
      }
    });
    
    // Use requestAnimationFrame for smooth UI updates
    smoothAnimation(() => {
      // Cache DOM elements
      const loading = getCachedElement('loading');
      const result = getCachedElement('result');
      const errorDiv = getCachedElement('error');
      
      // Show result UI efficiently
      if (loading) loading.style.display = 'none';
      if (result) result.style.display = 'block';
      if (errorDiv) errorDiv.style.display = 'none';
      
      // Batch DOM updates
      updateResultContent(data);
    });
    
    console.log('Result displayed successfully');
  };
})();

// Separate function for updating result content
function updateResultContent(data) {
  const isSafe = data.safe;
  const isLegitimateWebsite = data.is_legitimate_brand;
  const riskPercentage = data.risk_percentage || 0;
  
  console.log('Updating result content with:', { isSafe, isLegitimateWebsite, riskPercentage, data });
  
  // Use DocumentFragment for efficient DOM updates
  const updates = [];
  
  // Update status icon and text
  const statusIcon = document.getElementById('statusIcon');
  const statusText = document.getElementById('statusText');
  
  if (statusIcon && statusText) {
    if (isSafe) {
      statusIcon.textContent = '✅';
      statusIcon.className = 'status-icon status-safe';
      statusText.textContent = isLegitimateWebsite ? 'Legitimate Brand' : 'Safe';
      statusText.className = 'status-text status-safe';
    } else {
      if (riskPercentage > 80) {
        statusIcon.textContent = '🚨';
        statusIcon.className = 'status-icon status-critical';
        statusText.textContent = 'Critical Threat';
        statusText.className = 'status-text status-critical';
      } else if (riskPercentage > 60) {
        statusIcon.textContent = '⚠️';
        statusIcon.className = 'status-icon status-danger';
        statusText.textContent = 'High Risk';
        statusText.className = 'status-text status-danger';
      } else {
        statusIcon.textContent = '⚠️';
        statusIcon.className = 'status-icon status-warning';
        statusText.textContent = 'Warning';
        statusText.className = 'status-text status-warning';
      }
    }
  }
  
  // Update reason
  const reason = document.getElementById('reason');
  if (reason) reason.textContent = data.reason || 'No details available';
  
  // Update risk bar with CSS transitions
  const riskBar = document.getElementById('riskFill');
  const riskText = document.getElementById('riskText');
  
  console.log('Risk bar elements:', { riskBar, riskText, riskPercentage });
  
  if (riskBar && riskText) {
    // Ensure the element is visible first
    riskBar.style.display = 'block';
    
    // Use transform for better performance
    const scaleValue = riskPercentage / 100;
    console.log('Setting risk bar scale to:', scaleValue);
    
    // Try both transform and width for maximum compatibility
    riskBar.style.transform = `scaleX(${scaleValue})`;
    riskBar.style.width = `${riskPercentage}%`; // Fallback
    
    riskText.textContent = `${Math.round(riskPercentage)}% THREAT LEVEL`;
    
    // Set risk bar color class efficiently
    const riskClass = riskPercentage > 75 ? 'high-risk' : 
                     riskPercentage > 40 ? 'medium-risk' : 'low-risk';
    riskBar.className = `risk-fill ${riskClass}`;
    
    console.log('Risk bar updated with class:', riskBar.className, 'transform:', riskBar.style.transform, 'width:', riskBar.style.width);
  } else {
    console.error('Risk bar elements not found:', { riskBar, riskText });
  }
  
  // Update details section asynchronously
  requestIdleCallback(() => {
    updateDetailsSection(data);
    
    // Show source code analysis if available
    if (data.source_analysis) {
      showSourceCodeAnalysis(data.source_analysis);
    }
  });
}

  // Optimized details section update with efficient DOM manipulation
  const updateDetailsSection = (() => {
    let detailsElement = null;
    
    return (data) => {
      if (!detailsElement) {
        detailsElement = document.getElementById('details');
      }
      if (!detailsElement) return;
      
      // Use DocumentFragment for efficient DOM updates
      const fragment = document.createDocumentFragment();
      
      // Build details array for batch processing
      const details = [];
      
      if (data.processing_time) {
        details.push(['Processing Time', `${data.processing_time.toFixed(2)}s`]);
      }
      
      if (data.ml_prediction) {
        details.push(['ML Prediction', data.ml_prediction]);
      }
      
      if (data.confidence !== undefined) {
        details.push(['Confidence', `${Math.round(data.confidence * 100)}%`]);
      }
      
      if (data.verdict) {
        details.push(['Verdict', data.verdict]);
      }
      
      if (data.is_legitimate_brand) {
        details.push(['Brand Status', 'Verified Legitimate']);
      } else if (data.is_likely_legitimate) {
        details.push(['Brand Status', 'Likely Legitimate']);
      }
      
      // Create all detail items in batch
      details.forEach(([label, value]) => {
        const item = addDetailItemToFragment(fragment, label, value);
      });
      
      // Single DOM update
      detailsElement.innerHTML = '';
      detailsElement.appendChild(fragment);
    };
  })();
  
  // Optimized helper function for creating detail items
  function addDetailItemToFragment(fragment, label, value) {
    const item = document.createElement('div');
    item.className = 'detail-item';
    
    const labelEl = document.createElement('span');
    labelEl.className = 'detail-label';
    labelEl.textContent = label;
    
    const valueEl = document.createElement('span');
    valueEl.className = 'detail-value';
    valueEl.textContent = value;
    
    item.appendChild(labelEl);
    item.appendChild(valueEl);
    fragment.appendChild(item);
    
    return item;
  }
  
  // New function to handle source code analysis results with special handling for brands
  function showSourceCodeAnalysis(analysisData) {
    if (!sourceCodeAnalysisDiv) return;
    
    // Create or update source code analysis section
    sourceCodeAnalysisDiv.innerHTML = '';
    sourceCodeAnalysisDiv.style.display = 'block';
    
    // Create header
    const header = document.createElement('h3');
    header.textContent = 'Page Analysis';
    sourceCodeAnalysisDiv.appendChild(header);
    
    // If site is recognized as a legitimate brand, show that first
    if (analysisData.isLegitimate) {
      const brandInfo = document.createElement('div');
      brandInfo.className = 'brand-info';
      
      if (analysisData.brandName) {
        brandInfo.innerHTML = `<strong>✓ Recognized ${analysisData.brandName} site</strong>`;
      } else {
        brandInfo.innerHTML = `<strong>✓ Likely legitimate site</strong>`;
      }
      
      sourceCodeAnalysisDiv.appendChild(brandInfo);
      
      // If no significant threats were found on the legitimate site, show that
      if (analysisData.threatIndicators.length === 0 || 
          (analysisData.threatIndicators.length === 1 && analysisData.riskScore < 20)) {
        const safeInfo = document.createElement('p');
        safeInfo.textContent = 'No suspicious code patterns detected';
        safeInfo.className = 'safe-info';
        sourceCodeAnalysisDiv.appendChild(safeInfo);
        return;
      }
    }
    
    // Add threat indicators if any
    if (analysisData.threatIndicators && analysisData.threatIndicators.length > 0) {
      const threatList = document.createElement('ul');
      threatList.className = 'threat-list';
      
      // Map threat codes to user-friendly descriptions
      const threatMapping = {
        'obfuscatedJS': 'Obfuscated JavaScript detected',
        'hiddenElements': 'Hidden elements present',
        'externalFormSubmission': 'Form submits to external domain',
        'credentialStealingForms': 'Potential credential stealing',
        'hiddenFormElements': 'Hidden elements in forms',
        'suspiciousScripts': 'Suspicious scripts detected',
        'passwordFieldsInHiddenElements': 'Password fields in hidden elements',
        'documentWriteLongString': 'Dynamically written content',
        'multipleSuspiciousForms': 'Multiple suspicious forms',
        'multipleExternalIframes': 'Multiple external frames'
      };
      
      // Only show the most important threats (up to 3)
      const priorityOrder = [
        'credentialStealingForms', 
        'passwordFieldsInHiddenElements',
        'suspiciousScripts',
        'obfuscatedJS',
        'externalFormSubmission',
        'hiddenFormElements'
      ];
      
      // Sort threats by priority
      const sortedThreats = [...analysisData.threatIndicators].sort((a, b) => {
        const indexA = priorityOrder.indexOf(a);
        const indexB = priorityOrder.indexOf(b);
        return (indexA === -1 ? 999 : indexA) - (indexB === -1 ? 999 : indexB);
      });
      
      // Show at most 3 threats
      const threatsToShow = sortedThreats.slice(0, 3);
      
      threatsToShow.forEach(threat => {
        const item = document.createElement('li');
        item.className = 'threat-item';
        item.textContent = threatMapping[threat] || threat;
        threatList.appendChild(item);
      });
      
      if (threatsToShow.length > 0) {
        sourceCodeAnalysisDiv.appendChild(threatList);
      }
      
      // Add warning if high risk
      // Adjust threshold based on whether it's a legitimate site
      const riskThreshold = analysisData.isLegitimate ? 60 : 40;
      if (analysisData.riskScore > riskThreshold) {
        const warning = document.createElement('div');
        warning.className = 'source-code-warning';
        warning.textContent = `Suspicious code detected (Risk: ${analysisData.riskScore}/100)`;
        sourceCodeAnalysisDiv.appendChild(warning);
      }
    } else {
      // No threats found
      const noThreats = document.createElement('p');
      noThreats.textContent = 'No suspicious code patterns detected';
      noThreats.className = 'safe-info';
      sourceCodeAnalysisDiv.appendChild(noThreats);
    }
    
    // Add details if available
    if (analysisData.threatDetails && (
        (analysisData.threatDetails.forms && analysisData.threatDetails.forms.passwordFieldsCount > 0) || 
        (analysisData.threatDetails.scripts && analysisData.threatDetails.scripts.suspicious > 0))
    ) {
      const details = document.createElement('div');
      details.className = 'code-details';
      
      if (analysisData.threatDetails.forms) {
        const formInfo = document.createElement('p');
        formInfo.textContent = `Forms: ${analysisData.threatDetails.forms.passwordFieldsCount > 0 ? 
          `Contains ${analysisData.threatDetails.forms.passwordFieldsCount} password fields` : 'No password fields'}`;
        
        if (analysisData.threatDetails.forms.credentialStealingForms > 0) {
          formInfo.textContent += ` - Submits to external domain`;
          formInfo.className = 'warning-detail';
        }
        details.appendChild(formInfo);
      }
      
      if (analysisData.threatDetails.scripts && analysisData.threatDetails.scripts.suspicious > 0) {
        const scriptInfo = document.createElement('p');
        scriptInfo.className = 'warning-detail';
        scriptInfo.textContent = `${analysisData.threatDetails.scripts.suspicious} suspicious scripts detected`;
        details.appendChild(scriptInfo);
      }
      
      if (details.childNodes.length > 0) {
        sourceCodeAnalysisDiv.appendChild(details);
      }
    }
  }
  
  // Function to request source code analysis from content script
  function requestSourceCodeAnalysis() {
    if (!sourceCodeAnalysisDiv) return;
    
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (!tabs || !tabs.length) return;
      
      const activeTab = tabs[0];
      
      // First try to see if we already have analysis results
      chrome.runtime.sendMessage({action: 'getSourceCodeAnalysis'}, (response) => {
        if (response && response.data) {
          showSourceCodeAnalysis(response.data);
        } else {
          // Request new analysis from content script
          chrome.tabs.sendMessage(activeTab.id, {action: 'analyzeSourceCode'}, (response) => {
            if (response) {
              showSourceCodeAnalysis(response);
            } else if (sourceCodeAnalysisDiv) {
              // Content script may not be loaded or accessible
              sourceCodeAnalysisDiv.innerHTML = '<p>Source code analysis not available for this page</p>';
            }
          });
        }
      });
    });
  }

  // First check if server is running
  async function checkServerHealth() {
    try {
        console.log("Checking server health...");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // 5s timeout
        
        const healthResponse = await fetch('http://localhost:5000/health', {
            signal: controller.signal,
            mode: 'cors',  // Explicitly set CORS mode
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        
        clearTimeout(timeoutId);
        
        if (!healthResponse.ok) {
            throw new Error(`Server health check failed: ${healthResponse.status}`);
        }
        
        const healthData = await healthResponse.json();
        console.log("Server health check response:", healthData);
        
        if (!healthData.detector_loaded) {
            throw new Error("Phishing detector not properly initialized");
        }
        
        return true;
    } catch (healthError) {
        console.error("Server health check failed:", healthError);
        showError(`Server connection failed. Please ensure the API server is running at http://localhost:5000\n\nError: ${healthError.message}`);
        return false;
    }
  }

  // Update the URL analysis function
  async function analyzeUrl(url) {
    try {
        console.log("Sending analysis request for URL:", url);
        const response = await fetch(`http://localhost:5000/check_url?url=${encodeURIComponent(url)}`, {
            method: 'GET',
            mode: 'cors',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }

        const data = await response.json();
        console.log("Analysis response:", data);
        return data;
    } catch (error) {
        console.error("Analysis request failed:", error);
        throw error;
    }
  }

  // Add event listeners for simplified popup buttons after DOM is ready
  setTimeout(() => {
    const retryButton = document.getElementById('retry');
    if (retryButton) {
      retryButton.addEventListener('click', async () => {
        if (currentUrl) {
          analyzeCurrentPage();
        } else {
          // Re-get current tab URL and analyze
          try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
              currentUrl = tab.url;
              analyzeCurrentPage();
            } else {
              showError('Cannot analyze this page (system page or extension page)');
            }
          } catch (error) {
            showError('Failed to get current page information');
          }
        }
      });
    }
    
    const reportButton = document.getElementById('reportIssue');
    if (reportButton) {
      reportButton.addEventListener('click', () => {
        if (currentAnalysisData && currentUrl) {
          reportFeedback('issue');
        }
      });
    }
  }, 100); // Small delay to ensure DOM elements are available
  
// Listen for source code analysis results from content script
if (chrome.runtime) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'sourceCodeAnalysisResult' || message.action === 'sourceCodeThreatUpdated') {
      showSourceCodeAnalysis(message.data);
    }
    return true;
  });
}

// Enhanced detailed analysis with dramatic effects
document.addEventListener('click', async (e) => {
  if (e.target.id === 'detailedAnalysis') {
    try {
      // Dramatic button transformation
      e.target.textContent = 'INITIATING DEEP SCAN...';
      e.target.style.background = 'linear-gradient(45deg, #ff4444, #ff0066)';
      e.target.style.animation = 'criticalWarning 0.5s ease-in-out infinite alternate';
      
      let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      let url = tab.url;
      
      console.log('🔍 DEEP SCAN PROTOCOL ACTIVATED:', url);
      
      const response = await fetch('http://localhost:5000/analyze_detailed', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url })
      });
      
      const data = await response.json();
      console.log('📊 DEEP SCAN RESULTS:', data);
      
      // Update UI with dramatic layer results
      if (data.layer_results) {
        // Create enhanced layer results that include ensemble and final verdict
        let enhancedLayers = [...data.layer_results];
        
        // Add Ensemble Decision layer if available
        if (data.ensemble_result) {
          enhancedLayers.push({
            layer: 'Ensemble Decision',
            risk_score: data.ensemble_result.weighted_risk_score || 0,
            weight: 1.0,
            flags: data.ensemble_result.conflicts || [],
            consensus: data.ensemble_result.consensus,
            layer_scores: data.ensemble_result.layer_scores
          });
        }
        
        // Add Final Verdict layer if available  
        if (data.final_result) {
          enhancedLayers.push({
            layer: 'Final Verdict',
            risk_score: data.final_result.risk_percentage || 0,
            weight: 1.0,
            flags: data.final_result.recommendations || [],
            verdict: data.final_result.verdict,
            confidence: data.final_result.confidence
          });
        }
        
        displayLayerResults(enhancedLayers);
        
        // Dramatic completion
        e.target.textContent = 'SCAN COMPLETE';
        e.target.style.background = 'linear-gradient(45deg, #00ff88, #00aa44)';
        e.target.style.animation = 'safeGlow 2s ease-in-out infinite alternate';
        e.target.disabled = true;
        
        // Show additional detailed info matching final verdict logic
        const additionalInfo = document.getElementById('additionalInfo');
        if (additionalInfo && data.final_result) {
          const finalResult = data.final_result;
          additionalInfo.innerHTML = `
            <div class="additional-details">
              <h4>Enhanced Detection Results:</h4>
              <p><strong>Processing Time:</strong> ${(data.processing_time * 1000).toFixed(1)}ms</p>
              <p><strong>Total Layers:</strong> ${enhancedLayers.length}</p>
              <p><strong>ML Weight:</strong> 1.5x (Enhanced for phishing detection)</p>
              <p><strong>Consensus:</strong> ${data.ensemble_result?.consensus || 'N/A'}</p>
              ${finalResult.recommendations ? 
                `<div class="recommendations">
                  <strong>Security Recommendations:</strong>
                  ${finalResult.recommendations.slice(0, 3).map(rec => `<div>• ${rec}</div>`).join('')}
                </div>` : ''
              }
              ${data.ensemble_result?.conflicts?.length > 0 ?
                `<div class="conflicts">
                  <strong>Layer Conflicts:</strong>
                  ${data.ensemble_result.conflicts.map(conflict => `<div>⚠️ ${conflict}</div>`).join('')}
                </div>` : ''
              }
            </div>
          `;
          additionalInfo.style.display = 'block';
        }
      }
      
    } catch (error) {
      console.error('🚨 DEEP SCAN FAILURE:', error);
      e.target.textContent = 'SCAN FAILED';
      e.target.style.background = 'linear-gradient(45deg, #666, #333)';
      e.target.style.animation = 'errorShake 0.5s ease-in-out';
    }
  }
});

// Optimized layer results display with lazy loading and efficient DOM manipulation
const displayLayerResults = (() => {
  let layerResultsElement = null;
  
  // Template cache for better performance
  const templates = {
    header: '<h4 style="color: #ffffff; font-family: Orbitron, monospace; text-align: center; margin-bottom: 16px; text-shadow: 0 0 10px #667eea;">🔍 ADVANCED THREAT ANALYSIS 🔍</h4>',
    
    contentAnalysis: (layer) => {
      const { content_analysis: content, ssl_info: ssl, form_analysis: forms, js_analysis: js } = layer;
      
      return `
        <div style="margin-top: 8px; padding: 8px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
          <strong style="color: #00aaff;">🌐 WEBSITE SCAN RESULTS:</strong>
          ${ssl?.has_ssl ? '🔒 SSL Certificate Valid' : '⚠️ No SSL/Invalid Certificate'}
          ${content?.phishing_keywords_found?.length ? `<br>🚨 Phishing Keywords: ${content.phishing_keywords_found.length}` : ''}
          ${forms?.form_count ? `<br>📝 Forms Detected: ${forms.form_count}` : ''}
          ${forms?.sensitive_forms?.length ? `<br>🔐 Sensitive Data Collection: ${forms.sensitive_forms.length} forms` : ''}
          ${forms?.external_submission ? '<br>⚠️ Data Forwarded to External Domain' : ''}
          ${forms?.insecure_submission ? '<br>🚨 Insecure Form Submission (HTTP)' : ''}
          ${js?.suspicious_patterns?.length ? `<br>⚙️ Suspicious JavaScript: ${js.suspicious_patterns.length} patterns` : ''}
          ${js?.obfuscation_detected ? '<br>🕵️ Code Obfuscation Detected' : ''}
          ${js?.data_collection ? '<br>📊 Data Collection Code Found' : ''}
          ${content?.analysis_type === 'url_based' ? '<br>🔗 URL-Based Analysis (Content Not Available)' : ''}
        </div>
      `;
    },
    
    ensembleDecision: (layer) => `
      <div style="margin-top: 8px; padding: 8px; background: rgba(255,170,0,0.1); border-radius: 4px; border-left: 3px solid #ffaa00;">
        <strong style="color: #ffaa00;">⚖️ ENSEMBLE ANALYSIS:</strong>
        <br><strong>CONSENSUS:</strong> ${layer.consensus.toUpperCase()}
        ${layer.layer_scores ? `<br><strong>LAYER SCORES:</strong><br>${Object.entries(layer.layer_scores).map(([name, score]) => `• ${name}: ${score}%`).join('<br>')}` : ''}
        ${layer.flags?.length ? `<br><strong>CONFLICTS:</strong><br>${layer.flags.map(flag => `⚠️ ${flag}`).join('<br>')}` : ''}
      </div>
    `,
    
    finalVerdict: (layer) => `
      <div style="margin-top: 8px; padding: 8px; background: rgba(255,0,102,0.1); border-radius: 4px; border-left: 3px solid #ff0066;">
        <strong style="color: #ff0066;">🎯 FINAL VERDICT:</strong>
        <br><strong>SECURITY LEVEL:</strong> ${layer.verdict.toUpperCase()}
        <br><strong>CONFIDENCE:</strong> ${((layer.confidence || 0) * 100).toFixed(1)}%
        ${layer.flags?.length ? `<br><strong>RECOMMENDATIONS:</strong><br>${layer.flags.slice(0, 3).map(rec => `• ${rec}`).join('<br>')}` : ''}
      </div>
    `
  };
  
  const getRiskInfo = (riskLevel) => {
    if (riskLevel >= 75) return { color: '#ff0066', label: 'CRITICAL', icon: '☠️' };
    if (riskLevel >= 60) return { color: '#ff4444', label: 'DANGER', icon: '🚨' };
    if (riskLevel >= 35) return { color: '#ffaa00', label: 'SUSPICIOUS', icon: '⚠️' };
    if (riskLevel >= 15) return { color: '#88ff00', label: 'LOW RISK', icon: '🟡' };
    return { color: '#00ff88', label: 'SECURE', icon: '✅' };
  };
  
  const createLayerElement = (layer, index) => {
    const layerDiv = document.createElement('div');
    layerDiv.className = 'layer-result';
    
    const riskLevel = layer.risk_score || 0;
    const layerWeight = layer.weight || 1.0;
    const { color: riskColor, label: riskLabel, icon: riskIcon } = getRiskInfo(riskLevel);
    
    // Determine content based on layer type
    let contentAnalysisHTML = '';
    if (layer.layer === 'Content Analysis' && layer.content_analysis) {
      contentAnalysisHTML = templates.contentAnalysis(layer);
    } else if (layer.layer === 'Ensemble Decision' && layer.consensus) {
      contentAnalysisHTML = templates.ensembleDecision(layer);
    } else if (layer.layer === 'Final Verdict' && layer.verdict) {
      contentAnalysisHTML = templates.finalVerdict(layer);
    }
    
    layerDiv.innerHTML = `
      <div class="layer-header">
        <span class="layer-name">${riskIcon} LAYER ${index + 1}: ${layer.layer.toUpperCase()}</span>
        <span class="layer-risk" style="color: ${riskColor}">
          ${riskLevel.toFixed(1)}% (${riskLabel})
        </span>
      </div>
      <div style="font-size: 0.75em; color: rgba(255,255,255,0.7); margin-bottom: 6px;">
        ANALYSIS WEIGHT: ${layerWeight}x ${layerWeight > 1.0 ? '(ENHANCED)' : ''}
      </div>
      ${layer.flags?.length ? 
        `<div style="margin-top: 6px;">
          ${layer.flags.map(flag => `<div style="font-size: 0.8em; color: #ff4444; margin-bottom: 2px;">🔍 ${flag.toUpperCase()}</div>`).join('')}
        </div>` : ''
      }
      ${layer.ml_prediction ? 
        `<div style="font-size: 0.8em; color: #00aaff; margin-top: 6px; padding: 6px; background: rgba(0,170,255,0.1); border-radius: 4px; border-left: 3px solid #00aaff;">
          <strong>🤖 AI NEURAL NET:</strong> ${layer.ml_prediction.toUpperCase()}
          <br><strong>PROBABILITY:</strong> LEGIT: ${(layer.confidence_scores?.legitimate * 100 || 0).toFixed(1)}%, 
          THREAT: ${(layer.confidence_scores?.phishing * 100 || 0).toFixed(1)}%
          ${layer.inference_time ? `<br><strong>INFERENCE:</strong> ${(layer.inference_time * 1000).toFixed(1)}ms` : ''}
          ${layer.model_info ? `<br><strong>MODEL:</strong> ${layer.model_info.type} (ACC: ${(layer.model_info.accuracy * 100).toFixed(1)}%)` : ''}
        </div>` : ''
      }
      ${contentAnalysisHTML}
    `;
    
    return layerDiv;
  };
  
  return (layers) => {
    if (!layerResultsElement) {
      layerResultsElement = document.getElementById('layerResults');
    }
    if (!layerResultsElement) return;
    
    // Use requestAnimationFrame for smooth rendering
    smoothAnimation(() => {
      // Create document fragment for efficient DOM manipulation
      const fragment = document.createDocumentFragment();
      
      // Add header
      const headerDiv = document.createElement('div');
      headerDiv.innerHTML = templates.header;
      fragment.appendChild(headerDiv);
      
      // Create layer elements in batch
      layers.forEach((layer, index) => {
        const layerElement = createLayerElement(layer, index);
        
        // Add staggered entrance animation
        layerElement.style.animation = `fadeInUp 0.5s ease-out ${index * 0.1}s both`;
        
        fragment.appendChild(layerElement);
      });
      
      // Single DOM update
      layerResultsElement.innerHTML = '';
      layerResultsElement.appendChild(fragment);
      layerResultsElement.style.display = 'block';
    });
  };
})();

// Enhanced popup functionality for user feedback
function createFeedbackSection() {
    const container = document.getElementById('result') || document.body;
    
    // Remove existing feedback section if it exists
    const existingFeedback = document.getElementById('feedbackSection');
    if (existingFeedback) {
        existingFeedback.remove();
    }
    
    const feedbackSection = document.createElement('div');
    feedbackSection.id = 'feedbackSection';
    feedbackSection.innerHTML = `
        <div class="feedback-container">
            <h3>🎯 Help Improve Detection</h3>
            <p>Was this analysis accurate?</p>
            <div class="feedback-buttons">
                <button id="feedbackCorrect" class="feedback-btn correct">✅ Correct</button>
                <button id="feedbackIncorrect" class="feedback-btn incorrect">❌ Incorrect</button>
            </div>
            <div id="feedbackDetails" class="feedback-details" style="display:none;">
                <textarea id="feedbackComment" placeholder="Additional comments (optional)"></textarea>
                <button id="submitFeedback" class="submit-btn">Submit Feedback</button>
            </div>
            <div id="feedbackStatus" class="feedback-status"></div>
        </div>
    `;
    
    container.appendChild(feedbackSection);
    
    // Add event listeners
    document.getElementById('feedbackCorrect').addEventListener('click', () => {
        handleFeedbackResponse('correct');
    });
    
    document.getElementById('feedbackIncorrect').addEventListener('click', () => {
        handleFeedbackResponse('incorrect');
    });
    
    document.getElementById('submitFeedback').addEventListener('click', submitUserFeedback);
}

function handleFeedbackResponse(response) {
    currentFeedback = {
        response: response,
        timestamp: Date.now(),
        url: currentUrl
    };
    
    document.getElementById('feedbackDetails').style.display = 'block';
    
    // Update UI
    const buttons = document.querySelectorAll('.feedback-btn');
    buttons.forEach(btn => btn.classList.remove('selected'));
    document.getElementById(`feedback${response.charAt(0).toUpperCase() + response.slice(1)}`).classList.add('selected');
}

async function submitUserFeedback() {
    const comment = document.getElementById('feedbackComment').value;
    const statusDiv = document.getElementById('feedbackStatus');
    
    try {
        const feedback = {
            ...currentFeedback,
            comment: comment,
            analysisData: currentAnalysisData
        };
        
        // Send to background script
        const response = await chrome.runtime.sendMessage({
            action: 'updateUserFeedback',
            feedback: feedback
        });
        
        if (response && response.success) {
            statusDiv.innerHTML = '✅ Thank you for your feedback!';
            statusDiv.className = 'feedback-status success';
            
            // Hide feedback section after 3 seconds
            setTimeout(() => {
                document.getElementById('feedbackSection').style.display = 'none';
            }, 3000);
        } else {
            throw new Error('Failed to submit feedback');
        }
        
    } catch (error) {
        statusDiv.innerHTML = '❌ Failed to submit feedback';
        statusDiv.className = 'feedback-status error';
    }
}

// function displayMonitoringStatus() {
//     const statusDiv = document.createElement('div');
//     statusDiv.id = 'monitoringStatus';
//     statusDiv.innerHTML = `
//         <div class="monitoring-status">
//             <h4>📊 Monitoring Status</h4>
//             <div id="monitoringInfo">
//                 <p>🔍 Background monitoring: <span id="monitoringEnabled">Active</span></p>
//                 <p>📊 Risk assessments: <span id="riskAssessments">0</span></p>
//                 <p>🔔 Notifications: <span id="notificationCount">0</span></p>
//             </div>
//         </div>
//     `;
    
//     document.body.appendChild(statusDiv);
    
//     // Get monitoring data
//     chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
//         if (tabs[0]) {
//             chrome.runtime.sendMessage({
//                 action: 'getMonitoringData',
//                 tabId: tabs[0].id
//             }, (response) => {
//                 if (response && response.data) {
//                     updateMonitoringDisplay(response.data);
//                 }
//             });
//         }
//     });
// }

function updateMonitoringDisplay(data) {
    const riskAssessmentsEl = document.getElementById('riskAssessments');
    const notificationCountEl = document.getElementById('notificationCount');
    
    if (riskAssessmentsEl) riskAssessmentsEl.textContent = data.riskScore || 0;
    if (notificationCountEl) notificationCountEl.textContent = data.notifications?.length || 0;
    
    if (data.suspiciousActivity && data.suspiciousActivity.length > 0) {
        const infoDiv = document.getElementById('monitoringInfo');
        if (infoDiv) {
            const warningDiv = document.createElement('div');
            warningDiv.className = 'monitoring-warning';
            warningDiv.innerHTML = `⚠️ ${data.suspiciousActivity.length} suspicious activities detected`;
            infoDiv.appendChild(warningDiv);
        }
    }
}

function createNotificationSettings() {
    const settingsDiv = document.createElement('div');
    settingsDiv.id = 'notificationSettings';
    settingsDiv.innerHTML = `
        
    `;
    
    document.body.appendChild(settingsDiv);
    
    // Load current settings
    chrome.runtime.sendMessage({action: 'getNotificationSettings'}, (settings) => {
        if (settings) {
            const enableNotifications = document.getElementById('enableNotifications');
            const contextAware = document.getElementById('contextAware');
            const notificationFrequency = document.getElementById('notificationFrequency');
            
            if (enableNotifications) enableNotifications.checked = settings.enabled !== false;
            if (contextAware) contextAware.checked = settings.contextAware !== false;
            if (notificationFrequency) notificationFrequency.value = settings.frequency || 'medium';
        }
    });
    
    // Save settings
    const saveButton = document.getElementById('saveSettings');
    if (saveButton) {
        saveButton.addEventListener('click', () => {
            const enableNotifications = document.getElementById('enableNotifications');
            const contextAware = document.getElementById('contextAware');
            const notificationFrequency = document.getElementById('notificationFrequency');
            
            const settings = {
                enabled: enableNotifications ? enableNotifications.checked : false,
                contextAware: contextAware ? contextAware.checked : false,
                frequency: notificationFrequency ? notificationFrequency.value : 'medium'
            };
            
            chrome.runtime.sendMessage({
                action: 'updateNotificationSettings',
                settings: settings
            }, (response) => {
                if (response && response.success) {
                    showTemporaryMessage('Settings saved!', 'success');
                }
            });
        });
    }
}

function showTemporaryMessage(message, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `temporary-message ${type}`;
    messageDiv.textContent = message;
    document.body.appendChild(messageDiv);
    
    setTimeout(() => {
        messageDiv.remove();
    }, 3000);
}

// Tab Navigation Functions
function initializeTabNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs and contents
            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));
            
            // Add active class to clicked tab
            tab.classList.add('active');
            
            // Show corresponding content
            const targetTab = tab.getAttribute('data-tab');
            const targetContent = document.getElementById(`${targetTab}-tab`);
            if (targetContent) {
                targetContent.classList.add('active');
                
                // Load specific content for each tab
                if (targetTab === 'history') {
                    displayEmailHistory();
                }
            }
        });
    });
}

// Initialize UI Components
function initializeUIComponents() {
    // Protection toggle
    const protectionToggle = document.getElementById('protectionToggle');
    if (protectionToggle) {
        protectionToggle.addEventListener('change', (e) => {
            updateProtectionStatus(e.target.checked);
        });
    }
    
    // Settings toggles
    const settingsToggles = [
        'realtimeProtection', 
        'autoScanDownloads', 
        'showNotifications', 
        'blockSuspicious', 
        'deepLearning',
        'autoThreatAlerts',
        'criticalSounds',
        'lowRiskNotifications',
        'badgeUpdates'
    ];
    settingsToggles.forEach(toggleId => {
        const toggle = document.getElementById(toggleId);
        if (toggle) {
            toggle.addEventListener('change', (e) => {
                saveSetting(toggleId, e.target.checked);
                
                // Send notification settings updates to background script
                if (['autoThreatAlerts', 'criticalSounds', 'lowRiskNotifications', 'badgeUpdates'].includes(toggleId)) {
                    updateBackgroundNotificationSettings();
                }
            });
        }
    });
    
    // Action buttons
    const actionButtons = {
        'clearHistory': () => clearScanHistory(),
        'exportSettings': () => exportSettings(),
        'reportSafe': () => reportFeedback('safe'),
        'reportPhishing': () => reportFeedback('phishing'),
        'testNotifications': () => testNotificationSystem()
    };
    
    Object.keys(actionButtons).forEach(buttonId => {
        const button = document.getElementById(buttonId);
        if (button) {
            button.addEventListener('click', actionButtons[buttonId]);
        }
    });
}

// Load and save settings with error handling
function loadSettings() {
    // Check if chrome.storage is available
    if (!chrome || !chrome.storage || !chrome.storage.local) {
        console.warn('Chrome storage API not available, using defaults');
        applyDefaultSettings();
        return;
    }
    
    try {
        chrome.storage.local.get(['phishingHunterSettings'], (result) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error:', chrome.runtime.lastError);
                applyDefaultSettings();
                return;
            }
            
            const settings = result.phishingHunterSettings || {};
            applySettingsToUI(settings);
        });
    } catch (error) {
        console.error('Failed to load settings:', error);
        applyDefaultSettings();
    }
}

function applyDefaultSettings() {
    const defaultSettings = {
        'realtimeProtection': true,
        'autoScanDownloads': false,
        'showNotifications': true,
        'blockSuspicious': true,
        'deepLearning': true,
        'autoThreatAlerts': true,
        'criticalSounds': true,
        'lowRiskNotifications': false,
        'badgeUpdates': true
    };
    applySettingsToUI(defaultSettings);
}

function applySettingsToUI(settings) {
    // Apply settings to toggles
    const settingsMap = {
        'realtimeProtection': true,
        'autoScanDownloads': false,
        'showNotifications': true,
        'blockSuspicious': true,
        'deepLearning': true,
        'autoThreatAlerts': true,
        'criticalSounds': true,
        'lowRiskNotifications': false,
        'badgeUpdates': true
    };
    
    Object.keys(settingsMap).forEach(key => {
        const toggle = document.getElementById(key);
        if (toggle) {
            toggle.checked = settings[key] !== undefined ? settings[key] : settingsMap[key];
        }
    });
}

function saveSetting(key, value) {
    // Check if chrome.storage is available
    if (!chrome || !chrome.storage || !chrome.storage.local) {
        console.warn('Chrome storage API not available, cannot save setting');
        showTemporaryMessage('Settings cannot be saved (storage unavailable)', 'warning');
        return;
    }
    
    try {
        chrome.storage.local.get(['phishingHunterSettings'], (result) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error:', chrome.runtime.lastError);
                showTemporaryMessage('Failed to save setting', 'warning');
                return;
            }
            
            const settings = result.phishingHunterSettings || {};
            settings[key] = value;
            
            chrome.storage.local.set({ 'phishingHunterSettings': settings }, () => {
                if (chrome.runtime.lastError) {
                    console.error('Storage set error:', chrome.runtime.lastError);
                    showTemporaryMessage('Failed to save setting', 'warning');
                } else {
                    showTemporaryMessage('Setting saved!', 'success');
                }
            });
        });
    } catch (error) {
        console.error('Failed to save setting:', error);
        showTemporaryMessage('Failed to save setting', 'warning');
    }
}

function testNotificationSystem() {
    console.log('🧪 Testing notification system...');
    
    // First check browser notification permissions
    if ('Notification' in window) {
        console.log('📋 Browser notification permission:', Notification.permission);
        
        if (Notification.permission === 'denied') {
            showTemporaryMessage('❌ Browser notifications are BLOCKED! Enable in Chrome Settings → Site Settings → Notifications', 'error');
            console.error('❌ Browser notifications denied');
            return;
        }
        
        if (Notification.permission === 'default') {
            showTemporaryMessage('🔔 Requesting notification permission...', 'info');
            Notification.requestPermission().then(permission => {
                console.log('📋 New notification permission:', permission);
                if (permission === 'granted') {
                    showTemporaryMessage('✅ Permission granted! Trying again...', 'success');
                    setTimeout(() => testNotificationSystem(), 1000);
                } else {
                    showTemporaryMessage('❌ Permission denied. Please allow notifications manually.', 'error');
                }
            });
            return;
        }
    }
    
    // Check Chrome extension notification permission
    if (chrome && chrome.permissions) {
        chrome.permissions.contains({permissions: ['notifications']}, (hasPermission) => {
            if (!hasPermission) {
                showTemporaryMessage('❌ Extension lacks notification permission!', 'error');
                console.error('❌ Extension notification permission missing');
                return;
            }
            
            console.log('✅ Extension has notification permission');
            
            // Test direct Chrome notification API
            testDirectNotification();
            
            // Test through background script
            testBackgroundNotification();
        });
    } else {
        // Fallback if permissions API not available
        testDirectNotification();
        testBackgroundNotification();
    }
}

function testDirectNotification() {
    console.log('� Testing direct Chrome notification...');
    
    if (chrome && chrome.notifications) {
        const notificationId = `direct_test_${Date.now()}`;
        
        chrome.notifications.create(notificationId, {
            type: 'basic',
            iconUrl: 'icons/warning.png',
            title: '⚠️ TEST WARNING: Suspicious Site Detected',
            message: 'This is an example of what you\'ll see when visiting a dangerous website. Risk: 75%',
            priority: 1,
            requireInteraction: true
        }, (createdId) => {
            if (chrome.runtime.lastError) {
                showTemporaryMessage('❌ Direct notification failed: ' + chrome.runtime.lastError.message, 'error');
                console.error('❌ Direct notification error:', chrome.runtime.lastError);
            } else {
                showTemporaryMessage('✅ Example warning notification shown!', 'success');
                console.log('✅ Direct notification successful:', createdId);
            }
        });
    } else {
        console.error('❌ Chrome notifications API not available');
        showTemporaryMessage('❌ Chrome notifications API not available', 'error');
    }
}

function testBackgroundNotification() {
    console.log('🔬 Testing background script notification...');
    
    chrome.runtime.sendMessage({
        action: 'testNotification'
    }, (response) => {
        if (chrome.runtime.lastError) {
            showTemporaryMessage('❌ Background script error: ' + chrome.runtime.lastError.message, 'error');
            console.error('❌ Background script error:', chrome.runtime.lastError);
        } else if (response && response.success) {
            showTemporaryMessage('✅ Example threat warning sent! Check your system tray for the warning notification.', 'success');
            console.log('✅ Background notification successful:', response);
        } else {
            showTemporaryMessage('❌ Background notification failed: ' + (response?.error || 'Unknown error'), 'error');
            console.error('❌ Background notification failed:', response);
        }
    });
}

// Load statistics
function loadStats() {
    // Check if chrome.storage is available
    if (!chrome || !chrome.storage || !chrome.storage.local) {
        console.warn('Chrome storage API not available, using default stats');
        setDefaultStats();
        return;
    }
    
    try {
        chrome.storage.local.get(['phishingHunterStats'], (result) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error:', chrome.runtime.lastError);
                setDefaultStats();
                return;
            }
            
            const stats = result.phishingHunterStats || {
                totalScans: 0,
                threatsBlocked: 0,
                safeSites: 0,
                lastScan: null
            };
            
            updateStatsUI(stats);
        });
    } catch (error) {
        console.error('Failed to load stats:', error);
        setDefaultStats();
    }
}

function setDefaultStats() {
    const defaultStats = {
        totalScans: 0,
        threatsBlocked: 0,
        safeSites: 0,
        lastScan: null
    };
    updateStatsUI(defaultStats);
}

function updateStatsUI(stats) {
    const totalScansEl = document.getElementById('totalScans');
    const threatsBlockedEl = document.getElementById('threatsBlocked');
    const safeSitesEl = document.getElementById('safeSites');
    const lastScanEl = document.getElementById('lastScan');
    
    if (totalScansEl) totalScansEl.textContent = stats.totalScans;
    if (threatsBlockedEl) threatsBlockedEl.textContent = stats.threatsBlocked;
    if (safeSitesEl) safeSitesEl.textContent = stats.safeSites;
    
    if (lastScanEl) {
        if (stats.lastScan) {
            const lastScanTime = new Date(stats.lastScan);
            const now = new Date();
            const diffMinutes = Math.floor((now - lastScanTime) / (1000 * 60));
            lastScanEl.textContent = diffMinutes < 60 ? `${diffMinutes}m` : `${Math.floor(diffMinutes / 60)}h`;
        } else {
            lastScanEl.textContent = 'Never';
        }
    }
}

// Update statistics
function updateStats(action) {
    // Check if chrome.storage is available
    if (!chrome || !chrome.storage || !chrome.storage.local) {
        console.warn('Chrome storage API not available, cannot update stats');
        return;
    }
    
    try {
        chrome.storage.local.get(['phishingHunterStats'], (result) => {
            if (chrome.runtime.lastError) {
                console.error('Storage error:', chrome.runtime.lastError);
                return;
            }
            
            const stats = result.phishingHunterStats || {
                totalScans: 0,
                threatsBlocked: 0,
                safeSites: 0,
                lastScan: null
            };
            
            stats.totalScans++;
            stats.lastScan = new Date().toISOString();
            
            if (action === 'threat') {
                stats.threatsBlocked++;
            } else if (action === 'safe') {
                stats.safeSites++;
            }
            
            chrome.storage.local.set({ 'phishingHunterStats': stats }, () => {
                if (chrome.runtime.lastError) {
                    console.error('Storage set error:', chrome.runtime.lastError);
                } else {
                    loadStats(); // Refresh displayed stats
                }
            });
        });
    } catch (error) {
        console.error('Failed to update stats:', error);
    }
}

function updateProtectionStatus(enabled) {
    chrome.storage.local.set({ 'phishingHunterEnabled': enabled }, () => {
        const statusText = enabled ? 'Protection enabled' : 'Protection disabled';
        showTemporaryMessage(statusText, enabled ? 'success' : 'warning');
    });
}

function clearScanHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
        chrome.storage.local.remove(['phishingHunterStats'], () => {
            showTemporaryMessage('History cleared!', 'success');
            loadStats();
        });
    }
}

function exportSettings() {
    chrome.storage.local.get(['phishingHunterSettings'], (result) => {
        const settings = result.phishingHunterSettings || {};
        const dataStr = JSON.stringify(settings, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = 'phishing-hunter-settings.json';
        link.click();
        
        showTemporaryMessage('Settings exported!', 'success');
    });
}

function reportFeedback(type) {
    if (currentAnalysisData && currentUrl) {
        // Send feedback to server
        const feedback = {
            url: currentUrl,
            type: type,
            timestamp: new Date().toISOString(),
            analysisData: currentAnalysisData
        };
        
        chrome.storage.local.get(['phishingHunterFeedback'], (result) => {
            const feedbackList = result.phishingHunterFeedback || [];
            feedbackList.push(feedback);
            
            chrome.storage.local.set({ 'phishingHunterFeedback': feedbackList }, () => {
                showTemporaryMessage(`Feedback submitted! Thank you for helping improve our detection.`, 'success');
            });
        });
    }
}

// Real-time monitoring status functions
async function initializeMonitoringStatus() {
    try {
        // Get current tab monitoring data
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab) {
            chrome.runtime.sendMessage({
                action: 'getMonitoringData',
                tabId: tab.id
            }, (response) => {
                if (response && response.data) {
                    updateMonitoringStatusUI(response.data);
                }
            });
        }
        
        // Update protection status display
        updateProtectionStatusDisplay();
        
        // Listen for monitoring updates
        setupMonitoringListeners();
        
    } catch (error) {
        console.error('Failed to initialize monitoring status:', error);
    }
}

function updateMonitoringStatusUI(monitoringData) {
    // Update protection status badge
    const protectionIcon = document.querySelector('.protection-icon');
    const protectionText = document.querySelector('.protection-text');
    const protectionSubtext = document.querySelector('.protection-subtext');
    
    if (monitoringData.scanStatus === 'scanning') {
        if (protectionIcon) protectionIcon.textContent = '🔍';
        if (protectionText) protectionText.textContent = 'Scanning in Progress';
        if (protectionSubtext) protectionSubtext.textContent = 'Analyzing page content';
    } else if (monitoringData.scanStatus === 'complete') {
        const riskScore = monitoringData.finalRiskScore || monitoringData.riskScore || 0;
        
        if (riskScore >= 60) {
            if (protectionIcon) protectionIcon.textContent = '🚨';
            if (protectionText) protectionText.textContent = 'Threat Detected';
            if (protectionSubtext) protectionSubtext.textContent = `Risk: ${Math.round(riskScore)}%`;
        } else if (riskScore >= 20) {
            if (protectionIcon) protectionIcon.textContent = '⚠️';
            if (protectionText) protectionText.textContent = 'Caution Advised';
            if (protectionSubtext) protectionSubtext.textContent = `Risk: ${Math.round(riskScore)}%`;
        } else {
            if (protectionIcon) protectionIcon.textContent = '✅';
            if (protectionText) protectionText.textContent = 'Site Verified Safe';
            if (protectionSubtext) protectionSubtext.textContent = 'No threats detected';
        }
    }
    
    // Update scan history if we're on the history tab
    updateScanHistoryDisplay(monitoringData);
}

function updateProtectionStatusDisplay() {
    chrome.storage.local.get(['phishingHunterSettings'], (result) => {
        const settings = result.phishingHunterSettings || {};
        const isEnabled = settings.realtimeProtection !== false;
        
        const protectionToggle = document.getElementById('protectionToggle');
        if (protectionToggle) {
            protectionToggle.checked = isEnabled;
        }
        
        const protectionStatus = document.querySelector('.protection-status');
        if (protectionStatus) {
            if (isEnabled) {
                protectionStatus.classList.remove('disabled');
                protectionStatus.classList.add('enabled');
            } else {
                protectionStatus.classList.add('disabled');
                protectionStatus.classList.remove('enabled');
            }
        }
    });
}

function setupMonitoringListeners() {
    // Listen for background monitoring updates
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'monitoringUpdate') {
            updateMonitoringStatusUI(message.data);
        } else if (message.action === 'threatDetected') {
            showThreatAlert(message.data);
        }
        return true;
    });
}

function updateScanHistoryDisplay(monitoringData) {
    const historyContainer = document.getElementById('scanHistory');
    if (!historyContainer) return;
    
    // Get current tab info
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && monitoringData.scanStatus === 'complete') {
            const historyItem = createHistoryItem({
                url: tabs[0].url,
                title: tabs[0].title,
                riskScore: monitoringData.finalRiskScore || monitoringData.riskScore || 0,
                timestamp: Date.now(),
                threats: monitoringData.quickThreats || []
            });
            
            // Remove empty state if present
            const emptyState = historyContainer.querySelector('.empty-state');
            if (emptyState) {
                emptyState.remove();
            }
            
            // Add to top of history
            historyContainer.insertBefore(historyItem, historyContainer.firstChild);
            
            // Keep only last 10 items
            const items = historyContainer.querySelectorAll('.history-item');
            if (items.length > 10) {
                items[items.length - 1].remove();
            }
        }
    });
}

function createHistoryItem(data) {
    const item = document.createElement('div');
    item.className = 'history-item';
    
    const riskScore = data.riskScore || 0;
    let statusIcon = '✅';
    let statusClass = 'safe';
    
    if (riskScore >= 60) {
        statusIcon = '🚨';
        statusClass = 'danger';
    } else if (riskScore >= 20) {
        statusIcon = '⚠️';
        statusClass = 'warning';
    }
    
    const domain = new URL(data.url).hostname;
    const timeAgo = formatTimeAgo(data.timestamp);
    
    item.innerHTML = `
        <div class="history-status ${statusClass}">${statusIcon}</div>
        <div class="history-url">
            <div class="history-domain">${domain}</div>
            <div class="history-title">${data.title || domain}</div>
        </div>
        <div class="history-time">${timeAgo}</div>
    `;
    
    return item;
}

function formatTimeAgo(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    
    if (diff < 60000) return 'Now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
    return `${Math.floor(diff / 86400000)}d`;
}

function showThreatAlert(threatData) {
    // Create in-popup threat alert
    const alertDiv = document.createElement('div');
    alertDiv.className = 'threat-alert';
    alertDiv.innerHTML = `
        <div class="alert-content">
            <div class="alert-icon">🚨</div>
            <div class="alert-text">
                <strong>Security Alert</strong>
                <p>${threatData.message || 'Potential threat detected on this page'}</p>
            </div>
            <button class="alert-close" onclick="this.parentElement.parentElement.remove()">×</button>
        </div>
    `;
    
    document.body.appendChild(alertDiv);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 10000);
}

function updateBackgroundNotificationSettings() {
    // Get current notification settings and send to background script
    chrome.storage.local.get(['phishingHunterSettings'], (result) => {
        const settings = result.phishingHunterSettings || {};
        
        const notificationSettings = {
            enabled: settings.autoThreatAlerts !== false,
            soundEnabled: settings.criticalSounds !== false,
            lowRiskEnabled: settings.lowRiskNotifications === true,
            badgeUpdatesEnabled: settings.badgeUpdates !== false
        };
        
        chrome.runtime.sendMessage({
            action: 'updateNotificationSettings',
            settings: notificationSettings
        }, (response) => {
            if (response && response.success) {
                console.log('Notification settings updated in background');
            }
        });
    });
}

// Performance optimization and memory management utilities
class PerformanceManager {
    constructor() {
        this.observers = [];
        this.intervals = [];
        this.timeouts = [];
        this.eventListeners = [];
    }
    
    // Cleanup all resources to prevent memory leaks
    cleanup() {
        // Clear all intervals
        if (window.phishingHunterIntervals) {
            window.phishingHunterIntervals.forEach(id => clearInterval(id));
            window.phishingHunterIntervals = [];
        }
        
        // Cancel animation frames
        if (animationFrameId) {
            cancelAnimationFrame(animationFrameId);
            animationFrameId = null;
        }
        
        // Clear resize timeout
        if (resizeTimeoutId) {
            clearTimeout(resizeTimeoutId);
            resizeTimeoutId = null;
        }
        
        // Clear component cache periodically
        if (componentCache.size > 10) {
            componentCache.clear();
            loadedComponents.clear();
        }
        
        console.log('Performance cleanup completed');
    }
    
    // Debounced resize handler
    static handleResize = debounce(() => {
        // Only recreate neural network if visible
        const neuralNetwork = document.getElementById('neuralNetwork');
        if (neuralNetwork && neuralNetwork.offsetParent !== null) {
            createNeuralNetwork();
        }
    }, 300);
    
    // Memory-efficient image loading
    static optimizeImages() {
        const images = document.querySelectorAll('img');
        images.forEach(img => {
            if (!img.loading) {
                img.loading = 'lazy';
            }
        });
    }
}

// Initialize performance manager
const performanceManager = new PerformanceManager();

// Add efficient resize listener
window.addEventListener('resize', PerformanceManager.handleResize, { passive: true });

// Page visibility API for performance optimization
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        // Pause animations and reduce activity when hidden
        if (animationFrameId) {
            cancelAnimationFrame(animationFrameId);
            animationFrameId = null;
        }
    } else {
        // Resume activity when visible
        requestIdleCallback(() => {
            if (!loadedComponents.has('neuralNetwork')) {
                createNeuralNetwork();
            }
        });
    }
}, { passive: true });

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    performanceManager.cleanup();
}, { passive: true });

// Memory usage monitoring (development only)
if (DEBUG) {
    setInterval(() => {
        if (performance.memory) {
            const memory = performance.memory;
            const mbUsed = Math.round(memory.usedJSHeapSize / 1048576);
            const mbTotal = Math.round(memory.totalJSHeapSize / 1048576);
            
            if (mbUsed > 50) { // Alert if using more than 50MB
                console.warn(`High memory usage: ${mbUsed}MB/${mbTotal}MB`);
                performanceManager.cleanup();
            }
        }
    }, 30000); // Check every 30 seconds
}

// Export for potential external use
window.PhishingHunterPerformance = {
    debounce,
    throttle,
    lazyLoad,
    smoothAnimation,
    performanceManager
};

/*
 * PERFORMANCE OPTIMIZATION SUMMARY
 * ================================
 * 
 * This file has been optimized with the following performance improvements:
 * 
 * 1. LAZY LOADING OF COMPONENTS
 *    - Neural network background creation is lazy-loaded using lazyLoad utility
 *    - Enhanced spinner creation is lazy-loaded and cached
 *    - displayLayerResults function uses lazy loading pattern
 *    - Components are loaded only when needed to reduce initial load time
 * 
 * 2. DEBOUNCED ANIMATIONS
 *    - createNeuralNetwork function is debounced (300ms delay)
 *    - Window resize handler is debounced to prevent excessive redraws
 *    - Connection animations are throttled to reduce CPU usage
 *    - displayMonitoringStatus is debounced (500ms delay)
 * 
 * 3. EFFICIENT DOM MANIPULATION
 *    - DocumentFragment used for batch DOM operations
 *    - Element caching in showResult and showError functions
 *    - Single DOM updates instead of multiple separate updates
 *    - Template caching in displayLayerResults for better performance
 *    - Reduced number of DOM queries through element caching
 * 
 * 4. CODE SPLITTING
 *    - Initialization split into 3 phases: critical, non-critical, and analysis
 *    - Critical UI loads immediately for better user experience
 *    - Non-critical components load when browser is idle (requestIdleCallback)
 *    - Analysis functionality is deferred to prevent blocking
 * 
 * 5. REDUCED MEMORY FOOTPRINT
 *    - Component cache with automatic cleanup when size exceeds 10 items
 *    - Interval tracking and cleanup in PerformanceManager
 *    - Memory usage monitoring in development mode
 *    - Automatic cleanup on page unload
 *    - Reduced node count in neural network for better performance
 * 
 * 6. REQUESTANIMATIONFRAME FOR SMOOTH ANIMATIONS
 *    - smoothAnimation utility wraps requestAnimationFrame
 *    - All UI updates use requestAnimationFrame for 60fps performance
 *    - Animation frame cleanup to prevent memory leaks
 *    - Smooth transitions in showResult, showError, and showLoading
 * 
 * ADDITIONAL OPTIMIZATIONS:
 * - Passive event listeners for better scroll performance
 * - Page visibility API to pause animations when tab is hidden
 * - Transform-based animations instead of layout-triggering properties
 * - CSS containment properties (will-change) for better rendering
 * - Throttled connection animations with reduced frequency
 * - Efficient risk level calculation with lookup objects
 * - Template strings cached for repeated use
 * 
 * MEMORY MANAGEMENT:
 * - PerformanceManager class for centralized cleanup
 * - Automatic interval and timeout cleanup
 * - Component cache size limiting
 * - Memory usage alerts in development mode
 * - Resource cleanup on page unload
 * 
 * BROWSER COMPATIBILITY:
 * - requestIdleCallback with fallback
 * - Performance API feature detection
 * - Graceful degradation for older browsers
 * - Progressive enhancement approach
 */

// Email Analysis Functions
function initializeEmailComponents() {
    // Email analysis button
    const analyzeEmailBtn = document.getElementById('analyzeEmail');
    if (analyzeEmailBtn) {
        analyzeEmailBtn.addEventListener('click', () => {
            analyzeEmailContent();
        });
    }
    
    // Quick email check button
    const quickEmailBtn = document.getElementById('quickEmailCheck');
    if (quickEmailBtn) {
        quickEmailBtn.addEventListener('click', () => {
            quickEmailCheck();
        });
    }
    
    // Email report buttons
    const reportEmailSafeBtn = document.getElementById('reportEmailSafe');
    if (reportEmailSafeBtn) {
        reportEmailSafeBtn.addEventListener('click', () => {
            reportEmailFeedback('safe');
        });
    }
    
    const reportEmailPhishingBtn = document.getElementById('reportEmailPhishing');
    if (reportEmailPhishingBtn) {
        reportEmailPhishingBtn.addEventListener('click', () => {
            reportEmailFeedback('phishing');
        });
    }
    
    // Email retry button
    const retryEmailBtn = document.getElementById('retryEmail');
    if (retryEmailBtn) {
        retryEmailBtn.addEventListener('click', () => {
            hideEmailError();
        });
    }
    
    // Get current email button
    const getCurrentEmailBtn = document.getElementById('getCurrentEmail');
    if (getCurrentEmailBtn) {
        getCurrentEmailBtn.addEventListener('click', () => {
            getCurrentEmailComposition();
        });
    }
    
    // Add debug button event listener
    const debugEmailBtn = document.getElementById('debugEmailDetection');
    if (debugEmailBtn) {
        debugEmailBtn.addEventListener('click', () => {
            triggerEmailDebug();
        });
    }
    
    // Add force email detection button event listener
    const forceEmailBtn = document.getElementById('forceEmailDetection');
    if (forceEmailBtn) {
        forceEmailBtn.addEventListener('click', () => {
            triggerForceEmailDetection();
        });
    }
    
    // Show helpful guidance for users
    showEmailGuidance();
}

// Analyze email content using the API
async function analyzeEmailContent() {
    try {
        // Get email data from form
        const senderEmail = document.getElementById('senderEmail').value.trim();
        const emailSubject = document.getElementById('emailSubject').value.trim();
        const emailContent = document.getElementById('emailContent').value.trim();
        
        // Validate input
        if (!emailContent && !emailSubject) {
            showEmailError('Please provide either email content or subject');
            return;
        }
        
        // Show loading state
        showEmailLoading();
        hideEmailResult();
        hideEmailError();
        
        // Prepare request data
        const requestData = {
            content: emailContent,
            subject: emailSubject,
            sender: senderEmail
        };
        
        // Call API
        const response = await fetch(`${apiServerUrl}/analyze_email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }
        
        const result = await response.json();
        
        // Hide loading and show results
        hideEmailLoading();
        displayEmailAnalysisResult(result);
        
        // Store for feedback
        currentEmailAnalysis = result;
        
    } catch (error) {
        console.error('Email analysis failed:', error);
        hideEmailLoading();
        showEmailError(`Analysis failed: ${error.message}`);
    }
}

// Get current email composition from active tab
async function getCurrentEmailComposition() {
    try {
        console.log('📧 Getting current email composition...');
        
        // Show loading state
        showEmailLoading();
        hideEmailResult();
        hideEmailError();
        
        // First check the email detection status
        console.log('📧 Checking email detection status...');
        const statusResponse = await chrome.runtime.sendMessage({
            action: 'checkEmailDetectionStatus'
        });
        
        console.log('📧 Email detection status:', statusResponse);
        
        if (!statusResponse.success) {
            throw new Error(`Email detection not available: ${statusResponse.error}`);
        }
        
        const emailState = statusResponse.data;
        console.log('📧 Current email state:', emailState);
        
        // Check if email detection is available (provider detected)
        if (!emailState.detectedProvider) {
            throw new Error('Email detection not initialized. Please ensure you are on an email provider page (Gmail, Outlook, Yahoo).');
        }
        
        // Check if we have email data
        if (!emailState.currentEmailData) {
            if (!emailState.isComposing && !emailState.isReading) {
                throw new Error('No email detected. Please either compose a new email or open/read an email from your inbox.');
            } else {
                throw new Error('No email content detected. Please ensure you have email content visible.');
            }
        }
        
        // Use the email data we already have from the status check
        console.log('📧 Current email data:', emailState.currentEmailData);
        
        // Populate form fields with current email data
        const senderEmailField = document.getElementById('senderEmail');
        const emailSubjectField = document.getElementById('emailSubject');
        const emailContentField = document.getElementById('emailContent');
        
        if (senderEmailField) senderEmailField.value = emailState.currentEmailData.sender || '';
        if (emailSubjectField) emailSubjectField.value = emailState.currentEmailData.subject || '';
        if (emailContentField) emailContentField.value = emailState.currentEmailData.content || '';
        
        // Hide loading and show success message
        hideEmailLoading();
        showEmailSuccess('✅ Current email content loaded! Click "ANALYZE EMAIL" to scan for threats.');
        
    } catch (error) {
        console.error('Failed to get current email:', error);
        hideEmailLoading();
        
        // Show more helpful error messages
        let userMessage = error.message;
        
        if (error.message.includes('Content script not loaded')) {
            userMessage = 'Email detection not available on this page. Please ensure you are on an email provider (Gmail, Outlook, Yahoo) and refresh the page.';
        } else if (error.message.includes('No email composition detected')) {
            userMessage = 'No email composition detected. Please compose an email first or ensure you are on an email provider page.';
        } else if (error.message.includes('Could not establish connection')) {
            userMessage = 'Extension not properly loaded. Please refresh the page and try again.';
        } else if (error.message.includes('Email detection not initialized')) {
            userMessage = 'Email detection not initialized. Please ensure you are on an email provider page (Gmail, Outlook, Yahoo) and refresh the page.';
        }
        
        showEmailError(userMessage);
    }
}

// Quick email check using pattern matching
async function quickEmailCheck() {
    try {
        // Get email data from form
        const senderEmail = document.getElementById('senderEmail').value.trim();
        const emailSubject = document.getElementById('emailSubject').value.trim();
        const emailContent = document.getElementById('emailContent').value.trim();
        
        // Validate input
        if (!emailContent && !emailSubject) {
            showEmailError('Please provide either email content or subject');
            return;
        }
        
        // Show loading state
        showEmailLoading();
        hideEmailResult();
        hideEmailError();
        
        // Prepare request data
        const requestData = {
            content: emailContent,
            subject: emailSubject,
            sender: senderEmail
        };
        
        // Call quick check API
        const response = await fetch(`${apiServerUrl}/check_email_quick`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.status} ${response.statusText}`);
        }
        
        const result = await response.json();
        
        // Hide loading and show results
        hideEmailLoading();
        displayEmailAnalysisResult(result);
        
        // Store for feedback
        currentEmailAnalysis = result;
        
    } catch (error) {
        console.error('Quick email check failed:', error);
        hideEmailLoading();
        showEmailError(`Quick check failed: ${error.message}`);
    }
}

// Display email analysis results
function displayEmailAnalysisResult(result) {
    try {
        const emailResult = document.getElementById('emailResult');
        const emailStatusIcon = document.getElementById('emailStatusIcon');
        const emailStatusText = document.getElementById('emailStatusText');
        const emailReason = document.getElementById('emailReason');
        const emailRiskBar = document.getElementById('emailRiskBar');
        const emailRiskFill = document.getElementById('emailRiskFill');
        const emailRiskText = document.getElementById('emailRiskText');
        const emailDetails = document.getElementById('emailDetails');
        
        if (!emailResult) return;
        
        // Update status icon and text
        const isPhishing = result.is_phishing || false;
        const riskScore = result.risk_score || 0;
        
        if (isPhishing || riskScore >= 70) {
            emailStatusIcon.className = 'status-icon status-critical';
            emailStatusIcon.textContent = '🚨';
            emailStatusText.textContent = 'PHISHING DETECTED';
            emailStatusText.className = 'status-text status-critical';
        } else if (riskScore >= 50) {
            emailStatusIcon.className = 'status-icon status-warning';
            emailStatusIcon.textContent = '⚠️';
            emailStatusText.textContent = 'SUSPICIOUS EMAIL';
            emailStatusText.className = 'status-text status-warning';
        } else {
            emailStatusIcon.className = 'status-icon status-safe';
            emailStatusIcon.textContent = '✅';
            emailStatusText.textContent = 'SAFE EMAIL';
            emailStatusText.className = 'status-text status-safe';
        }
        
        // Update reason
        if (result.reason) {
            emailReason.textContent = result.reason;
        } else if (result.threats && result.threats.length > 0) {
            emailReason.textContent = `Threats detected: ${result.threats.join(', ')}`;
        } else {
            emailReason.textContent = isPhishing ? 'Multiple suspicious indicators detected' : 'No threats detected';
        }
        
        // Update risk bar
        emailRiskFill.style.width = `${riskScore}%`;
        emailRiskText.textContent = `${riskScore}% PHISHING RISK`;
        
        // Set risk bar color
        if (riskScore >= 70) {
            emailRiskFill.style.background = 'var(--gradient-danger)';
        } else if (riskScore >= 50) {
            emailRiskFill.style.background = 'var(--gradient-warning)';
        } else {
            emailRiskFill.style.background = 'var(--gradient-success)';
        }
        
        // Update details
        displayEmailDetails(result);
        
        // Show analysis breakdown if available
        if (result.analysis_method === 'ml_enhanced') {
            displayEmailAnalysisBreakdown(result);
        }
        
        // Show recommendations
        if (result.recommendations && result.recommendations.length > 0) {
            displayEmailRecommendations(result.recommendations);
        }
        
        // Show results
        emailResult.style.display = 'block';
        
        // Animate risk bar
        setTimeout(() => {
            emailRiskFill.style.transform = 'scaleX(1)';
        }, 100);
        
    } catch (error) {
        console.error('Failed to display email results:', error);
        showEmailError('Failed to display results');
    }
}

// Display email analysis details
function displayEmailDetails(result) {
    const emailDetails = document.getElementById('emailDetails');
    if (!emailDetails) return;
    
    let detailsHTML = '';
    
    // Basic info
    detailsHTML += `
        <div class="email-detail-item">
            <span class="email-detail-label">Analysis Method:</span>
            <span class="email-detail-value">${result.analysis_method || 'pattern_only'}</span>
        </div>
        <div class="email-detail-item">
            <span class="email-detail-label">Confidence:</span>
            <span class="email-detail-value">${Math.round((result.confidence || 0) * 100)}%</span>
        </div>
    `;
    
    // Sender analysis
    if (result.sender_analysis) {
        const sender = result.sender_analysis;
        detailsHTML += `
            <div class="email-detail-item">
                <span class="email-detail-label">Sender Risk:</span>
                <span class="email-detail-value ${sender.risk}">${sender.risk.toUpperCase()} (${sender.score})</span>
            </div>
        `;
    }
    
    // Content analysis
    if (result.content_analysis) {
        const content = result.content_analysis;
        detailsHTML += `
            <div class="email-detail-item">
                <span class="email-detail-label">Content Risk:</span>
                <span class="email-detail-value ${content.risk}">${content.risk.toUpperCase()} (${content.score})</span>
            </div>
        `;
    }
    
    // ML analysis
    if (result.ml_analysis && !result.ml_analysis.error) {
        const ml = result.ml_analysis;
        detailsHTML += `
            <div class="email-detail-item">
                <span class="email-detail-label">AI Prediction:</span>
                <span class="email-detail-value">${ml.predicted_label.toUpperCase()}</span>
            </div>
        `;
    }
    
    // Pattern analysis
    if (result.pattern_analysis) {
        const patterns = result.pattern_analysis;
        detailsHTML += `
            <div class="email-detail-item">
                <span class="email-detail-label">Patterns Found:</span>
                <span class="email-detail-value">${patterns.total_patterns}</span>
            </div>
        `;
    }
    
    emailDetails.innerHTML = detailsHTML;
}

// Display email analysis breakdown
function displayEmailAnalysisBreakdown(result) {
    const breakdown = document.getElementById('emailAnalysisBreakdown');
    if (!breakdown) return;
    
    let breakdownHTML = '';
    
    // Sender analysis
    if (result.sender_analysis) {
        const sender = result.sender_analysis;
        breakdownHTML += `
            <div class="analysis-section">
                <h4>📧 Sender Analysis</h4>
                <div id="senderAnalysis">
                    <div class="email-detail-item">
                        <span class="email-detail-label">Risk Level:</span>
                        <span class="email-detail-value ${sender.risk}">${sender.risk.toUpperCase()}</span>
                    </div>
                    <div class="email-detail-item">
                        <span class="email-detail-label">Risk Score:</span>
                        <span class="email-detail-value">${sender.score}</span>
                    </div>
                    ${sender.flags.map(flag => `
                        <div class="email-detail-item">
                            <span class="email-detail-label">Flag:</span>
                            <span class="email-detail-value warning">${flag}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Content analysis
    if (result.content_analysis) {
        const content = result.content_analysis;
        breakdownHTML += `
            <div class="analysis-section">
                <h4>📝 Content Analysis</h4>
                <div id="contentAnalysis">
                    <div class="email-detail-item">
                        <span class="email-detail-label">Risk Level:</span>
                        <span class="email-detail-value ${content.risk}">${content.risk.toUpperCase()}</span>
                    </div>
                    <div class="email-detail-item">
                        <span class="email-detail-label">Risk Score:</span>
                        <span class="email-detail-value">${content.score}</span>
                    </div>
                    ${content.flags.map(flag => `
                        <div class="email-detail-item">
                            <span class="email-detail-label">Flag:</span>
                            <span class="email-detail-value warning">${flag}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // AI analysis
    if (result.ml_analysis && !result.ml_analysis.error) {
        const ml = result.ml_analysis;
        breakdownHTML += `
            <div class="analysis-section">
                <h4>🤖 AI Analysis</h4>
                <div id="aiAnalysis">
                    <div class="email-detail-item">
                        <span class="email-detail-label">Prediction:</span>
                        <span class="email-detail-value">${ml.predicted_label.toUpperCase()}</span>
                    </div>
                    <div class="email-detail-item">
                        <span class="email-detail-label">Confidence:</span>
                        <span class="email-detail-value">${Math.round(ml.confidence * 100)}%</span>
                    </div>
                    ${Object.entries(ml.probabilities || {}).map(([label, prob]) => `
                        <div class="email-detail-item">
                            <span class="email-detail-label">${label}:</span>
                            <span class="email-detail-value">${Math.round(prob * 100)}%</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    // Pattern analysis
    if (result.pattern_analysis && result.pattern_analysis.patterns) {
        const patterns = result.pattern_analysis.patterns;
        breakdownHTML += `
            <div class="analysis-section">
                <h4>🔍 Pattern Detection</h4>
                <div id="patternAnalysis">
                    ${patterns.map(pattern => `
                        <div class="pattern-item">
                            <div class="pattern-category">${pattern.category.replace('_', ' ').toUpperCase()}</div>
                            <div class="pattern-matches">${pattern.matches} matches found</div>
                            <div class="pattern-examples">Examples: ${pattern.examples.join(', ')}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }
    
    breakdown.innerHTML = breakdownHTML;
    breakdown.style.display = 'block';
}

// Display email recommendations
function displayEmailRecommendations(recommendations) {
    const recommendationsSection = document.getElementById('emailRecommendations');
    const recommendationsList = document.getElementById('recommendationsList');
    
    if (!recommendationsSection || !recommendationsList) return;
    
    const recommendationsHTML = recommendations.map(rec => `
        <div class="recommendation-item">${rec}</div>
    `).join('');
    
    recommendationsList.innerHTML = recommendationsHTML;
    recommendationsSection.style.display = 'block';
}

// Email feedback reporting
function reportEmailFeedback(type) {
    if (!currentEmailAnalysis) {
        console.warn('No email analysis data available for feedback');
        return;
    }
    
    try {
        const feedback = {
            type: 'email_analysis',
            feedback_type: type,
            analysis_data: currentEmailAnalysis,
            timestamp: Date.now()
        };
        
        // Send feedback to background script
        chrome.runtime.sendMessage({
            action: 'updateUserFeedback',
            feedback: feedback
        }, (response) => {
            if (response && response.success) {
                showTemporaryMessage('Feedback submitted successfully!', 'success');
            } else {
                showTemporaryMessage('Failed to submit feedback', 'warning');
            }
        });
        
        // Show confirmation
        showTemporaryMessage(`Email marked as ${type}`, 'success');
        
    } catch (error) {
        console.error('Failed to report email feedback:', error);
        showTemporaryMessage('Failed to submit feedback', 'warning');
    }
}

// Email UI state management
function showEmailLoading() {
    const loading = document.getElementById('emailLoading');
    if (loading) loading.style.display = 'block';
}

function hideEmailLoading() {
    const loading = document.getElementById('emailLoading');
    if (loading) loading.style.display = 'none';
}

function showEmailResult() {
    const result = document.getElementById('emailResult');
    if (result) result.style.display = 'block';
}

function hideEmailResult() {
    const result = document.getElementById('emailResult');
    if (result) result.style.display = 'none';
}

function showEmailError(message) {
    const error = document.getElementById('emailError');
    const errorDetails = document.querySelector('#emailError .error-details');
    
    if (error && errorDetails) {
        errorDetails.textContent = message;
        error.style.display = 'block';
    }
}

function showEmailSuccess(message) {
    const emailResult = document.getElementById('emailResult');
    const emailStatusIcon = document.getElementById('emailStatusIcon');
    const emailStatusText = document.getElementById('emailStatusText');
    const emailReason = document.getElementById('emailReason');
    
    if (emailResult && emailStatusIcon && emailStatusText && emailReason) {
        emailStatusIcon.className = 'status-icon status-safe';
        emailStatusIcon.textContent = '✅';
        emailStatusText.textContent = 'SUCCESS';
        emailStatusText.className = 'status-text status-safe';
        emailReason.textContent = message;
        
        emailResult.style.display = 'block';
    }
}

function hideEmailError() {
    const error = document.getElementById('emailError');
    if (error) error.style.display = 'none';
}

// Global variable for email analysis
let currentEmailAnalysis = null;

// Show helpful guidance for email analysis
function showEmailGuidance() {
    const guidance = document.getElementById('emailGuidance');
    if (!guidance) return;
    
    guidance.innerHTML = `
        <div class="email-guidance">
            <h4>📧 How to Use Email Analysis</h4>
            <div class="guidance-steps">
                <div class="step">
                    <span class="step-number">1</span>
                    <span class="step-text">Navigate to an email provider (Gmail, Outlook, Yahoo)</span>
                </div>
                <div class="step">
                    <span class="step-number">2</span>
                    <span class="step-text">Click "Compose" or "New Email"</span>
                </div>
                <div class="step">
                    <span class="step-number">3</span>
                    <span class="step-text">Click "GET CURRENT EMAIL" to load your draft</span>
                </div>
                <div class="step">
                    <span class="step-number">4</span>
                    <span class="step-text">Click "ANALYZE EMAIL" to scan for threats</span>
                </div>
            </div>
            <div class="guidance-note">
                <strong>Note:</strong> Email analysis works on Gmail, Outlook, Yahoo Mail, and other major email providers.
            </div>
        </div>
    `;
    
    guidance.style.display = 'block';
}

// Copy functionality for email fields and results
function initializeCopyButtons() {
    // Copy buttons for email input fields
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const fieldId = button.getAttribute('data-field');
            const field = document.getElementById(fieldId);
            
            if (!field || !field.value.trim()) {
                showTemporaryMessage('No content to copy', 'warning');
                return;
            }
            
            try {
                // Copy to clipboard
                await navigator.clipboard.writeText(field.value.trim());
                
                // Visual feedback
                button.classList.add('copied');
                button.querySelector('.copy-icon').textContent = '✅';
                
                // Show success message
                showTemporaryMessage(`${fieldId === 'senderEmail' ? 'Sender email' : fieldId === 'emailSubject' ? 'Subject' : 'Content'} copied to clipboard!`, 'success');
                
                // Reset button after 2 seconds
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.querySelector('.copy-icon').textContent = '📋';
                }, 2000);
                
            } catch (error) {
                console.error('Failed to copy to clipboard:', error);
                showTemporaryMessage('Failed to copy to clipboard', 'error');
            }
        });
    });
    
    // Copy button for analysis results
    const copyResultBtn = document.querySelector('.copy-result-btn');
    if (copyResultBtn) {
        copyResultBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            
            if (!currentEmailAnalysis) {
                showTemporaryMessage('No analysis results to copy', 'warning');
                return;
            }
            
            try {
                // Format the analysis results for copying
                const resultText = formatAnalysisResultsForCopy(currentEmailAnalysis);
                
                // Copy to clipboard
                await navigator.clipboard.writeText(resultText);
                
                // Visual feedback
                copyResultBtn.classList.add('copied');
                copyResultBtn.querySelector('.copy-icon').textContent = '✅';
                
                // Show success message
                showTemporaryMessage('Analysis results copied to clipboard!', 'success');
                
                // Reset button after 2 seconds
                setTimeout(() => {
                    copyResultBtn.classList.remove('copied');
                    copyResultBtn.querySelector('.copy-icon').textContent = '📋';
                }, 2000);
                
            } catch (error) {
                console.error('Failed to copy analysis results:', error);
                showTemporaryMessage('Failed to copy results', 'error');
            }
        });
    }
}

// Format analysis results for copying
function formatAnalysisResultsForCopy(analysis) {
    let result = '📧 EMAIL ANALYSIS RESULTS\n';
    result += '='.repeat(30) + '\n\n';
    
    // Basic info
    result += `Status: ${analysis.is_phishing ? '🚨 PHISHING DETECTED' : '✅ SAFE EMAIL'}\n`;
    result += `Risk Score: ${analysis.risk_score || 0}%\n`;
    result += `Confidence: ${Math.round((analysis.confidence || 0) * 100)}%\n`;
    result += `Analysis Method: ${analysis.analysis_method || 'pattern_only'}\n\n`;
    
    // Reason/Threats
    if (analysis.reason) {
        result += `Reason: ${analysis.reason}\n\n`;
    }
    
    if (analysis.threats && analysis.threats.length > 0) {
        result += `Threats Detected:\n`;
        analysis.threats.forEach(threat => {
            result += `• ${threat}\n`;
        });
        result += '\n';
    }
    
    // Recommendations
    if (analysis.recommendations && analysis.recommendations.length > 0) {
        result += `Recommendations:\n`;
        analysis.recommendations.forEach(rec => {
            result += `• ${rec}\n`;
        });
        result += '\n';
    }
    
    // Timestamp
    result += `Analysis Date: ${new Date().toLocaleString()}\n`;
    
    return result;
}

// Display email analysis history
function displayEmailHistory() {
    chrome.runtime.sendMessage({
        action: 'getEmailHistory'
    }, (response) => {
        if (response && response.success && response.history) {
            updateEmailHistoryDisplay(response.history);
        } else {
            console.log('No email history available');
        }
    });
}

// Update email history display
function updateEmailHistoryDisplay(history) {
    const emailHistoryList = document.getElementById('emailHistoryList');
    if (!emailHistoryList) return;
    
    if (!history || history.length === 0) {
        emailHistoryList.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📧</div>
                <div>No email analysis history yet</div>
            </div>
        `;
        return;
    }
    
    // Sort by timestamp (newest first)
    const sortedHistory = history.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    
    const historyHTML = sortedHistory.map((item, index) => {
        const timestamp = new Date(item.timestamp || Date.now());
        const timeAgo = getTimeAgo(timestamp);
        const status = item.analysis?.is_phishing ? '🚨 PHISHING' : '✅ SAFE';
        const riskScore = item.analysis?.risk_score || 0;
        const sender = item.sender || 'Unknown';
        const subject = item.subject || 'No subject';
        
        return `
            <div class="email-history-item" data-index="${index}">
                <div class="email-history-header">
                    <div class="email-history-status">
                        <span>${status}</span>
                        <span style="color: ${riskScore >= 70 ? 'var(--danger)' : riskScore >= 50 ? 'var(--warning)' : 'var(--success)'}">
                            (${riskScore}% risk)
                        </span>
                    </div>
                    <button type="button" class="email-history-copy" title="Copy email details" data-index="${index}">
                        <span class="copy-icon">📋</span>
                    </button>
                </div>
                <div class="email-history-details">
                    <div><strong>From:</strong> ${sender}</div>
                    <div><strong>Subject:</strong> ${subject}</div>
                    ${item.analysis?.threats && item.analysis.threats.length > 0 ? 
                        `<div><strong>Threats:</strong> ${item.analysis.threats.join(', ')}</div>` : ''
                    }
                </div>
                <div class="email-history-timestamp">${timeAgo}</div>
            </div>
        `;
    }).join('');
    
    emailHistoryList.innerHTML = historyHTML;
    
    // Add event listeners to copy buttons
    addEmailHistoryCopyListeners(sortedHistory);
}

// Add copy event listeners to email history items
function addEmailHistoryCopyListeners(history) {
    const copyButtons = document.querySelectorAll('.email-history-copy');
    
    copyButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const index = parseInt(button.getAttribute('data-index'));
            const historyItem = history[index];
            
            if (!historyItem) {
                showTemporaryMessage('No history item to copy', 'warning');
                return;
            }
            
            try {
                // Format the history item for copying
                const historyText = formatEmailHistoryForCopy(historyItem);
                
                // Copy to clipboard
                await navigator.clipboard.writeText(historyText);
                
                // Visual feedback
                button.classList.add('copied');
                button.querySelector('.copy-icon').textContent = '✅';
                
                // Show success message
                showTemporaryMessage('Email history copied to clipboard!', 'success');
                
                // Reset button after 2 seconds
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.querySelector('.copy-icon').textContent = '📋';
                }, 2000);
                
            } catch (error) {
                console.error('Failed to copy email history:', error);
                showTemporaryMessage('Failed to copy history', 'error');
            }
        });
    });
}

// Format email history item for copying
function formatEmailHistoryForCopy(historyItem) {
    let result = '📧 EMAIL ANALYSIS HISTORY\n';
    result += '='.repeat(30) + '\n\n';
    
    // Basic email info
    result += `From: ${historyItem.sender || 'Unknown'}\n`;
    result += `Subject: ${historyItem.subject || 'No subject'}\n`;
    result += `Content: ${historyItem.content ? historyItem.content.substring(0, 100) + '...' : 'No content'}\n\n`;
    
    // Analysis results
    if (historyItem.analysis) {
        result += `Analysis Results:\n`;
        result += `Status: ${historyItem.analysis.is_phishing ? '🚨 PHISHING DETECTED' : '✅ SAFE EMAIL'}\n`;
        result += `Risk Score: ${historyItem.analysis.risk_score || 0}%\n`;
        result += `Confidence: ${Math.round((historyItem.analysis.confidence || 0) * 100)}%\n`;
        result += `Analysis Method: ${historyItem.analysis.analysis_method || 'pattern_only'}\n\n`;
        
        if (historyItem.analysis.reason) {
            result += `Reason: ${historyItem.analysis.reason}\n\n`;
        }
        
        if (historyItem.analysis.threats && historyItem.analysis.threats.length > 0) {
            result += `Threats Detected:\n`;
            historyItem.analysis.threats.forEach(threat => {
                result += `• ${threat}\n`;
            });
            result += '\n';
        }
        
        if (historyItem.analysis.recommendations && historyItem.analysis.recommendations.length > 0) {
            result += `Recommendations:\n`;
            historyItem.analysis.recommendations.forEach(rec => {
                result += `• ${rec}\n`;
            });
            result += '\n';
        }
    }
    
    // Timestamp
    const timestamp = new Date(historyItem.timestamp || Date.now());
    result += `Analysis Date: ${timestamp.toLocaleString()}\n`;
    
    return result;
}

// Get time ago string
function getTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)}d ago`;
    
    return date.toLocaleDateString();
}

// Trigger email detection debug
async function triggerEmailDebug() {
    try {
        console.log('🔍 Triggering email detection debug...');
        
        const response = await chrome.runtime.sendMessage({
            action: 'debugEmailDetection'
        });
        
        if (response && response.success) {
            showTemporaryMessage('Debug report generated in console! Open Developer Tools (F12) to view.', 'success');
            console.log('✅ Debug report triggered successfully');
        } else {
            console.log('❌ Debug report failed. Full response:', response);
            const errorMessage = response?.error || response?.message || 'Unknown error';
            showTemporaryMessage(`Debug failed: ${errorMessage}`, 'warning');
            console.error('❌ Debug report failed:', response);
        }
        
    } catch (error) {
        console.error('Failed to trigger debug report:', error);
        showTemporaryMessage('Failed to trigger debug report', 'error');
    }
}

// Trigger force email detection
async function triggerForceEmailDetection() {
    console.log('🚀 Triggering force email detection...');
    
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'forceEmailDetection'
        });
        
        if (response.success && response.data) {
            console.log('✅ Force detection successful:', response.data);
            
            // Populate form fields with detected data
            if (response.data.subject) {
                document.getElementById('emailSubject').value = response.data.subject;
            }
            if (response.data.sender) {
                document.getElementById('senderEmail').value = response.data.sender;
            }
            if (response.data.content) {
                document.getElementById('emailContent').value = response.data.content;
            }
            
            // Show success message
            showTemporaryMessage('✅ Email content detected and populated!', 'success');
        } else {
            console.log('❌ Force detection failed:', response.error);
            showTemporaryMessage('❌ Force detection failed: ' + (response.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('❌ Force detection error:', error);
        showTemporaryMessage('❌ Force detection error: ' + error.message, 'error');
    }
}

// Trigger force refresh email detection
async function triggerForceRefreshEmailDetection() {
    console.log('🔄 Triggering force refresh email detection...');
    
    try {
        const response = await chrome.runtime.sendMessage({
            action: 'forceRefreshEmailDetection'
        });
        
        if (response.success && response.data) {
            console.log('✅ Force detection successful:', response.data);
            
            // Populate form fields with detected data
            if (response.data.subject) {
                document.getElementById('emailSubject').value = response.data.subject;
            }
            if (response.data.sender) {
                document.getElementById('senderEmail').value = response.data.sender;
            }
            if (response.data.content) {
                document.getElementById('emailContent').value = response.data.content;
            }
            
            // Show success message
            showTemporaryMessage('✅ Email content refreshed and populated!', 'success');
        } else {
            console.log('❌ Force refresh failed:', response.error);
            showTemporaryMessage('❌ Force refresh failed: ' + (response.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('❌ Force refresh error:', error);
        showTemporaryMessage('❌ Force refresh error: ' + error.message, 'error');
    }
}

// Initialize copy buttons when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeCopyButtons();
});

// Force detect button
document.getElementById('forceEmailDetection').addEventListener('click', triggerForceEmailDetection);

// Force refresh button
document.getElementById('forceRefreshEmailDetection').addEventListener('click', triggerForceRefreshEmailDetection);

// ---------------------------------------------------------------------------
// Explainable AI (v2): show which parts of the URL drove the ML verdict.
// Uses the /explain_url endpoint. Failures are silent so the main result is
// never affected.
// ---------------------------------------------------------------------------
async function showAiExplanation(url) {
  try {
    const result = document.getElementById('result');
    if (!result || !url) return;
    let box = document.getElementById('ai-explanation');
    if (!box) {
      box = document.createElement('div');
      box.id = 'ai-explanation';
      box.className = 'ai-explanation';
      result.appendChild(box);
    }
    box.textContent = 'Loading AI explanation…';
    const resp = await fetch(`${apiServerUrl}/explain_url?url=${encodeURIComponent(url)}`);
    if (!resp.ok) { box.remove(); return; }
    const data = await resp.json();
    const pretty = (f) => {
      const [kind, ...rest] = f.split(':');
      const name = rest.join(':');
      if (kind === 'lex') return name.replace(/_/g, ' ');
      if (kind === 'word') return `word “${name}”`;
      return `pattern “${name}”`;
    };
    const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const list = (items, cls) => items.slice(0, 4).map((i) =>
      `<li class="${cls}"><span>${esc(pretty(i.feature))}</span><b>${i.contribution > 0 ? '+' : ''}${i.contribution.toFixed(2)}</b></li>`).join('');
    const pct = (data.phishing_probability * 100).toFixed(1);
    box.innerHTML = `
      <div class="ai-explanation-title">🧠 Why? AI explanation</div>
      <div class="ai-explanation-prob">ML phishing probability: <b>${pct}%</b></div>
      ${data.toward_phishing.length ? `<div class="ai-explanation-sub">Pushed toward phishing</div><ul>${list(data.toward_phishing, 'up')}</ul>` : ''}
      ${data.toward_legitimate.length ? `<div class="ai-explanation-sub">Pushed toward safe</div><ul>${list(data.toward_legitimate, 'down')}</ul>` : ''}`;
  } catch (e) {
    const box = document.getElementById('ai-explanation');
    if (box) box.remove();
  }
}
