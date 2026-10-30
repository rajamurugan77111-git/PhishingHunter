// Debug script for testing notification system
// This file can be copied into the browser console for debugging

console.log('🔧 Starting notification debug session...');

// Test 1: Check if chrome.notifications API is available
function testNotificationAPI() {
    console.log('\n=== TEST 1: Chrome Notifications API ===');
    
    if (typeof chrome !== 'undefined' && chrome.notifications) {
        console.log('✅ Chrome notifications API is available');
        
        // Check permissions
        chrome.permissions.contains({permissions: ['notifications']}, (result) => {
            if (result) {
                console.log('✅ Notifications permission granted');
            } else {
                console.log('❌ Notifications permission NOT granted');
            }
        });
        
        return true;
    } else {
        console.log('❌ Chrome notifications API NOT available');
        return false;
    }
}

// Test 2: Test basic notification creation
function testBasicNotification() {
    console.log('\n=== TEST 2: Basic Notification Creation ===');
    
    const notificationId = `test_${Date.now()}`;
    
    chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: 'icon.png',
        title: '🧪 TEST: Basic Notification',
        message: 'This is a test notification to verify the system is working.',
        priority: 1
    }, (createdId) => {
        if (chrome.runtime.lastError) {
            console.log('❌ Basic notification failed:', chrome.runtime.lastError.message);
        } else {
            console.log('✅ Basic notification created:', createdId);
        }
    });
}

// Test 3: Test notification with different options
function testAdvancedNotification() {
    console.log('\n=== TEST 3: Advanced Notification ===');
    
    const notificationId = `advanced_test_${Date.now()}`;
    
    chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: 'icons/warning.png',
        title: '⚠️ TEST: Advanced Notification',
        message: 'This notification tests advanced features like priority and interaction.',
        priority: 2,
        requireInteraction: true
    }, (createdId) => {
        if (chrome.runtime.lastError) {
            console.log('❌ Advanced notification failed:', chrome.runtime.lastError.message);
        } else {
            console.log('✅ Advanced notification created:', createdId);
        }
    });
}

// Test 4: Check storage settings
function testStorageSettings() {
    console.log('\n=== TEST 4: Storage Settings Check ===');
    
    chrome.storage.local.get(['notificationSettings', 'phishingHunterSettings'], (result) => {
        console.log('📋 Notification settings:', result.notificationSettings);
        console.log('📋 Phishing Hunter settings:', result.phishingHunterSettings);
        
        const notificationsEnabled = (result.notificationSettings?.enabled !== false) && 
                                    (result.phishingHunterSettings?.autoThreatAlerts !== false) &&
                                    (result.phishingHunterSettings?.showNotifications !== false);
        
        if (notificationsEnabled) {
            console.log('✅ Notifications are enabled in settings');
        } else {
            console.log('❌ Notifications are DISABLED in settings');
            console.log('   - notificationSettings.enabled:', result.notificationSettings?.enabled);
            console.log('   - phishingHunterSettings.autoThreatAlerts:', result.phishingHunterSettings?.autoThreatAlerts);
            console.log('   - phishingHunterSettings.showNotifications:', result.phishingHunterSettings?.showNotifications);
        }
    });
}

// Test 5: Send message to background script
function testBackgroundMessage() {
    console.log('\n=== TEST 5: Background Script Communication ===');
    
    const testMessage = {
        action: 'testNotification'
    };
    
    console.log('📤 Sending message to background:', testMessage);
    
    chrome.runtime.sendMessage(testMessage, (response) => {
        if (chrome.runtime.lastError) {
            console.log('❌ Background message failed:', chrome.runtime.lastError.message);
            console.log('❌ Last error object:', chrome.runtime.lastError);
        } else if (response && response.success) {
            console.log('✅ Background script test successful:', response);
        } else {
            console.log('❌ Background script test failed:', response);
            console.log('❌ Response object details:', JSON.stringify(response, null, 2));
        }
    });
}

// Test 6: Browser notification permission check
function testBrowserPermissions() {
    console.log('\n=== TEST 6: Browser Notification Permissions ===');
    
    if ('Notification' in window) {
        console.log('📋 Browser notification permission:', Notification.permission);
        
        switch (Notification.permission) {
            case 'granted':
                console.log('✅ Browser notifications are ALLOWED');
                break;
            case 'denied':
                console.log('❌ Browser notifications are BLOCKED');
                console.log('   → Go to Chrome Settings > Privacy and Security > Site Settings > Notifications');
                console.log('   → Find this extension and set to "Allow"');
                break;
            case 'default':
                console.log('⚠️ Browser notifications not yet requested');
                console.log('   → Requesting permission now...');
                Notification.requestPermission().then(permission => {
                    console.log('📋 New permission result:', permission);
                });
                break;
        }
    } else {
        console.log('❌ Browser Notification API not available');
    }
}

// Run all tests
function runAllTests() {
    console.log('🔧 Running comprehensive notification debugging...\n');
    
    testNotificationAPI();
    setTimeout(() => testStorageSettings(), 500);
    setTimeout(() => testBrowserPermissions(), 1000);
    setTimeout(() => testPingBackground(), 1500);
    setTimeout(() => testBasicNotification(), 2000);
    setTimeout(() => testAdvancedNotification(), 2500);
    setTimeout(() => testBackgroundMessage(), 3000);
    
    setTimeout(() => {
        console.log('\n=== DEBUGGING COMPLETE ===');
        console.log('📋 Check the results above to identify the issue.');
        console.log('📋 If notifications still don\'t work, check:');
        console.log('   1. Chrome notification permissions');
        console.log('   2. Extension notification settings');
        console.log('   3. System notification settings (Windows/Mac)');
    }, 3500);
}

// Test 7: Simple ping test
function testPingBackground() {
    console.log('\n=== TEST 7: Simple Ping Test ===');
    
    chrome.runtime.sendMessage({
        action: 'getDebugInfo'
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.log('❌ Ping failed:', chrome.runtime.lastError.message);
        } else {
            console.log('✅ Ping successful:', response);
        }
    });
}

// Export functions for manual testing
window.debugNotifications = {
    runAllTests,
    testNotificationAPI,
    testBasicNotification,
    testAdvancedNotification,
    testStorageSettings,
    testBackgroundMessage,
    testBrowserPermissions,
    testPingBackground
};

console.log('🔧 Notification debug tools loaded!');
console.log('📋 Run: debugNotifications.runAllTests() to start debugging');
console.log('📋 Or run individual tests like: debugNotifications.testBasicNotification()');
