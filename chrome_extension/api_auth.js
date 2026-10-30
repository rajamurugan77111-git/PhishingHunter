// Phishing Hunter: attach the API key (Settings -> API key) to every request sent to
// the Phishing Hunter API server. Loaded by the popup and the background worker.
(function () {
  const SERVER_PREFIXES = ['http://localhost:5000', 'http://127.0.0.1:5000',
                           'https://localhost:5000', 'https://127.0.0.1:5000'];
  let apiKey = '';
  const ready = new Promise((resolve) => {
    try {
      chrome.storage.local.get(['phApiKey'], (r) => { apiKey = (r && r.phApiKey) || ''; resolve(); });
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.phApiKey) apiKey = changes.phApiKey.newValue || '';
      });
    } catch (e) { resolve(); }
  });
  const originalFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (SERVER_PREFIXES.some((p) => url.startsWith(p))) {
      await ready;
      if (apiKey) {
        const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
        headers.set('X-API-Key', apiKey);
        init = { ...init, headers };
      }
    }
    return originalFetch(input, init);
  };
})();
