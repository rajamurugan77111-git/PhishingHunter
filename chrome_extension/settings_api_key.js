// Settings tab: store the API server key used by api_auth.js.
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('phApiKey');
  const btn = document.getElementById('phApiKeySave');
  const msg = document.getElementById('phApiKeyMsg');
  if (!input || !btn) return;
  chrome.storage.local.get(['phApiKey'], (r) => { input.value = (r && r.phApiKey) || ''; });
  btn.addEventListener('click', async () => {
    const key = input.value.trim();
    await chrome.storage.local.set({ phApiKey: key });
    try {
      const resp = await fetch('http://localhost:5000/model_info');
      msg.textContent = resp.ok ? 'Saved ✓ — server accepted the key'
        : resp.status === 401 ? 'Saved, but the server rejected this key' : `Saved (server: ${resp.status})`;
    } catch (e) {
      msg.textContent = 'Saved ✓ (server not reachable right now)';
    }
  });
});
