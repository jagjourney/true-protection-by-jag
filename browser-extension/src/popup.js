document.addEventListener('DOMContentLoaded', () => {
  chrome.runtime.sendMessage({ type: 'getStats' }, (stats) => {
    if (stats) {
      document.getElementById('scanned').textContent = stats.scanned || 0;
      document.getElementById('blocked').textContent = stats.blocked || 0;
    }
  });
});
