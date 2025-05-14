document.addEventListener('DOMContentLoaded', () => {
  // Load saved preferences
  chrome.storage.local.get(['quickdrawPrefs'], (result) => {
    const prefs = result.quickdrawPrefs || {};
    document.querySelectorAll('input[type="checkbox"]').forEach((box) => {
      const type = box.dataset.type;
      const val = box.value;
      box.checked = prefs[type]?.includes(val);
    });
  });

  // Save preferences
  document.getElementById('save').addEventListener('click', () => {
    const prefs = {};
    document.querySelectorAll('input[type="checkbox"]').forEach((box) => {
      if (!prefs[box.dataset.type]) prefs[box.dataset.type] = [];
      if (box.checked) prefs[box.dataset.type].push(box.value);
    });
    chrome.storage.local.set({ quickdrawPrefs: prefs }, () => {
      document.getElementById('status').textContent = 'Saved!';
      setTimeout(() => {
        document.getElementById('status').textContent = '';
      }, 2000);
    });
  });
});
