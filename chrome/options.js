
document.addEventListener('DOMContentLoaded', () => {
  const types = ['ip', 'domain', 'hash', 'url', 'email', 'sandbox'];
  // Load saved settings
  types.forEach(type => {
    chrome.storage.sync.get([type + 'Tools'], data => {
      const list = data[type + 'Tools'] || [];
      list.forEach(tool => {
        const checkbox = document.querySelector(`input[name="${type}Tool"][value="${tool}"]`);
        if (checkbox) checkbox.checked = true;
      });
    });
  });

  // Save on button click
  document.getElementById('saveBtn').addEventListener('click', () => {
    types.forEach(type => {
      const checked = Array.from(document.querySelectorAll(`input[name="${type}Tool"]:checked`))
                           .map(cb => cb.value);
      chrome.storage.sync.set({ [type + 'Tools']: checked });
    });
    const status = document.getElementById('status');
    status.textContent = 'Settings saved!';
    setTimeout(() => { status.textContent = ''; }, 1500);
  });
});
