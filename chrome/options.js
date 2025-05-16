
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('options-form');
  const checkboxes = Array.from(form.querySelectorAll('input[type="checkbox"]'));

  // Load saved settings
  chrome.storage.sync.get('iocSelections', (data) => {
    const saved = data.iocSelections || {};
    checkboxes.forEach(box => {
      if (saved[box.id]) {
        box.checked = true;
      }
    });
  });

  // Save settings
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const selections = {};
    checkboxes.forEach(box => {
      selections[box.id] = box.checked;
    });
    chrome.storage.sync.set({ iocSelections: selections }, () => {
      const savedMsg = document.createElement('div');
      savedMsg.textContent = 'Preferences saved!';
      savedMsg.style.color = 'green';
      form.appendChild(savedMsg);
      setTimeout(() => savedMsg.remove(), 2000);
    });
  });
});
