(function () {
  var container = null;
  function getContainer() {
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      container.setAttribute('aria-live', 'polite');
      document.body.appendChild(container);
    }
    return container;
  }
  function showToast(message, isError) {
    var el = document.createElement('div');
    el.className = 'toast' + (isError ? ' error' : '');
    el.textContent = message;
    getContainer().appendChild(el);
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 4000);
  }
  window.showToast = showToast;
  window.showError = function (message) {
    showToast(message || 'Something went wrong', true);
  };
})();
