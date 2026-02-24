/**
 * Shared API helpers: clear error messages for failed fetch (server vs network).
 * Use handleApiResponse(res) after fetch when you need to show server errors;
 * in catch(), use showError(err.message || 'Network error').
 */
(function () {
  function showError(msg) {
    if (typeof window.showError === 'function') window.showError(msg);
    else if (typeof window.showToast === 'function') window.showToast(msg || 'Something went wrong', true);
  }

  /**
   * Call after fetch(). If res is not ok, reads body for error message, shows it, and throws.
   * @param {Response} res
   * @returns {Promise<Response>} same res if ok
   */
  function handleApiResponse(res) {
    if (res.ok) return Promise.resolve(res);
    return res.json().catch(function () { return {}; }).then(function (body) {
      var msg = (body && body.error && typeof body.error === 'string')
        ? body.error
        : ('Server error: ' + (res.status || '') + ' ' + (res.statusText || 'Request failed'));
      showError(msg);
      throw new Error(msg);
    });
  }

  /**
   * fetch() then handleApiResponse. Use .catch(err => { showError(err.message || 'Network error'); }) for network errors.
   */
  function apiFetch(url, options) {
    options = options || {};
    return fetch(url, options).then(function (res) {
      return handleApiResponse(res);
    });
  }

  window.handleApiResponse = handleApiResponse;
  window.apiFetch = apiFetch;
})();
