(function () {
  var overlay = document.getElementById('messages-panel-overlay');
  var toggleBtn = document.getElementById('header-messages-toggle');
  var closeBtn = document.getElementById('messages-panel-close');
  var listEl = document.getElementById('messages-panel-list');
  var detailEl = document.getElementById('messages-panel-detail');
  var detailMeta = document.getElementById('messages-panel-detail-meta');
  var detailBody = document.getElementById('messages-panel-detail-body');
  var toInput = document.getElementById('messages-panel-to');
  var toResults = document.getElementById('messages-panel-to-results');
  var bodyInput = document.getElementById('messages-panel-body');
  var sendBtn = document.getElementById('messages-panel-send');
  var sendError = document.getElementById('messages-panel-send-error');

  if (!overlay || !toggleBtn) return;

  var selectedToUserId = null;
  var selectedToUsername = null;

  function openPanel() {
    overlay.style.display = 'flex';
    overlay.setAttribute('aria-hidden', 'false');
    if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'true');
    loadInbox();
    document.body.style.overflow = 'hidden';
  }

  function closePanel() {
    overlay.style.display = 'none';
    overlay.setAttribute('aria-hidden', 'true');
    if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }

  function loadInbox() {
    if (!listEl) return;
    listEl.innerHTML = '<div class="messages-panel-empty">Loading…</div>';
    fetch('/api/messages', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!listEl) return;
        if (!data || !Array.isArray(data.messages)) {
          listEl.innerHTML = '<div class="messages-panel-empty">Could not load messages.</div>';
          return;
        }
        var messages = data.messages;
        if (messages.length === 0) {
          listEl.innerHTML = '<div class="messages-panel-empty">No messages yet. Send one using the form below.</div>';
          return;
        }
        listEl.innerHTML = messages.map(function (m) {
          var date = m.createdAt ? new Date(m.createdAt).toLocaleString() : '—';
          var preview = (m.body || '').slice(0, 60) + ((m.body || '').length > 60 ? '…' : '');
          var unreadClass = m.read ? '' : ' unread';
          var name = m.fromUsername || 'Unknown';
          var letter = name.charAt(0).toUpperCase();
          var hue = (name.split('').reduce(function (a, c) { return a + c.charCodeAt(0); }, 0) % 360);
          var bg = 'hsl(' + hue + ', 55%, 45%)';
          return '<div class="messages-panel-row' + unreadClass + '" data-id="' + (m.id || '') + '">' +
            '<span class="messages-panel-avatar" style="background:' + bg + '">' + letter + '</span>' +
            '<span class="from">' + (name || '').replace(/</g, '&lt;') + '</span>' +
            '<span class="preview">' + (preview || '').replace(/</g, '&lt;') + '</span>' +
            '<span class="date">' + (date || '').replace(/</g, '&lt;') + '</span></div>';
        }).join('');
        listEl.querySelectorAll('.messages-panel-row').forEach(function (row) {
          row.addEventListener('click', function () {
            var id = row.dataset.id;
            showMessage(id);
            row.classList.remove('unread');
            row.style.fontWeight = '';
            var p = row.querySelector('.preview');
            if (p) p.style.color = '';
          });
        });
      })
      .catch(function () {
        if (listEl) listEl.innerHTML = '<div class="messages-panel-empty">Could not load messages.</div>';
      });
  }

  function showMessage(id) {
    fetch('/api/messages', { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        var msg = (data && data.messages) ? data.messages.find(function (m) { return m.id === id; }) : null;
        if (!msg || !detailMeta || !detailBody || !detailEl) return;
        detailMeta.textContent = 'From: ' + (msg.fromUsername || '—') + ' · ' + (msg.createdAt ? new Date(msg.createdAt).toLocaleString() : '');
        detailBody.textContent = msg.body || '';
        detailEl.style.display = 'block';
        fetch('/api/messages/' + encodeURIComponent(id) + '/read', {
          method: 'PATCH',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' }
        }).then(function () {
          var badge = document.getElementById('header-messages-badge');
          if (badge) {
            fetch('/api/messages/unread-count', { credentials: 'same-origin' })
              .then(function (r) { return r.ok ? r.json() : null; })
              .then(function (d) {
                if (d && d.unreadCount > 0) {
                  badge.textContent = d.unreadCount > 99 ? '99+' : d.unreadCount;
                  badge.style.display = 'inline-block';
                } else {
                  badge.style.display = 'none';
                }
              });
          }
        }).catch(function () {});
      });
  }

  toggleBtn.addEventListener('click', function (e) {
    e.preventDefault();
    if (overlay.style.display === 'flex') closePanel(); else openPanel();
  });

  if (closeBtn) closeBtn.addEventListener('click', closePanel);

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closePanel();
  });
  var panel = overlay.querySelector('.messages-panel');
  if (panel) panel.addEventListener('click', function (e) { e.stopPropagation(); });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay && overlay.style.display === 'flex') closePanel();
  });

  if (toInput) {
    toInput.addEventListener('input', function () {
      selectedToUserId = null;
      selectedToUsername = null;
      var q = (toInput.value || '').trim();
      if (q.length < 2) {
        toResults.classList.remove('visible');
        toResults.innerHTML = '';
        return;
      }
      fetch('/api/users/search?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (users) {
          if (!users.length) {
            toResults.innerHTML = '<div class="px-3 py-2 text-sm text-gray-500">No users found</div>';
          } else {
            toResults.innerHTML = users.map(function (u) {
              return '<div class="px-3 py-2 text-sm cursor-pointer hover:bg-gray-100" data-id="' + (u.id || '') + '" data-username="' + (u.username || '').replace(/"/g, '&quot;') + '">' + (u.username || '').replace(/</g, '&lt;') + '</div>';
            }).join('');
            toResults.querySelectorAll('div[data-id]').forEach(function (div) {
              div.addEventListener('click', function () {
                selectedToUserId = div.dataset.id;
                selectedToUsername = div.dataset.username;
                toInput.value = div.dataset.username || '';
                toResults.classList.remove('visible');
              });
            });
          }
          toResults.classList.add('visible');
        });
    });
    toInput.addEventListener('blur', function () { setTimeout(function () { toResults.classList.remove('visible'); }, 150); });
  }

  if (sendBtn && sendError) {
    sendBtn.addEventListener('click', function () {
      sendError.textContent = '';
      var body = (bodyInput && bodyInput.value) ? bodyInput.value.trim() : '';
      if (!selectedToUserId) {
        sendError.textContent = 'Please select a recipient (search and click a username).';
        return;
      }
      if (!body) {
        sendError.textContent = 'Please enter a message.';
        return;
      }
      sendBtn.disabled = true;
      fetch('/api/messages', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toUserId: selectedToUserId, body: body })
      })
        .then(function (r) {
          if (!r.ok) return r.json().then(function (err) { throw new Error(err.error || 'Send failed'); });
          if (bodyInput) bodyInput.value = '';
          loadInbox();
          if (typeof showToast === 'function') showToast('Message sent!');
          else if (typeof alert === 'function') alert('Message sent!');
        })
        .catch(function (err) {
          sendError.textContent = err.message || 'Failed to send message.';
        })
        .finally(function () { sendBtn.disabled = false; });
    });
  }
})();
