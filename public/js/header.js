(function () {
  var THEME_KEY = 'dressup-theme';
  function getStoredTheme() {
    try {
      var t = localStorage.getItem(THEME_KEY);
      return t === 'dark' || t === 'light' ? t : 'light';
    } catch (e) { return 'light'; }
  }
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
  }
  setTheme(getStoredTheme());

  // Site wallpaper: apply from site settings (debug upload)
  fetch('/api/site-settings', { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .catch(function () { return null; })
    .then(function (data) {
      var url = (data && data.wallpaperUrl) ? data.wallpaperUrl : '';
      if (url && document.body) {
        document.body.style.backgroundImage = 'url(' + url + ')';
        document.body.style.backgroundSize = 'cover';
        document.body.style.backgroundPosition = 'center';
        document.body.style.backgroundRepeat = 'no-repeat';
        document.body.style.backgroundAttachment = 'fixed';
      }
    });

  var placeholder = document.getElementById('header-placeholder');
  if (!placeholder) return;
  fetch('/api/me', { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : {}; })
    .catch(function () { return {}; })
    .then(function (me) {
      var guest = !(me && me.userId != null);
      return fetch(guest ? './partials/header-guest.html' : './partials/header.html')
        .then(function (r) { return r.text(); })
        .then(function (html) {
          placeholder.outerHTML = html;
          (function setActiveTab() {
            var pathname = window.location.pathname.replace(/\/$/, '') || '/';
            var nav = document.querySelector('.header-nav');
            if (!nav) return;
            nav.querySelectorAll('.header-button').forEach(function (link) {
              var href = link.getAttribute('href');
              if (!href) return;
              var linkPath = new URL(href, window.location.origin).pathname.replace(/\/$/, '') || '/';
              var isProfileLink = linkPath === '/profile';
              var isCurrentProfile = pathname === '/profile' || pathname.indexOf('/profile-') === 0 || pathname === '/profile-bio';
              var isHomeLink = (linkPath === '/home.html' || linkPath === '/' || linkPath === '');
              var isCurrentHome = (pathname === '/' || pathname === '/home.html');
              var active = (pathname === linkPath) || (isProfileLink && isCurrentProfile) || (isHomeLink && isCurrentHome);
              if (active) link.classList.add('header-button-active');
            });
          })();
          var themeBtn = document.getElementById('header-theme-toggle');
          if (themeBtn) {
            themeBtn.addEventListener('click', function () {
              var current = document.documentElement.dataset.theme || getStoredTheme();
              var next = current === 'dark' ? 'light' : 'dark';
              setTheme(next);
            });
          }
          return guest;
        });
    })
    .then(function (guest) {
      if (!guest) {
        var script = document.createElement('script');
        script.src = '/js/messages-panel.js';
        script.async = false;
        document.body.appendChild(script);
        fetch('/api/me', { credentials: 'same-origin' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; }).then(function (me) {
          var roles = (me && me.roles) || [];
          var isAdmin = roles.indexOf('admin') !== -1;
          var isModOrAdmin = roles.indexOf('admin') !== -1 || roles.indexOf('moderator') !== -1;
          var mod = document.getElementById('header-moderation');
          if (mod) mod.style.display = isModOrAdmin ? '' : 'none';
        });
        var badge = document.getElementById('header-messages-badge');
        if (badge) {
          fetch('/api/messages/unread-count', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
              if (data && data.unreadCount > 0) {
                badge.textContent = data.unreadCount > 99 ? '99+' : data.unreadCount;
                badge.style.display = 'inline-block';
              }
            })
            .catch(function () {});
        }
        function refreshHeaderCurrency() {
          fetch('/api/user-inventory', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
              var el3 = document.getElementById('header-currency3-amount');
              if (el3) el3.textContent = data && data.currency3 != null ? data.currency3 : '0';
              var el = document.getElementById('header-currency-amount');
              if (el) el.textContent = data && data.currency != null ? data.currency : '0';
              var el2 = document.getElementById('header-currency2-amount');
              if (el2) el2.textContent = data && data.currency2 != null ? data.currency2 : '0';
              var elTickets = document.getElementById('header-golden-tickets-amount');
              if (elTickets) elTickets.textContent = data && data.goldenTickets != null ? data.goldenTickets : '0';
            })
            .catch(function () {});
        }
        refreshHeaderCurrency();
        window.updateHeaderCurrency = refreshHeaderCurrency;
        // User search in secondary header (expand from glass icon on click)
        var searchWrap = document.getElementById('header-search-wrap');
        var searchTrigger = document.getElementById('header-search-trigger');
        var searchInput = document.getElementById('header-search-users');
        var searchResults = document.getElementById('header-search-users-results');
        if (searchWrap && searchTrigger && searchInput && searchResults) {
          searchTrigger.addEventListener('click', function () {
            if (searchWrap.classList.contains('expanded')) return;
            searchWrap.classList.add('expanded');
            searchTrigger.setAttribute('aria-expanded', 'true');
            setTimeout(function () { searchInput.focus(); }, 100);
          });
          function collapseSearch() {
            searchWrap.classList.remove('expanded');
            searchTrigger.setAttribute('aria-expanded', 'false');
            searchInput.value = '';
            searchResults.classList.add('hidden');
            searchResults.innerHTML = '';
          }
          searchInput.addEventListener('blur', function () {
            setTimeout(function () {
              if (document.activeElement && searchResults.contains(document.activeElement)) return;
              searchResults.classList.add('hidden');
              searchWrap.classList.remove('expanded');
              searchTrigger.setAttribute('aria-expanded', 'false');
            }, 180);
          });
          searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
              collapseSearch();
              searchInput.blur();
            }
          });
          var debounceTimer = 0;
          searchInput.addEventListener('input', function () {
            clearTimeout(debounceTimer);
            var q = (searchInput.value || '').trim();
            if (!q) {
              searchResults.classList.add('hidden');
              searchResults.innerHTML = '';
              return;
            }
            debounceTimer = setTimeout(function () {
              fetch('/api/users/search?q=' + encodeURIComponent(q), { credentials: 'same-origin' })
                .then(function (r) { return r.ok ? r.json() : []; })
                .catch(function () { return []; })
                .then(function (list) {
                  if (!Array.isArray(list) || list.length === 0) {
                    searchResults.innerHTML = '<span class="header-online-empty" style="display:block;padding:8px 10px;">No users found</span>';
                  } else {
                    searchResults.innerHTML = list.map(function (u) {
                      return '<a href="/profile?user=' + encodeURIComponent(u.id) + '">' + (u.username || '') + '</a>';
                    }).join('');
                  }
                  searchResults.classList.remove('hidden');
                });
            }, 200);
          });
          searchInput.addEventListener('focus', function () {
            if (searchResults.innerHTML) searchResults.classList.remove('hidden');
          });
        }
        // Online users in secondary header
        function loadOnlineUsers() {
          var container = document.getElementById('header-online-users');
          if (!container) return;
          fetch('/api/users/online', { credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
              var users = (data && data.users) ? data.users : [];
              if (users.length === 0) {
                container.innerHTML = '<span class="header-online-empty">No one else online</span>';
              } else {
                container.innerHTML = users.map(function (u) {
                  return '<a href="/profile?user=' + encodeURIComponent(u.id) + '">' + (u.username || '') + '</a>';
                }).join('');
              }
            })
            .catch(function () {
              var c = document.getElementById('header-online-users');
              if (c) c.innerHTML = '<span class="header-online-empty">—</span>';
            });
        }
        loadOnlineUsers();
        setInterval(loadOnlineUsers, 30000);
      }
    })
    .catch(function (err) {
      console.error('Failed to load header:', err);
    });
})();
