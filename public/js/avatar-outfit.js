(function (w) {
  var SLOT_ORDER = ['body-slot', 'shirt-slot', 'pants-slot', 'skirt-slot', 'dress-slot', 'jacket-slot', 'shoes-slot', 'hat-slot', 'jewelry-slot', 'other-slot', 'hair-slot', 'socks-slot', 'makeup-slot'];
  var BASE = '/img/character.png';

  function isPlaceholderAvatarSrc(src) {
    var s = String(src || '');
    return /dfer5erer/i.test(s) || /via\.placeholder\.com/i.test(s) || /p4vl0v\.neocities\.org\/dfer5erer/i.test(s);
  }

  function canvasImageSrc(src) {
    src = String(src || '').trim();
    if (!src || isPlaceholderAvatarSrc(src)) return BASE;
    if (src.indexOf('i.ibb.co/938sCGCJ/character.png') !== -1) return BASE;
    src = src.replace(/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?(\/Uploads\/.+)$/i, '$1');
    if (/^https?:\/\/i\.ibb\.co\//i.test(src)) return '/media/proxy?u=' + encodeURIComponent(src);
    return src;
  }

  function equippedToLayers(equipped) {
    if (!equipped || typeof equipped !== 'object') return null;
    var all = [];
    SLOT_ORDER.forEach(function (slotId) {
      var arr = equipped[slotId];
      if (!Array.isArray(arr)) return;
      arr.forEach(function (item) {
        if (!item || typeof item !== 'object') return;
        var src = String(item.src || item.imageUrl || '');
        if (!src || isPlaceholderAvatarSrc(src)) return;
        all.push({
          src: src,
          x: item.x != null ? item.x : 0,
          y: item.y != null ? item.y : 0,
          z: item.zIndex != null ? item.zIndex : 0,
          zIndex: item.zIndex != null ? item.zIndex : 0,
          alt: item.alt || '',
          slotId: item.slotId || slotId
        });
      });
    });
    if (!all.length) return null;
    all.sort(function (a, b) { return (a.z || 0) - (b.z || 0); });
    return all;
  }

  function layersWithBase(layers) {
    var rest = Array.isArray(layers) ? layers.filter(function (l) {
      if (!l) return false;
      var src = String(l.src || '');
      if (!src || isPlaceholderAvatarSrc(src)) return false;
      if (src.indexOf('character.png') !== -1) return false;
      return true;
    }) : [];
    return [{ src: BASE, x: 0, y: 0, z: -1, zIndex: -1 }].concat(rest);
  }

  function fetchEquipped(userId) {
    var self = (userId == null || userId === '' || userId === 'me');
    var url = self ? '/api/equipped-items' : '/api/users/' + encodeURIComponent(userId) + '/equipped';
    return fetch(url, { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : {}; })
      .catch(function () { return {}; });
  }

  function snapshotEquippedItems() {
    return fetchEquipped('me').then(function (equipped) {
      return equippedToLayers(equipped);
    });
  }

  function renderEquippedLayers(container, equipped, opts) {
    if (!container) return;
    opts = opts || {};
    var layers = equippedToLayers(equipped) || [];
    layers.forEach(function (item) {
      var el = document.createElement('img');
      if (opts.className) el.className = opts.className;
      var src = canvasImageSrc((item.src || item.imageUrl || '').trim());
      if (src && src.indexOf('/') === 0) src = w.location.origin + src;
      el.referrerPolicy = 'no-referrer';
      el.src = src || '';
      el.alt = item.alt || '';
      el.style.zIndex = item.zIndex != null ? item.zIndex : 2;
      el.style.transform = 'translate(-50%, -50%) translate(' + (item.x || 0) + 'px, ' + (item.y || 0) + 'px)';
      el.onerror = function () { el.style.display = 'none'; };
      if (typeof opts.onItem === 'function') opts.onItem(el, item);
      container.appendChild(el);
    });
  }

  w.AVATAR_BASE = BASE;
  w.isPlaceholderAvatarSrc = isPlaceholderAvatarSrc;
  w.canvasImageSrc = canvasImageSrc;
  w.equippedToLayers = equippedToLayers;
  w.layersWithBase = layersWithBase;
  w.fetchEquipped = fetchEquipped;
  w.snapshotEquippedItems = snapshotEquippedItems;
  w.renderEquippedLayers = renderEquippedLayers;
})(window);
