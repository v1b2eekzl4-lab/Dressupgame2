const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'hosted-uploads.json');
const URL_KEYS = new Set([
  'src', 'url', 'imageUrl', 'profilePictureUrl', 'mergedImageUrl',
  'wallpaperUrl', 'forumHeaderGraphic', 'hoverCardSignatureImage'
]);

let map = {};

function load() {
  try {
    if (fs.existsSync(FILE)) {
      const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
      if (parsed && typeof parsed === 'object') map = parsed;
    }
  } catch (_) {
    map = {};
  }
  return map;
}

load();

function save() {
  fs.writeFileSync(FILE, JSON.stringify(map, null, 2), 'utf8');
}

function normalizeKey(p) {
  let s = String(p || '').replace(/\\/g, '/');
  if (!s || s.startsWith('data:')) return s || '';
  const local = s.match(/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?(\/Uploads\/.+)$/i);
  if (local) s = local[1];
  if (s.startsWith('Uploads/')) s = '/' + s;
  else if (!s.startsWith('/') && !/^https?:\/\//i.test(s)) s = '/Uploads/' + s;
  return s.split('?')[0];
}

function getUrl(p) {
  const key = normalizeKey(p);
  return map[key] || null;
}

function setUrl(p, url) {
  const key = normalizeKey(p);
  if (!key || !url) return;
  map[key] = url;
  save();
}

function merge(entries) {
  let changed = 0;
  Object.entries(entries || {}).forEach(([key, url]) => {
    const k = normalizeKey(key);
    if (k && url && map[k] !== url) {
      map[k] = url;
      changed++;
    }
  });
  if (changed) save();
  return changed;
}

function resolvePublicUrl(url) {
  if (!url || typeof url !== 'string') return url;
  if (url.startsWith('data:')) return url;
  if (/^https?:\/\//i.test(url) && !/localhost|127\.0\.0\.1/i.test(url)) return url;
  const hosted = getUrl(url);
  if (hosted) return hosted;
  const key = normalizeKey(url);
  return key.startsWith('/Uploads/') ? key : url;
}

function looksLikeAssetPath(s) {
  if (typeof s !== 'string' || !s) return false;
  if (s.startsWith('data:')) return false;
  if (/^https?:\/\//i.test(s) || s.startsWith('//')) return true;
  if (s.startsWith('/Uploads/') || s.startsWith('Uploads/') || s.startsWith('/img/')) return true;
  return false;
}

function resolveUrlsDeep(value) {
  if (typeof value === 'string') {
    return looksLikeAssetPath(value) ? resolvePublicUrl(value) : value;
  }
  if (Array.isArray(value)) return value.map(resolveUrlsDeep);
  if (value && typeof value === 'object') {
    const out = {};
    Object.keys(value).forEach((k) => {
      if (URL_KEYS.has(k) && typeof value[k] === 'string') out[k] = resolvePublicUrl(value[k]);
      else out[k] = resolveUrlsDeep(value[k]);
    });
    return out;
  }
  return value;
}

function middleware(req, res, next) {
  const hosted = getUrl('/Uploads' + req.path);
  if (hosted) return res.redirect(302, hosted);
  next();
}

module.exports = {
  load,
  getUrl,
  setUrl,
  merge,
  resolvePublicUrl,
  resolveUrlsDeep,
  middleware,
  normalizeKey
};
