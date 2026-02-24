require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const https = require('https');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

/** Atomic write: write to .tmp then rename, so we never leave a half-written file (safer with concurrent users). */
function writeAtomic(filePath, content) {
  const tmpPath = filePath + '.tmp.' + process.pid + '.' + Date.now();
  fs.writeFileSync(tmpPath, content, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

/** In-process lock per key so only one read-modify-write runs at a time (prevents lost updates with concurrent users). */
const lockQueues = new Map();
function withLock(key, fn) {
  let q = lockQueues.get(key);
  if (!q) {
    q = [];
    lockQueues.set(key, q);
  }
  const runNext = () => {
    setImmediate(() => {
      q.shift();
      if (q.length > 0) q[0]();
    });
  };
  const wrapped = () => {
    try {
      return fn();
    } finally {
      runNext();
    }
  };
  q.push(wrapped);
  if (q.length === 1) wrapped();
}

const usersFile = path.join(__dirname, 'users.json');
const EARN_CURRENCY_CAP = 50;
const USERNAME_MIN = 3;
const USERNAME_MAX = 30;
const USERNAME_REGEX = /^[a-zA-Z0-9_]+$/;
const PASSWORD_MIN = 6;
const PASSWORD_MAX = 500;

// Administrator account: user id 1 (has admin role; access to moderation). Set ADMIN_PASSWORD in .env for production.
const ADMIN_USER = {
  id: 1,
  username: process.env.ADMIN_USERNAME || 'admin',
  password: process.env.ADMIN_PASSWORD || 'password',
  roles: ['admin']
};

function loadUsers() {
  try {
    if (fs.existsSync(usersFile)) {
      const data = fs.readFileSync(usersFile, 'utf8');
      const users = JSON.parse(data);
      if (!Array.isArray(users)) return [];
      // Backfill missing ids: assign next available id (2, 3, ...)
      let nextId = 2;
      let changed = false;
      const withIds = users.map(u => {
        if (!u) return u;
        let out = typeof u.id === 'number' ? { ...u } : { ...u, id: nextId++ };
        if (typeof out.id === 'number' && out.id >= nextId) nextId = out.id + 1;
        // Ensure user id 2 has admin and moderator roles if missing
        if (out.id === 2) {
          const want = ['admin', 'moderator'];
          const has = Array.isArray(out.roles) ? out.roles : [];
          const missing = want.filter(r => !has.includes(r));
          if (missing.length) {
            out.roles = [...has, ...missing];
            changed = true;
          }
        }
        return out;
      });
      const idChanged = withIds.some((u, i) => u && users[i] && u.id !== users[i].id);
      if (changed || idChanged) saveUsers(withIds);
      return withIds;
    }
  } catch (e) {
    console.error('loadUsers failed:', e.message || e);
  }
  return [];
}

function saveUsers(users) {
  writeAtomic(usersFile, JSON.stringify(users, null, 2));
}

function getUsersForAuth() {
  const fromFile = loadUsers();
  // Dedupe by id so built-in id 1 is used; file users take precedence for id 2+
  const byId = new Map();
  [ADMIN_USER, ...fromFile].forEach(u => { if (u && u.id != null) byId.set(u.id, u); });
  return Array.from(byId.values());
}

/** Returns roles for userId: admin (id 1), or from user record (e.g. id 2 = admin + moderator). */
function getRoles(userId) {
  if (userId == null) return [];
  const id = Number(userId);
  if (id === 1) return ['admin'];
  const users = getUsersForAuth();
  const u = users.find(x => x.id === id);
  return (u && Array.isArray(u.roles)) ? u.roles : [];
}

/** True if user can delete/close forums (admin or moderator; designers cannot). */
function canDeleteForum(userId) {
  const roles = getRoles(userId);
  return roles.includes('admin') || roles.includes('moderator');
}

/** True if user can lock/unlock threads (admin or moderator). */
function canLockForum(userId) {
  const roles = getRoles(userId);
  return roles.includes('admin') || roles.includes('moderator');
}

/** True if user can see item debug (admin, moderator, or designer). */
function canSeeItemDebug(userId) {
  const roles = getRoles(userId);
  return roles.includes('admin') || roles.includes('moderator') || roles.includes('designer');
}

/** True if user can assign roles to others (admin only). */
function canAssignRoles(userId) {
  return getRoles(userId).includes('admin');
}

/** True if user can edit home dashboard (admin or moderator). */
function canEditDashboard(userId) {
  const roles = getRoles(userId);
  return roles.includes('admin') || roles.includes('moderator');
}

/** True if user can view and manage reports (admin or moderator). */
function canViewReports(userId) {
  const roles = getRoles(userId);
  return roles.includes('admin') || roles.includes('moderator');
}

function nextUserId() {
  const users = loadUsers();
  const maxId = users.length ? Math.max(...users.map(u => u.id || 0)) : 0;
  return Math.max(2, maxId + 1);
}

// Simple in-memory rate limit for auth (no extra dependency)
const authRateLimit = new Map();
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_MAX_ATTEMPTS = 10;
function checkAuthRateLimit(req, res, next) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = authRateLimit.get(ip);
  if (!entry || now - entry.start > AUTH_WINDOW_MS) {
    entry = { start: now, count: 0 };
    authRateLimit.set(ip, entry);
  }
  entry.count++;
  if (entry.count > AUTH_MAX_ATTEMPTS) {
    const isJson = req.path.startsWith('/api') || (req.get('accept') || '').includes('application/json');
    if (isJson) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
    return res.redirect(req.path === '/register' ? '/create-account?error=rate' : '/login?error=rate');
  }
  next();
}

// Middleware setup (higher JSON limit so outfit save with merged base64 image succeeds)
app.use(express.json({ limit: '15mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '15mb' }));
const isProduction = process.env.NODE_ENV === 'production';

// Security headers (no helmet dependency)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
// Prevent caching of API responses (user/session data)
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// In-memory online users: userId -> { username, lastSeen }. "Online" = active in last 5 minutes; list excludes current user.
const onlineUsersMap = new Map();
const ONLINE_TTL_MS = 5 * 60 * 1000; // 5 minutes
function touchOnlineUser(userId, username) {
  if (userId == null || !username) return;
  onlineUsersMap.set(userId, { username: String(username), lastSeen: Date.now() });
}
function getOnlineUsers(excludeUserId) {
  const now = Date.now();
  const out = [];
  for (const [id, data] of onlineUsersMap.entries()) {
    if (now - data.lastSeen > ONLINE_TTL_MS) {
      onlineUsersMap.delete(id);
      continue;
    }
    if (excludeUserId != null && Number(id) === Number(excludeUserId)) continue;
    out.push({ id: Number(id), username: data.username });
  }
  return out;
}
app.use(function (req, res, next) {
  if (req.session && req.session.userId != null && req.session.user) {
    touchOnlineUser(req.session.userId, req.session.user);
  }
  next();
});

// Resolve uploads dir: prefer 'Uploads', fallback to 'uploads' (folder may exist as lowercase)
const uploadsDir = fs.existsSync(path.join(__dirname, 'Uploads'))
  ? path.join(__dirname, 'Uploads')
  : path.join(__dirname, 'uploads');
app.use('/Uploads', express.static(uploadsDir, { maxAge: process.env.NODE_ENV === 'production' ? '7d' : 0 }));

// Sticker dir and multer (fully defined here so route order is guaranteed)
const hoverCardStickersDirEarly = path.join(uploadsDir, 'hover-card-stickers');
const hoverCardStickersFileEarly = path.join(__dirname, 'hover-card-stickers.json');
try {
  if (!fs.existsSync(hoverCardStickersDirEarly)) fs.mkdirSync(hoverCardStickersDirEarly, { recursive: true });
  if (!fs.existsSync(hoverCardStickersFileEarly)) fs.writeFileSync(hoverCardStickersFileEarly, '[]', 'utf8');
} catch (e) {}
const stickerUploadStorageEarly = multer.diskStorage({
  destination: (req, file, cb) => cb(null, hoverCardStickersDirEarly),
  filename: (req, file, cb) => cb(null, Date.now() + (path.extname(file.originalname) || '.png'))
});
const stickerUploadMulterEarly = multer({
  storage: stickerUploadStorageEarly,
  fileFilter: (req, file, cb) => {
    const mt = (file.mimetype || '').toLowerCase();
    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    cb(null, /^image\//.test(mt) || ['.png', '.gif', '.jpg', '.jpeg', '.webp'].includes(ext));
  }
});
const stickerReplaceMulterEarly = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const mt = (file.mimetype || '').toLowerCase();
    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    cb(null, /^image\//.test(mt) || ['.png', '.gif', '.jpg', '.jpeg', '.webp'].includes(ext));
  }
});

// Sticker API routes (registered before static so they always match)
app.get('/api/hover-card-stickers', (req, res) => {
  try {
    const list = (function load() {
      try {
        if (fs.existsSync(hoverCardStickersFileEarly)) return JSON.parse(fs.readFileSync(hoverCardStickersFileEarly, 'utf8'));
      } catch (e) {}
      return [];
    })();
    const baseUrl = '/Uploads/hover-card-stickers/';
    let out = (Array.isArray(list) ? list : []).map(s => ({
      id: s.id || s.filename,
      filename: s.filename || s.id,
      url: baseUrl + (s.filename || s.id),
      tags: Array.isArray(s.tags) ? s.tags : []
    }));
    const search = (req.query.search || '').trim().toLowerCase();
    if (search) {
      out = out.filter(s => {
        const id = (s.id || '').toLowerCase();
        const filename = (s.filename || '').toLowerCase();
        const tagStr = (s.tags || []).join(' ').toLowerCase();
        return id.includes(search) || filename.includes(search) || tagStr.includes(search);
      });
    }
    res.json(out);
  } catch (e) {
    console.error('GET hover-card-stickers:', e);
    res.status(500).json({ error: 'Failed to load stickers' });
  }
});

app.patch('/api/hover-card-stickers/:id', requireLogin, (req, res) => {
  try {
    const userId = req.session && req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator')) {
      return res.status(403).json({ error: 'Admin or moderator required' });
    }
    const id = (req.params.id || '').replace(/\.\./g, '');
    if (!id) return res.status(400).json({ error: 'Sticker id required' });
    let list = [];
    try {
      if (fs.existsSync(hoverCardStickersFileEarly)) list = JSON.parse(fs.readFileSync(hoverCardStickersFileEarly, 'utf8'));
      if (!Array.isArray(list)) list = [];
    } catch (e) {}
    const idx = list.findIndex(s => (s.id || s.filename) === id);
    if (idx === -1) return res.status(404).json({ error: 'Sticker not found' });
    const tags = req.body && req.body.tags;
    const tagArray = Array.isArray(tags)
      ? tags.map(t => String(t).trim()).filter(Boolean)
      : (typeof tags === 'string' ? tags.split(/[\s,]+/).map(t => t.trim()).filter(Boolean) : []);
    list[idx] = { ...list[idx], tags: tagArray };
    fs.writeFileSync(hoverCardStickersFileEarly, JSON.stringify(list, null, 2), 'utf8');
    res.json({ id: list[idx].id || list[idx].filename, tags: list[idx].tags });
  } catch (e) {
    console.error('PATCH hover-card-stickers:', e);
    res.status(500).json({ error: 'Failed to update sticker' });
  }
});

app.put('/api/hover-card-stickers/:id/replace-image', requireLogin, stickerReplaceMulterEarly.single('sticker'), (req, res) => {
  try {
    const userId = req.session && req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator')) {
      return res.status(403).json({ error: 'Admin or moderator required to replace sticker image' });
    }
    const rawId = req.params.id;
    const id = (typeof rawId === 'string' ? decodeURIComponent(rawId) : '').replace(/\.\./g, '').replace(/[/\\]/g, '');
    if (!id) return res.status(400).json({ error: 'Sticker id required' });
    let list = [];
    try {
      if (fs.existsSync(hoverCardStickersFileEarly)) list = JSON.parse(fs.readFileSync(hoverCardStickersFileEarly, 'utf8'));
      if (!Array.isArray(list)) list = [];
    } catch (e) {}
    if (!list.some(s => (s.id || s.filename) === id)) {
      return res.status(404).json({ error: 'Sticker not found' });
    }
    if (!req.file || !req.file.buffer) {
      return res.status(400).json({ error: 'No image file uploaded. Use PNG, GIF, JPG, or WebP.' });
    }
    const filePath = path.join(hoverCardStickersDirEarly, id);
    fs.writeFileSync(filePath, req.file.buffer);
    res.json({ id, url: '/Uploads/hover-card-stickers/' + encodeURIComponent(id) });
  } catch (e) {
    console.error('PUT hover-card-stickers replace-image:', e);
    res.status(500).json({ error: 'Failed to replace sticker image: ' + (e.message || 'server error') });
  }
});

app.post('/api/hover-card-stickers/upload', requireLogin, stickerUploadMulterEarly.single('sticker'), (req, res) => {
  try {
    const userId = req.session && req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator')) {
      return res.status(403).json({ error: 'Admin or moderator required to upload stickers' });
    }
    if (!req.file || !req.file.filename) {
      return res.status(400).json({ error: 'No sticker file uploaded. Use PNG, GIF, JPG, or WebP.' });
    }
    const filename = req.file.filename;
    let list = [];
    try {
      if (fs.existsSync(hoverCardStickersFileEarly)) list = JSON.parse(fs.readFileSync(hoverCardStickersFileEarly, 'utf8'));
      if (!Array.isArray(list)) list = [];
    } catch (e) {}
    if (list.some(s => (s.id || s.filename) === filename)) {
      return res.status(400).json({ error: 'Sticker with this id already exists' });
    }
    list.push({ id: filename, filename });
    fs.writeFileSync(hoverCardStickersFileEarly, JSON.stringify(list, null, 2), 'utf8');
    res.json({ id: filename, filename, url: '/Uploads/hover-card-stickers/' + filename });
  } catch (e) {
    console.error('POST hover-card-stickers/upload:', e);
    res.status(500).json({ error: 'Failed to upload sticker: ' + (e.message || 'server error') });
  }
});

// Middleware to require login for protected routes (redirect to login when not logged in)
// For /api/* requests, return 401 JSON so fetch() gets JSON instead of HTML redirect
function requireLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    res.redirect('/login');
  }
}

// Page routes that require login (before static so they are matched first)
app.get('/create', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
});
app.get('/projects', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'projects.html'));
});
app.get('/wardrobe.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wardrobe.html'));
});
app.get('/store.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'store.html'));
});
app.get('/messages.html', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'messages.html'));
});
app.get('/profile-edit', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile-edit.html'));
});
app.get('/profile-saved-outfits', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile-saved-outfits.html'));
});
app.get('/profile-saved-outfits.html', (req, res) => {
  res.redirect(302, '/profile-saved-outfits');
});

// item-debug: serve at /item-debug-page (auth done inside handler so route always matches)
const itemDebugPath = path.resolve(__dirname, 'public', 'item-debug.html');
const itemDebugNoCache = (res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
};
app.get('/item-debug-ping', function (req, res) { res.type('text').send('item-debug routes loaded'); });
app.get('/item-debug-ok', function (req, res) {
  let n = 0;
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    n = list.length;
  } catch (_) {}
  res.set('Content-Type', 'text/plain; charset=utf-8').send('OK\nItems: ' + n);
});
app.get('/item-debug-test', function (req, res) {
  if (!req.session || !req.session.user) return res.redirect('/');
  if (!canSeeItemDebug(req.session.userId)) {
    res.status(403).set('Content-Type', 'text/html; charset=utf-8').send('<!DOCTYPE html><html><body><h1>403</h1><p>Need admin/moderator/designer.</p><a href="/home">Home</a></body></html>');
    return;
  }
  let count = 0;
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    count = list.length;
  } catch (_) {}
  itemDebugNoCache(res);
  res.set('Content-Type', 'text/html; charset=utf-8').send(
    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Item Debug Test</title></head><body style="font-family:sans-serif;padding:2rem;background:#1a1a2e;color:#eee;min-height:100vh;">' +
    '<h1 style="color:#22c55e;">Item Debug Test</h1>' +
    '<p>If you see this page, the server and auth work.</p>' +
    '<p id="count">Items in database: ' + count + '</p>' +
    '<p><a href="/item-debug-page" style="color:#7dd3fc;">Open full Item Debug</a></p>' +
    '</body></html>'
  );
});

app.get('/item-debug-list', function (req, res) {
  if (!req.session || !req.session.user) return res.redirect('/');
  if (!canSeeItemDebug(req.session.userId)) {
    res.status(403).set('Content-Type', 'text/html; charset=utf-8').send('<!DOCTYPE html><html><body><h1>403</h1><p>Need admin/moderator/designer.</p><a href="/home">Home</a></body></html>');
    return;
  }
  itemDebugNoCache(res);
  let list = [];
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
  } catch (_) {}
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  let rows = '';
  list.forEach(function (it) {
    const id = esc(it.id || it.filename || '');
    const designer = esc(it.designer || '');
    const fn = esc(it.filename || '');
    rows += '<tr><td>' + id + '</td><td>' + designer + '</td><td>' + fn + '</td></tr>';
  });
  const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Items (' + list.length + ')</title></head><body style="font-family:sans-serif;padding:20px;background:#fff;color:#111;margin:0;">' +
    '<div style="background:#22c55e;color:#fff;padding:20px;margin:-20px -20px 20px -20px;">' +
    '<h1 style="margin:0;font-size:1.8rem;">ITEM DEBUG LIST</h1>' +
    '<p style="margin:10px 0 0 0;font-size:1.2rem;">' + list.length + ' items in table below.</p>' +
    '<p style="margin:8px 0 0 0;"><a href="/item-debug-page" style="color:#fff;text-decoration:underline;">Open full Item Debug page</a></p>' +
    '</div>' +
    '<table style="border-collapse:collapse;width:100%;">' +
    '<thead><tr style="background:#333;color:#fff;"><th style="padding:8px;text-align:left;">ID</th><th style="padding:8px;">Designer</th><th style="padding:8px;">Filename</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table></body></html>';
  res.set('Content-Type', 'text/html; charset=utf-8').send(html);
});
app.get('/item-debug-page', function (req, res) {
  if (!req.session || !req.session.user) return res.redirect('/');
  if (!canSeeItemDebug(req.session.userId)) {
    res.status(403);
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.send('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Access denied</title></head><body style="font-family:sans-serif;padding:2rem;max-width:480px;margin:2rem auto;"><h1>Access denied</h1><p>Item Debug requires an <strong>admin</strong>, <strong>moderator</strong>, or <strong>designer</strong> role.</p><p><a href="/home">Back to home</a></p></body></html>');
  }
  itemDebugNoCache(res);
  try {
    let html = fs.readFileSync(itemDebugPath, 'utf8');
    const version = 'Item Debug · ' + Date.now();
    const marker = '<div id="item-debug-server-marker" style="position:fixed;top:80px;right:10px;z-index:9999;background:#22c55e;color:#fff;padding:6px 10px;border-radius:6px;font-size:11px;" title="Page read from disk on this request">' + version + '</div>\n';
    let list = [];
    try {
      const raw = fs.readFileSync(itemsFile, 'utf8');
      const data = JSON.parse(raw);
      list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    } catch (_) {}
    function esc(s) {
      if (s == null) return '';
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
    let tbodyRows = '';
    list.forEach(function (it) {
      const id = esc(it.id || it.filename || '');
      const designer = esc(it.designer || '');
      const text = designer ? id + ' · ' + designer : id;
      tbodyRows += '<tr data-filename="' + esc(it.filename || '') + '"><td colspan="15" style="padding:8px;">' + text + '</td></tr>';
    });
    html = html.replace(/<tbody\s+id="items-tbody"\s*>\s*<\/tbody>/, '<tbody id="items-tbody">' + tbodyRows + '</tbody>');
    console.log('[item-debug] served page with ' + list.length + ' items');
    var emptyPara = '<p id="empty" class="empty" style="display:block;">Loading…</p>';
    if (list.length > 0) {
      html = html.replace(emptyPara, '<p id="empty" class="empty" style="display:none;">No items yet.</p>');
    } else {
      html = html.replace(emptyPara, '<p id="empty" class="empty" style="display:block;">No items yet. Upload items using the Upload item button.</p>');
    }
    const json = JSON.stringify(list).replace(/<\/script/gi, '<\\/script');
    const itemsScript = '<script>window.__ITEM_DEBUG_INITIAL_ITEMS__=' + json + ';</script>\n';
    const banner = '<div style="background:#1e3a5f;color:#fff;padding:10px 16px;margin:0 0 16px 0;border-radius:8px;"><strong>' + list.length + ' items</strong> loaded. If the table below is empty, open <a href="/item-debug-list" style="color:#7dd3fc;">/item-debug-list</a> to see the list.</div>\n';
    html = html.replace(/<body[^>]*>/, '$&' + marker + itemsScript + banner);
    res.send(html);
  } catch (e) {
    console.error('[item-debug] error:', e.message);
    res.status(500).send('Error: ' + e.message);
  }
});
app.get('/item-debug.html', function (req, res) {
  if (!req.session || !req.session.user) return res.redirect('/');
  if (!canSeeItemDebug(req.session.userId)) return res.status(403).send('Access denied.');
  itemDebugNoCache(res);
  res.redirect(302, '/item-debug-page');
});
app.get('/item-debug', function (req, res) {
  if (!req.session || !req.session.user) return res.redirect('/');
  if (!canSeeItemDebug(req.session.userId)) return res.status(403).send('Access denied.');
  itemDebugNoCache(res);
  res.redirect(302, '/item-debug-page');
});

// Adjust page: before static so it always gets no-cache and correct file
const adjustNoCache = (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'adjust.html'));
};
app.get('/adjust', adjustNoCache);
app.get('/adjust.html', adjustNoCache);

// Page routes BEFORE static so /login, /, etc. are always matched first
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/create-account', (req, res) => {
  if (req.session.user) return res.redirect('/home');
  res.sendFile(path.join(__dirname, 'public', 'create-account.html'));
});

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
  lastModified: true
}));

// Routes (API and redirects)
app.get('/api/health', (req, res) => {
  res.status(200).json({ ok: true });
});

function passwordMatches(stored, plain) {
  if (!stored || !plain) return false;
  if (stored.startsWith('$2')) return bcrypt.compareSync(plain, stored);
  return stored === plain;
}

app.post('/login', checkAuthRateLimit, (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password;
  if (!username || !password) {
    return res.redirect('/login?error=missing');
  }
  if (username.length > USERNAME_MAX || (typeof password === 'string' && password.length > PASSWORD_MAX)) {
    return res.redirect('/login?error=invalid');
  }
  const users = getUsersForAuth();
  const user = users.find(u => (u.username || '').toLowerCase() === username.toLowerCase() && passwordMatches(u.password, password));
  if (user) {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    authRateLimit.delete(ip);
    req.session.user = user.username;
    req.session.userId = user.id;
    res.redirect('/home');
  } else {
    res.redirect('/login?error=invalid');
  }
});

app.post('/register', checkAuthRateLimit, (req, res) => {
  const { username, password, confirm } = req.body;
  const trimmed = (username || '').trim();
  if (!trimmed || !password) {
    return res.redirect('/create-account?error=missing');
  }
  if (password !== confirm) {
    return res.redirect('/create-account?error=nomatch');
  }
  if (trimmed.length < USERNAME_MIN || trimmed.length > USERNAME_MAX) {
    return res.redirect('/create-account?error=username-length');
  }
  if (!USERNAME_REGEX.test(trimmed)) {
    return res.redirect('/create-account?error=username-chars');
  }
  if (password.length < PASSWORD_MIN) {
    return res.redirect('/create-account?error=password-length');
  }
  if (password.length > PASSWORD_MAX) {
    return res.redirect('/create-account?error=password-long');
  }
  const allUsers = getUsersForAuth();
  if (allUsers.some(u => (u.username || '').toLowerCase() === trimmed.toLowerCase())) {
    return res.redirect('/create-account?error=taken');
  }
  const hash = bcrypt.hashSync(password, 10);
  let newId;
  withLock('users', () => {
    const users = loadUsers();
    newId = nextUserId();
    users.push({ id: newId, username: trimmed, password: hash });
    saveUsers(users);
  });
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  authRateLimit.delete(ip);
  req.session.user = trimmed;
  req.session.userId = newId;
  res.redirect('/home');
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/home');
    }
    res.redirect('/');
  });
});

app.get('/api/me', (req, res) => {
  const userId = req.session.userId != null ? req.session.userId : null;
  res.json({
    user: req.session.user || null,
    userId,
    roles: getRoles(userId)
  });
});

app.get('/api/users/search', (req, res) => {
  try {
    const q = (req.query.q || '').trim().toLowerCase();
    if (!q) return res.json([]);
    const all = getUsersForAuth();
    const matches = all
      .filter(u => u && (u.username || '').toLowerCase().indexOf(q) !== -1)
      .map(u => ({ id: u.id, username: u.username }));
    res.json(matches);
  } catch (e) {
    res.json([]);
  }
});

app.get('/api/users/online', (req, res) => {
  try {
    const excludeUserId = req.session && req.session.userId != null ? req.session.userId : null;
    const list = getOnlineUsers(excludeUserId);
    res.json({ users: list });
  } catch (e) {
    res.json({ users: [] });
  }
});

/** List all users (id, username) for logged-in users. Used by users page. */
app.get('/api/users/list', (req, res) => {
  try {
    if (req.session.userId == null) return res.status(401).json({ error: 'Not logged in' });
    const users = getUsersForAuth();
    const list = users.map(u => ({ id: u.id, username: u.username || '' }));
    res.json(list);
  } catch (e) {
    res.json([]);
  }
});

app.get('/api/profile', (req, res) => {
  try {
    const userId = req.session.userId;
    const username = req.session.user || null;
    if (userId == null || !username) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    ensureUserInventory(req);
    const profile = getOrCreateProfile(userId);
    const purchased = req.session.purchased || [];
    res.json({
      userId,
      username,
      currency: req.session.currency,
      currency2: req.session.currency2 != null ? req.session.currency2 : 0,
      currency3: req.session.currency3 != null ? req.session.currency3 : 0,
      purchasedCount: purchased.length,
      profilePictureUrl: profile.profilePictureUrl || null,
      bio: profile.bio != null ? profile.bio : '',
      displayName: profile.displayName != null ? String(profile.displayName).slice(0, 50) : '',
      accentColor: profile.accentColor != null ? String(profile.accentColor).slice(0, 20) : '',
      profilePageHtml: profile.profilePageHtml != null ? String(profile.profilePageHtml) : ''
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.get('/home', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

function loadDashboardSlides() {
  try {
    if (fs.existsSync(dashboardSlidesFile)) {
      const data = fs.readFileSync(dashboardSlidesFile, 'utf8');
      const list = JSON.parse(data);
      return Array.isArray(list) ? list : [];
    }
  } catch (e) {
    console.error('loadDashboardSlides failed:', e.message || e);
  }
  return [];
}

function saveDashboardSlides(slides) {
  writeAtomic(dashboardSlidesFile, JSON.stringify(Array.isArray(slides) ? slides : [], null, 2));
}

app.get('/api/dashboard/slides', (req, res) => {
  try {
    const slides = loadDashboardSlides();
    if (slides.length === 0) {
      const defaultSlides = [
        { id: '1', title: 'Home Dashboard', text: 'Welcome back! Explore your options.', imageUrl: '' },
        { id: '2', title: 'News Update', text: 'New wardrobe items available today!', imageUrl: '' },
        { id: '3', title: 'Special Offer', text: 'Get 20% off on select items this week!', imageUrl: '' }
      ];
      return res.json(defaultSlides);
    }
    res.json(slides);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load slides' });
  }
});

app.put('/api/dashboard/slides', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canEditDashboard(userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const slides = req.body.slides;
    if (!Array.isArray(slides)) return res.status(400).json({ error: 'slides must be an array' });
    const sanitized = slides.map((s, i) => {
      const images = Array.isArray(s.images) ? s.images.slice(0, 50).map(img => ({
        url: String((img && img.url) || '').slice(0, 500),
        x: typeof (img && img.x) === 'number' ? img.x : (typeof (img && img.x) === 'string' ? parseFloat(img.x) : 0),
        y: typeof (img && img.y) === 'number' ? img.y : (typeof (img && img.y) === 'string' ? parseFloat(img.y) : 0),
        w: typeof (img && img.w) === 'number' ? img.w : (typeof (img && img.w) === 'string' ? parseFloat(img.w) : 120),
        h: typeof (img && img.h) === 'number' ? img.h : (typeof (img && img.h) === 'string' ? parseFloat(img.h) : 120),
        visible: (img && img.visible) === false ? false : true
      })) : [];
      const videos = Array.isArray(s.videos) ? s.videos.slice(0, 10).map(v => ({
        url: String((v && v.url) || '').slice(0, 500),
        x: typeof (v && v.x) === 'number' ? v.x : (typeof (v && v.x) === 'string' ? parseFloat(v.x) : 20),
        y: typeof (v && v.y) === 'number' ? v.y : (typeof (v && v.y) === 'string' ? parseFloat(v.y) : 80),
        w: typeof (v && v.w) === 'number' ? v.w : (typeof (v && v.w) === 'string' ? parseFloat(v.w) : 200),
        h: typeof (v && v.h) === 'number' ? v.h : (typeof (v && v.h) === 'string' ? parseFloat(v.h) : 112),
        visible: (v && v.visible) === false ? false : true
      })) : [];
      const titleStrForCompare = String(s.title || '').trim();
      let texts = Array.isArray(s.texts) ? s.texts.slice(0, 20).map(t => {
        let content = String((t && t.content) != null ? t.content : '').slice(0, 2000);
        if (content.trim() === titleStrForCompare) content = '';
        let fontSize = typeof (t && t.fontSize) === 'number' ? t.fontSize : (typeof (t && t.fontSize) === 'string' ? parseInt(t.fontSize, 10) : 16);
        fontSize = Math.max(10, Math.min(72, isNaN(fontSize) ? 16 : fontSize));
        const fontWeight = (t && t.fontWeight) === 'bold' ? 'bold' : '';
        const fontStyle = (t && t.fontStyle) === 'italic' ? 'italic' : '';
        let color = (t && t.color != null) ? String(t.color).trim() : '';
        if (color && color.length > 50) color = color.slice(0, 50);
        return {
          content,
          x: typeof (t && t.x) === 'number' ? t.x : (typeof (t && t.x) === 'string' ? parseFloat(t.x) : 20),
          y: typeof (t && t.y) === 'number' ? t.y : (typeof (t && t.y) === 'string' ? parseFloat(t.y) : 60),
          fontSize,
          fontWeight,
          fontStyle,
          color: color || undefined,
          visible: (t && t.visible) === false ? false : true
        };
      }) : [];
      texts = texts.filter(t => (t.content || '').trim() !== '');
      const linkUrl = String(s.linkUrl || s.link || '').trim().slice(0, 500);
      let bodyText = texts.length > 0 ? String(texts[0].content || '').slice(0, 2000) : String(s.text || '').slice(0, 2000);
      if (bodyText.trim() === titleStrForCompare) bodyText = '';
      const out = {
        id: String(s.id || (i + 1)),
        title: String(s.title || '').slice(0, 200),
        text: bodyText,
        imageUrl: String(s.imageUrl || '').slice(0, 500),
        backgroundUrl: String(s.backgroundUrl || '').slice(0, 500),
        linkUrl: linkUrl || undefined,
        titleX: typeof s.titleX === 'number' ? s.titleX : (typeof s.titleX === 'string' ? parseFloat(s.titleX) : 20),
        titleY: typeof s.titleY === 'number' ? s.titleY : (typeof s.titleY === 'string' ? parseFloat(s.titleY) : 20),
        textX: typeof s.textX === 'number' ? s.textX : (typeof s.textX === 'string' ? parseFloat(s.textX) : 20),
        textY: typeof s.textY === 'number' ? s.textY : (typeof s.textY === 'string' ? parseFloat(s.textY) : 60),
        images,
        videos
      };
      if (texts.length > 0) out.texts = texts;
      if (s.fontFamily) out.fontFamily = String(s.fontFamily).slice(0, 100);
      if (typeof s.durationMs === 'number' && s.durationMs >= 1000) out.durationMs = Math.min(60000, s.durationMs);
      if (Array.isArray(s.layerOrder) && s.layerOrder.length > 0 && s.layerOrder.length <= 100) {
        const allowed = /^(background|title|text-\d+|image-\d+|video-\d+)$/;
        out.layerOrder = s.layerOrder.filter(x => typeof x === 'string' && allowed.test(x)).slice(0, 100);
        if (out.layerOrder.length === 0) delete out.layerOrder;
      }
      return out;
    });
    withLock('dashboardSlides', () => saveDashboardSlides(sanitized));
    res.json({ success: true, slides: sanitized });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save slides' });
  }
});

const dashboardUploadDir = path.join(__dirname, 'Uploads', 'dashboard');
try { if (!fs.existsSync(dashboardUploadDir)) fs.mkdirSync(dashboardUploadDir, { recursive: true }); } catch (e) { /* ignore */ }
const dashboardImageMimes = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
const dashboardVideoMimes = ['video/mp4', 'video/webm', 'video/ogg'];
const dashboardMediaMimes = [...dashboardImageMimes, ...dashboardVideoMimes];
const dashboardUploadStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, dashboardUploadDir),
  filename: (req, file, cb) => cb(null, 'slide-' + Date.now() + (path.extname(file.originalname) || '.png'))
});
const dashboardUploadMulter = multer({
  storage: dashboardUploadStorage,
  fileFilter: (req, file, cb) => cb(null, dashboardMediaMimes.includes(file.mimetype))
});
app.post('/api/dashboard/upload', requireLogin, dashboardUploadMulter.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image file' });
    res.json({ url: '/Uploads/dashboard/' + path.basename(req.file.path) });
  } catch (e) {
    res.status(500).json({ error: 'Failed to upload' });
  }
});

// Slide gallery: upload and list images/videos for use in dashboard slides (admin/moderator only)
const slideGalleryDir = path.join(__dirname, 'Uploads', 'slide-gallery');
const slideGalleryMetaFile = path.join(__dirname, 'slide-gallery-meta.json');
const slideGalleryMediaMimes = [...dashboardImageMimes, ...dashboardVideoMimes];
function loadSlideGalleryMeta() {
  try {
    if (!fs.existsSync(slideGalleryMetaFile)) return {};
    const raw = fs.readFileSync(slideGalleryMetaFile, 'utf8');
    const data = JSON.parse(raw);
    return typeof data === 'object' && data !== null ? data : {};
  } catch (e) { return {}; }
}
function saveSlideGalleryMeta(meta) {
  fs.writeFileSync(slideGalleryMetaFile, JSON.stringify(meta, null, 2), 'utf8');
}
try { if (!fs.existsSync(slideGalleryDir)) fs.mkdirSync(slideGalleryDir, { recursive: true }); } catch (e) { /* ignore */ }
const slideGalleryStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, slideGalleryDir),
  filename: (req, file, cb) => cb(null, 'gallery-' + Date.now() + (path.extname(file.originalname) || '.png'))
});
const slideGalleryMulter = multer({
  storage: slideGalleryStorage,
  fileFilter: (req, file, cb) => cb(null, slideGalleryMediaMimes.includes(file.mimetype))
});
app.post('/api/slide-gallery/upload', requireLogin, (req, res, next) => {
  if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
  next();
}, slideGalleryMulter.single('image'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image or video file' });
    const name = path.basename(req.file.path);
    const tagsRaw = (req.body && req.body.tags) ? String(req.body.tags).trim() : '';
    const tags = tagsRaw ? tagsRaw.split(/\s*,\s*/).map(t => t.trim()).filter(Boolean) : [];
    if (tags.length > 0) {
      const meta = loadSlideGalleryMeta();
      meta[name] = { tags };
      saveSlideGalleryMeta(meta);
    }
    res.json({ url: '/Uploads/slide-gallery/' + name, name, tags });
  } catch (e) {
    res.status(500).json({ error: 'Failed to upload' });
  }
});
app.get('/api/slide-gallery', requireLogin, (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    if (!fs.existsSync(slideGalleryDir)) return res.json({ images: [] });
    const meta = loadSlideGalleryMeta();
    const filterTag = (req.query && req.query.tag) ? String(req.query.tag).trim().toLowerCase() : '';
    const names = fs.readdirSync(slideGalleryDir).filter(f => {
      const p = path.join(slideGalleryDir, f);
      return fs.statSync(p).isFile() && /\.(png|jpe?g|gif|webp|mp4|webm|og[gv])$/i.test(f);
    });
    names.sort((a, b) => (fs.statSync(path.join(slideGalleryDir, b)).mtimeMs || 0) - (fs.statSync(path.join(slideGalleryDir, a)).mtimeMs || 0));
    let images = names.map(name => {
      const entry = meta[name];
      const tags = Array.isArray(entry && entry.tags) ? entry.tags : [];
      const isVideo = /\.(mp4|webm|og[gv])$/i.test(name);
      return { url: '/Uploads/slide-gallery/' + name, name, tags, type: isVideo ? 'video' : 'image' };
    });
    if (filterTag) {
      images = images.filter(img => (img.tags || []).some(t => String(t).toLowerCase() === filterTag));
    }
    res.json({ images });
  } catch (e) {
    res.status(500).json({ error: 'Failed to list gallery' });
  }
});
app.patch('/api/slide-gallery/:name', requireLogin, (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const name = (req.params.name || '').replace(/\.\./g, '').replace(/[/\\]/g, '');
    if (!name || !/^gallery-[a-z0-9.-]+$/i.test(name)) return res.status(400).json({ error: 'Invalid filename' });
    const filePath = path.join(slideGalleryDir, name);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
    const tagsRaw = (req.body && req.body.tags) != null ? (Array.isArray(req.body.tags) ? req.body.tags.join(',') : String(req.body.tags)) : '';
    const tags = tagsRaw ? String(tagsRaw).split(/\s*,\s*/).map(t => t.trim()).filter(Boolean) : [];
    const meta = loadSlideGalleryMeta();
    meta[name] = { tags };
    saveSlideGalleryMeta(meta);
    res.json({ name, tags });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update tags' });
  }
});
app.delete('/api/slide-gallery/:name', requireLogin, (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const name = (req.params.name || '').replace(/\.\./g, '').replace(/[/\\]/g, '');
    if (!name || !/^gallery-[a-z0-9.-]+$/i.test(name)) return res.status(400).json({ error: 'Invalid filename' });
    const filePath = path.join(slideGalleryDir, name);
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
    fs.unlinkSync(filePath);
    const meta = loadSlideGalleryMeta();
    if (meta[name]) { delete meta[name]; saveSlideGalleryMeta(meta); }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete' });
  }
});

const dashboardSlideSubmissionsFile = path.join(__dirname, 'dashboardSlideSubmissions.json');
function loadDashboardSlideSubmissions() {
  try {
    if (fs.existsSync(dashboardSlideSubmissionsFile)) {
      const data = fs.readFileSync(dashboardSlideSubmissionsFile, 'utf8');
      const list = JSON.parse(data);
      return Array.isArray(list) ? list : [];
    }
  } catch (e) {
    console.error('loadDashboardSlideSubmissions failed:', e.message || e);
  }
  return [];
}
function saveDashboardSlideSubmissions(list) {
  fs.writeFileSync(dashboardSlideSubmissionsFile, JSON.stringify(Array.isArray(list) ? list : [], null, 2));
}
function sanitizeOneSlide(s, id) {
  const images = Array.isArray(s.images) ? s.images.slice(0, 50).map(img => ({
    url: String((img && img.url) || '').slice(0, 500),
    x: typeof (img && img.x) === 'number' ? img.x : (typeof (img && img.x) === 'string' ? parseFloat(img.x) : 0),
    y: typeof (img && img.y) === 'number' ? img.y : (typeof (img && img.y) === 'string' ? parseFloat(img.y) : 0),
    visible: (img && img.visible) === false ? false : true
  })) : [];
  const videos = Array.isArray(s.videos) ? s.videos.slice(0, 10).map(v => ({
    url: String((v && v.url) || '').slice(0, 500),
    x: typeof (v && v.x) === 'number' ? v.x : (typeof (v && v.x) === 'string' ? parseFloat(v.x) : 20),
    y: typeof (v && v.y) === 'number' ? v.y : (typeof (v && v.y) === 'string' ? parseFloat(v.y) : 80),
    w: typeof (v && v.w) === 'number' ? v.w : (typeof (v && v.w) === 'string' ? parseFloat(v.w) : 200),
    h: typeof (v && v.h) === 'number' ? v.h : (typeof (v && v.h) === 'string' ? parseFloat(v.h) : 112),
    visible: (v && v.visible) === false ? false : true
  })) : [];
  const titleStrForCompare = String(s.title || '').trim();
  let texts = Array.isArray(s.texts) ? s.texts.slice(0, 20).map(t => {
    let content = String((t && t.content) != null ? t.content : '').slice(0, 2000);
    if (content.trim() === titleStrForCompare) content = '';
    return {
      content,
      x: typeof (t && t.x) === 'number' ? t.x : (typeof (t && t.x) === 'string' ? parseFloat(t.x) : 20),
      y: typeof (t && t.y) === 'number' ? t.y : (typeof (t && t.y) === 'string' ? parseFloat(t.y) : 60),
      visible: (t && t.visible) === false ? false : true
    };
  }) : [];
  texts = texts.filter(t => (t.content || '').trim() !== '');
  const linkUrl = String(s.linkUrl || s.link || '').trim().slice(0, 500);
  let bodyText = texts.length > 0 ? String(texts[0].content || '').slice(0, 2000) : String(s.text || '').slice(0, 2000);
  if (bodyText.trim() === titleStrForCompare) bodyText = '';
  const out = {
    id: String(id || s.id || '1'),
    title: String(s.title || '').slice(0, 200),
    text: bodyText,
    imageUrl: String(s.imageUrl || '').slice(0, 500),
    backgroundUrl: String(s.backgroundUrl || '').slice(0, 500),
    linkUrl: linkUrl || undefined,
    titleX: typeof s.titleX === 'number' ? s.titleX : (typeof s.titleX === 'string' ? parseFloat(s.titleX) : 20),
    titleY: typeof s.titleY === 'number' ? s.titleY : (typeof s.titleY === 'string' ? parseFloat(s.titleY) : 20),
    textX: typeof s.textX === 'number' ? s.textX : (typeof s.textX === 'string' ? parseFloat(s.textX) : 20),
    textY: typeof s.textY === 'number' ? s.textY : (typeof s.textY === 'string' ? parseFloat(s.textY) : 60),
    images,
    videos,
    durationMs: typeof s.durationMs === 'number' && s.durationMs >= 1000 ? Math.min(60000, s.durationMs) : 3000
  };
  if (texts.length > 0) out.texts = texts;
  if (s.fontFamily) out.fontFamily = String(s.fontFamily).slice(0, 100);
  if (Array.isArray(s.layerOrder) && s.layerOrder.length > 0 && s.layerOrder.length <= 100) {
    const allowed = /^(background|title|text-\d+|image-\d+|video-\d+)$/;
    out.layerOrder = s.layerOrder.filter(x => typeof x === 'string' && allowed.test(x)).slice(0, 100);
    if (out.layerOrder.length === 0) delete out.layerOrder;
  }
  return out;
}

app.post('/api/dashboard/slides/submit', requireLogin, (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const s = req.body && req.body.slide;
    if (!s || typeof s !== 'object') return res.status(400).json({ error: 'Slide object required' });
    const submissions = loadDashboardSlideSubmissions();
    const submissionId = 'sub-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9);
    const slide = sanitizeOneSlide(s, submissionId);
    const username = (req.session.username || req.session.email || 'User') + '';
    submissions.push({
      id: submissionId,
      userId,
      username: username.slice(0, 100),
      createdAt: new Date().toISOString(),
      status: 'pending',
      slide
    });
    saveDashboardSlideSubmissions(submissions);
    res.json({ success: true, submissionId });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to submit slide' });
  }
});

app.get('/api/dashboard/slides/submissions', (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const list = loadDashboardSlideSubmissions();
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: 'Failed to load submissions' });
  }
});

app.post('/api/dashboard/slides/submissions/:id/approve', (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const id = (req.params && req.params.id) || '';
    let approvedSlide;
    withLock('dashboardSlides', () => {
      const submissions = loadDashboardSlideSubmissions();
      const idx = submissions.findIndex(x => x.id === id && x.status === 'pending');
      if (idx === -1) throw new Error('Submission not found');
      const submission = submissions[idx];
      const slides = loadDashboardSlides();
      const newId = slides.length ? String(Math.max(...slides.map(s => parseInt(s.id, 10) || 0)) + 1) : '1';
      approvedSlide = { ...submission.slide, id: newId };
      slides.push(approvedSlide);
      saveDashboardSlides(slides);
      submissions.splice(idx, 1);
      saveDashboardSlideSubmissions(submissions);
    });
    res.json({ success: true, slide: approvedSlide });
  } catch (e) {
    if (e.message === 'Submission not found') return res.status(404).json({ error: 'Submission not found' });
    res.status(500).json({ error: e.message || 'Failed to approve' });
  }
});

app.post('/api/dashboard/slides/submissions/:id/reject', (req, res) => {
  try {
    if (!canEditDashboard(req.session.userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const id = (req.params && req.params.id) || '';
    const submissions = loadDashboardSlideSubmissions();
    const idx = submissions.findIndex(x => x.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Submission not found' });
    submissions.splice(idx, 1);
    saveDashboardSlideSubmissions(submissions);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed to reject' });
  }
});

app.put('/api/profile', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const { bio, displayName, accentColor, profilePageHtml } = req.body;
    const key = String(userId);
    withLock('profiles', () => {
      const profiles = loadProfiles();
      if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', displayName: '', accentColor: '' };
      if (typeof bio === 'string') profiles[key].bio = bio;
      if (typeof displayName === 'string') profiles[key].displayName = displayName.slice(0, 50).trim();
      if (typeof accentColor === 'string') {
        const trimmed = accentColor.trim().slice(0, 20);
        if (/^#[0-9A-Fa-f]{3,6}$/.test(trimmed) || trimmed === '') profiles[key].accentColor = trimmed;
      }
      if (typeof profilePageHtml === 'string') profiles[key].profilePageHtml = sanitizeProfilePageHtml(profilePageHtml);
      saveProfiles(profiles);
      res.json({ success: true, bio: profiles[key].bio, displayName: profiles[key].displayName || '', accentColor: profiles[key].accentColor || '', profilePageHtml: profiles[key].profilePageHtml || '' });
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/** Forum post customization (members only): GET current settings, PUT save settings. */
const FORUM_NAME_FONTS = ['Arial', 'Georgia', 'Times New Roman', 'Verdana', 'Courier New', 'Comic Sans MS', 'Trebuchet MS', 'Impact', 'Lucida Sans', 'Palatino'];

app.get('/api/forum-post-customization', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const profile = getOrCreateProfile(userId);
    res.json({
      forumPostHeader: typeof profile.forumPostHeader === 'string' ? profile.forumPostHeader : '',
      forumHeaderGraphic: typeof profile.forumHeaderGraphic === 'string' ? profile.forumHeaderGraphic : '',
      forumPostColor: typeof profile.forumPostColor === 'string' ? profile.forumPostColor : '',
      forumNameColor: typeof profile.forumNameColor === 'string' ? profile.forumNameColor : '',
      forumNameFont: typeof profile.forumNameFont === 'string' ? profile.forumNameFont : '',
      forumBlinkies: Array.isArray(profile.forumBlinkies) ? profile.forumBlinkies : [],
      availableFonts: FORUM_NAME_FONTS
    });
  } catch (e) {
    console.error('Forum post customization GET:', e);
    res.status(500).json({ error: 'Failed to load' });
  }
});

app.put('/api/forum-post-customization', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator') && !roles.includes('membership')) {
      return res.status(403).json({ error: 'Exclusive membership required to customize forum posts' });
    }
    const { forumPostHeader, forumHeaderGraphic, forumPostColor, forumNameColor, forumNameFont, forumBlinkies } = req.body || {};
    const key = String(userId);
    withLock('profiles', () => {
      const profiles = loadProfiles();
      if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', displayName: '', accentColor: '' };
      if (typeof forumPostHeader === 'string') profiles[key].forumPostHeader = forumPostHeader.slice(0, 200);
      if (typeof forumHeaderGraphic === 'string') {
        const u = forumHeaderGraphic.trim().slice(0, 500);
        profiles[key].forumHeaderGraphic = u;
      }
      if (typeof forumPostColor === 'string') {
        const c = forumPostColor.trim();
        if (c === '' || /^#[0-9A-Fa-f]{3,6}$/.test(c)) profiles[key].forumPostColor = c;
      }
      if (typeof forumNameColor === 'string') {
        const c = forumNameColor.trim();
        if (c === '' || /^#[0-9A-Fa-f]{3,6}$/.test(c)) profiles[key].forumNameColor = c;
      }
      if (typeof forumNameFont === 'string') profiles[key].forumNameFont = forumNameFont.slice(0, 80);
      if (Array.isArray(forumBlinkies)) {
        profiles[key].forumBlinkies = forumBlinkies.filter(u => typeof u === 'string' && u.length > 0 && u.length < 500).slice(0, 10);
      }
      saveProfiles(profiles);
      res.json({
        forumPostHeader: profiles[key].forumPostHeader || '',
        forumHeaderGraphic: profiles[key].forumHeaderGraphic || '',
        forumPostColor: profiles[key].forumPostColor || '',
        forumNameColor: profiles[key].forumNameColor || '',
        forumNameFont: profiles[key].forumNameFont || '',
        forumBlinkies: profiles[key].forumBlinkies || []
      });
    });
  } catch (e) {
    console.error('Forum post customization PUT:', e);
    res.status(500).json({ error: 'Failed to save' });
  }
});

app.get('/api/hover-card-customization', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator') && !roles.includes('membership')) {
      return res.status(403).json({ error: 'Exclusive membership required' });
    }
    const profile = getOrCreateProfile(userId);
    let hoverCardFoil = getHoverCardFoilForUser(userId);
    if (hoverCardFoil === undefined) {
      hoverCardFoil = profile.hoverCardFoil;
      if (hoverCardFoil != null && typeof hoverCardFoil === 'string') {
        try { hoverCardFoil = JSON.parse(hoverCardFoil); } catch (e) { hoverCardFoil = undefined; }
      }
      if (hoverCardFoil != null && (typeof hoverCardFoil !== 'object' || Array.isArray(hoverCardFoil))) hoverCardFoil = undefined;
    }
    const hoverCardSignature = typeof profile.hoverCardSignature === 'string' ? profile.hoverCardSignature.trim().slice(0, 120) : '';
    const hoverCardSignatureImage = typeof profile.hoverCardSignatureImage === 'string' && profile.hoverCardSignatureImage.indexOf('data:image/') === 0
      ? profile.hoverCardSignatureImage.slice(0, 100000) : '';
    const hoverCardStickers = Array.isArray(profile.hoverCardStickers)
      ? profile.hoverCardStickers.filter(s => s && typeof s.id === 'string' && typeof s.x === 'number' && typeof s.y === 'number').slice(0, 12)
      : [];
    res.json({
      cardBgOpacity: typeof profile.hoverCardBgOpacity === 'number' ? profile.hoverCardBgOpacity : 0.55,
      cardBlurPx: typeof profile.hoverCardBlurPx === 'number' ? profile.hoverCardBlurPx : 14,
      cardBorderOpacity: typeof profile.hoverCardBorderOpacity === 'number' ? profile.hoverCardBorderOpacity : 0.5,
      avatarBgOpacity: typeof profile.hoverCardAvatarBgOpacity === 'number' ? profile.hoverCardAvatarBgOpacity : 0.4,
      avatarBlurPx: typeof profile.hoverCardAvatarBlurPx === 'number' ? profile.hoverCardAvatarBlurPx : 8,
      hoverCardFoil: hoverCardFoil || undefined,
      hoverCardSignature: hoverCardSignature || undefined,
      hoverCardSignatureImage: hoverCardSignatureImage || undefined,
      hoverCardStickers: hoverCardStickers.length ? hoverCardStickers : undefined
    });
  } catch (e) {
    console.error('Hover card customization GET:', e);
    res.status(500).json({ error: 'Failed to load' });
  }
});

// Get another user's foil config as a preset (by username, e.g. for "Freyon's foil")
app.get('/api/hover-card-foil-preset/:username', (req, res) => {
  try {
    const username = (req.params.username || '').trim().toLowerCase();
    if (!username) return res.status(400).json({ error: 'Username required' });
    const users = getUsersForAuth();
    const user = users.find(u => (u.username || '').toLowerCase() === username);
    if (!user || user.id == null) return res.status(404).json({ error: 'User not found' });
    const userId = user.id;
    let foil = getHoverCardFoilForUser(userId);
    if (foil === undefined) {
      const profiles = loadProfiles();
      const profile = profiles[String(userId)];
      if (profile && profile.hoverCardFoil != null) {
        foil = profile.hoverCardFoil;
        if (typeof foil === 'string') { try { foil = JSON.parse(foil); } catch (e) { foil = undefined; } }
      }
    }
    if (foil == null || typeof foil !== 'object' || Array.isArray(foil)) {
      return res.status(404).json({ error: 'No foil preset for this user' });
    }
    res.json({ hoverCardFoil: foil });
  } catch (e) {
    console.error('GET hover-card-foil-preset:', e);
    res.status(500).json({ error: 'Failed to load preset' });
  }
});

app.put('/api/hover-card-customization', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator') && !roles.includes('membership')) {
      return res.status(403).json({ error: 'Exclusive membership required' });
    }
    const body = req.body || {};
    const { cardBgOpacity, cardBlurPx, cardBorderOpacity, avatarBgOpacity, avatarBlurPx, hoverCardSignature: bodySignature, hoverCardSignatureImage: bodySignatureImage, hoverCardStickers: bodyStickers } = body;
    let hoverCardFoil = body.hoverCardFoil;
    if (typeof hoverCardFoil === 'string') {
      try { hoverCardFoil = JSON.parse(hoverCardFoil); } catch (e) { hoverCardFoil = undefined; }
    }
    if (process.env.NODE_ENV !== 'production') {
      console.log('[hover-card PUT] hoverCardFoil in body:', body.hoverCardFoil !== undefined, 'normalized:', hoverCardFoil != null && typeof hoverCardFoil === 'object' && !Array.isArray(hoverCardFoil));
    }
    const key = String(userId);
    withLock('profiles', () => {
    const profiles = loadProfiles();
    if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', displayName: '', accentColor: '' };
    if (typeof cardBgOpacity === 'number' && cardBgOpacity >= 0 && cardBgOpacity <= 1) profiles[key].hoverCardBgOpacity = cardBgOpacity;
    if (typeof cardBlurPx === 'number' && cardBlurPx >= 0 && cardBlurPx <= 40) profiles[key].hoverCardBlurPx = cardBlurPx;
    if (typeof cardBorderOpacity === 'number' && cardBorderOpacity >= 0 && cardBorderOpacity <= 1) profiles[key].hoverCardBorderOpacity = cardBorderOpacity;
    if (typeof avatarBgOpacity === 'number' && avatarBgOpacity >= 0 && avatarBgOpacity <= 1) profiles[key].hoverCardAvatarBgOpacity = avatarBgOpacity;
    if (typeof avatarBlurPx === 'number' && avatarBlurPx >= 0 && avatarBlurPx <= 30) profiles[key].hoverCardAvatarBlurPx = avatarBlurPx;
    if (typeof bodySignature === 'string') profiles[key].hoverCardSignature = bodySignature.trim().slice(0, 120);
    if (typeof bodySignatureImage === 'string' && bodySignatureImage.indexOf('data:image/') === 0) {
      profiles[key].hoverCardSignatureImage = bodySignatureImage.slice(0, 100000);
    } else if (bodySignatureImage === '' || bodySignatureImage === null) {
      delete profiles[key].hoverCardSignatureImage;
    }
    if (Array.isArray(bodyStickers)) {
      const valid = bodyStickers.filter(s => s && typeof s.id === 'string' && typeof s.x === 'number' && typeof s.y === 'number').slice(0, 12);
      profiles[key].hoverCardStickers = valid.map(s => ({
        id: String(s.id),
        x: Number(s.x),
        y: Number(s.y),
        scale: typeof s.scale === 'number' && s.scale >= 0.25 && s.scale <= 3 ? s.scale : 1,
        rotation: typeof s.rotation === 'number' && s.rotation >= -180 && s.rotation <= 180 ? s.rotation : 0,
        flipH: !!s.flipH,
        flipV: !!s.flipV
      }));
    }
    if (hoverCardFoil !== undefined) {
      if (hoverCardFoil != null && typeof hoverCardFoil === 'object' && !Array.isArray(hoverCardFoil)) {
        try {
          profiles[key].hoverCardFoil = JSON.parse(JSON.stringify(hoverCardFoil));
        } catch (e) {
          profiles[key].hoverCardFoil = hoverCardFoil;
        }
      } else {
        delete profiles[key].hoverCardFoil;
      }
    }
    try {
      saveProfiles(profiles);
      if (hoverCardFoil !== undefined) saveHoverCardFoil(userId, profiles[key].hoverCardFoil);
    } catch (saveErr) {
      console.error('Hover card customization PUT saveProfiles:', saveErr);
      return res.status(500).json({ error: 'Failed to save' });
    }
    let resFoil = getHoverCardFoilForUser(userId) || profiles[key].hoverCardFoil;
    if (resFoil != null && typeof resFoil === 'string') {
      try { resFoil = JSON.parse(resFoil); } catch (e) { resFoil = undefined; }
    }
    if (resFoil != null && (typeof resFoil !== 'object' || Array.isArray(resFoil))) resFoil = undefined;
    const resSignature = typeof profiles[key].hoverCardSignature === 'string' ? profiles[key].hoverCardSignature.trim().slice(0, 120) : '';
    const resSignatureImage = typeof profiles[key].hoverCardSignatureImage === 'string' && profiles[key].hoverCardSignatureImage.indexOf('data:image/') === 0
      ? profiles[key].hoverCardSignatureImage.slice(0, 100000) : '';
    const resStickers = Array.isArray(profiles[key].hoverCardStickers) ? profiles[key].hoverCardStickers.slice(0, 12) : [];
    res.json({
      cardBgOpacity: profiles[key].hoverCardBgOpacity != null ? profiles[key].hoverCardBgOpacity : 0.55,
      cardBlurPx: profiles[key].hoverCardBlurPx != null ? profiles[key].hoverCardBlurPx : 14,
      cardBorderOpacity: profiles[key].hoverCardBorderOpacity != null ? profiles[key].hoverCardBorderOpacity : 0.5,
      avatarBgOpacity: profiles[key].hoverCardAvatarBgOpacity != null ? profiles[key].hoverCardAvatarBgOpacity : 0.4,
      avatarBlurPx: profiles[key].hoverCardAvatarBlurPx != null ? profiles[key].hoverCardAvatarBlurPx : 8,
      hoverCardFoil: resFoil || undefined,
      hoverCardSignature: resSignature || undefined,
      hoverCardSignatureImage: resSignatureImage || undefined,
      hoverCardStickers: resStickers.length ? resStickers : undefined
    });
    });
  } catch (e) {
    console.error('Hover card customization PUT:', e);
    res.status(500).json({ error: 'Failed to save' });
  }
});

// PATCH: save only hoverCardFoil (so foil persists even if main PUT body was missing it)
app.patch('/api/hover-card-customization', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const roles = getRoles(userId);
    if (!roles.includes('admin') && !roles.includes('moderator') && !roles.includes('membership')) {
      return res.status(403).json({ error: 'Exclusive membership required' });
    }
    const body = req.body || {};
    let hoverCardFoil = body.hoverCardFoil;
    if (typeof hoverCardFoil === 'string') {
      try { hoverCardFoil = JSON.parse(hoverCardFoil); } catch (e) { hoverCardFoil = undefined; }
    }
    const key = String(userId);
    withLock('profiles', () => {
    const profiles = loadProfiles();
    if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', displayName: '', accentColor: '' };
    if (hoverCardFoil !== undefined) {
      if (hoverCardFoil != null && typeof hoverCardFoil === 'object' && !Array.isArray(hoverCardFoil)) {
        try {
          profiles[key].hoverCardFoil = JSON.parse(JSON.stringify(hoverCardFoil));
        } catch (e) {
          profiles[key].hoverCardFoil = hoverCardFoil;
        }
      } else {
        delete profiles[key].hoverCardFoil;
      }
    }
    saveProfiles(profiles);
    saveHoverCardFoil(userId, profiles[key].hoverCardFoil);
    let resFoil = getHoverCardFoilForUser(userId) || profiles[key].hoverCardFoil;
    if (resFoil != null && typeof resFoil === 'string') {
      try { resFoil = JSON.parse(resFoil); } catch (e) { resFoil = undefined; }
    }
    if (resFoil != null && (typeof resFoil !== 'object' || Array.isArray(resFoil))) resFoil = undefined;
    res.json({ hoverCardFoil: resFoil || undefined });
    });
  } catch (e) {
    console.error('Hover card customization PATCH:', e);
    res.status(500).json({ error: 'Failed to save foil' });
  }
});

/** Sanitize HTML for profile page: strip script, iframe, form, event handlers, javascript: URLs. Max length 50000. */
function sanitizeProfilePageHtml(html) {
  if (typeof html !== 'string') return '';
  let s = html.slice(0, 50000);
  s = s.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
  s = s.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, '');
  s = s.replace(/<form\b[^>]*>[\s\S]*?<\/form>/gi, '');
  s = s.replace(/<object\b[^>]*>[\s\S]*?<\/object>/gi, '');
  s = s.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
  s = s.replace(/\son\w+\s*=\s*[^\s>]+/gi, '');
  s = s.replace(/javascript\s*:/gi, '');
  return s;
}

/** Public profile for hover card etc. Returns userId, username, displayName, bio, profilePictureUrl, profilePageHtml. */
app.get('/api/users/:id/profile', (req, res) => {
  try {
    const id = req.params.id;
    const users = getUsersForAuth();
    const u = users.find(x => String(x.id) === String(id));
    if (!u) return res.status(404).json({ error: 'User not found' });
    const profile = getOrCreateProfile(id);
    res.json({
      userId: u.id,
      username: u.username || '',
      displayName: profile.displayName != null ? String(profile.displayName).slice(0, 50) : '',
      bio: profile.bio != null ? profile.bio : '',
      profilePictureUrl: profile.profilePictureUrl || null,
      profilePageHtml: profile.profilePageHtml != null ? String(profile.profilePageHtml) : ''
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/** Forum hover card: returns authorProfile + authorRoles for building full hover card (e.g. quoted username). */
app.get('/api/users/:id/forum-hover-profile', (req, res) => {
  try {
    const id = req.params.id;
    const users = getUsersForAuth();
    const u = users.find(x => String(x.id) === String(id));
    if (!u) return res.status(404).json({ error: 'User not found' });
    const profileToUse = getOrCreateProfile(id);
    let authorProfile = {
      userId: u.id,
      username: u.username || '',
      bio: (profileToUse && profileToUse.bio != null) ? profileToUse.bio : '',
      forumPostHeader: (profileToUse && typeof profileToUse.forumPostHeader === 'string') ? profileToUse.forumPostHeader.slice(0, 200) : '',
      forumHeaderGraphic: (profileToUse && typeof profileToUse.forumHeaderGraphic === 'string' && profileToUse.forumHeaderGraphic.trim()) ? profileToUse.forumHeaderGraphic.trim().slice(0, 500) : '',
      forumPostColor: (profileToUse && typeof profileToUse.forumPostColor === 'string' && /^#[0-9A-Fa-f]{3,6}$/.test(profileToUse.forumPostColor)) ? profileToUse.forumPostColor : '',
      forumNameColor: (profileToUse && typeof profileToUse.forumNameColor === 'string' && /^#[0-9A-Fa-f]{3,6}$/.test(profileToUse.forumNameColor)) ? profileToUse.forumNameColor : '',
      forumNameFont: (profileToUse && typeof profileToUse.forumNameFont === 'string') ? profileToUse.forumNameFont.slice(0, 80) : '',
      forumBlinkies: (profileToUse && Array.isArray(profileToUse.forumBlinkies)) ? profileToUse.forumBlinkies.filter(x => typeof x === 'string' && x.length > 0 && x.length < 500).slice(0, 10) : [],
      hoverCardBgOpacity: (profileToUse && typeof profileToUse.hoverCardBgOpacity === 'number') ? profileToUse.hoverCardBgOpacity : null,
      hoverCardBlurPx: (profileToUse && typeof profileToUse.hoverCardBlurPx === 'number') ? profileToUse.hoverCardBlurPx : null,
      hoverCardBorderOpacity: (profileToUse && typeof profileToUse.hoverCardBorderOpacity === 'number') ? profileToUse.hoverCardBorderOpacity : null,
      hoverCardAvatarBgOpacity: (profileToUse && typeof profileToUse.hoverCardAvatarBgOpacity === 'number') ? profileToUse.hoverCardAvatarBgOpacity : null,
      hoverCardAvatarBlurPx: (profileToUse && typeof profileToUse.hoverCardAvatarBlurPx === 'number') ? profileToUse.hoverCardAvatarBlurPx : null,
      hoverCardFoil: (function () {
        let foil = getHoverCardFoilForUser(id);
        if (foil === undefined && profileToUse && profileToUse.hoverCardFoil) {
          foil = profileToUse.hoverCardFoil;
          if (typeof foil === 'string') { try { foil = JSON.parse(foil); } catch (e) { foil = null; } }
        }
        return (foil != null && typeof foil === 'object' && !Array.isArray(foil)) ? foil : null;
      })(),
      hoverCardSignature: (profileToUse && typeof profileToUse.hoverCardSignature === 'string') ? profileToUse.hoverCardSignature.trim().slice(0, 120) : '',
      hoverCardSignatureImage: (profileToUse && typeof profileToUse.hoverCardSignatureImage === 'string' && profileToUse.hoverCardSignatureImage.indexOf('data:image/') === 0) ? profileToUse.hoverCardSignatureImage.slice(0, 100000) : '',
      hoverCardStickers: (profileToUse && Array.isArray(profileToUse.hoverCardStickers)) ? profileToUse.hoverCardStickers.filter(s => s && typeof s.id === 'string' && typeof s.x === 'number' && typeof s.y === 'number').slice(0, 12) : []
    };
    const authorRoles = getRoles(id);
    const profilePictureUrl = (profileToUse && profileToUse.profilePictureUrl) ? profileToUse.profilePictureUrl : null;
    res.json({ authorProfile, authorRoles, profilePictureUrl });
  } catch (error) {
    console.error('Error fetching forum hover profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/** Request friendship: current user sends request to target userId. */
app.post('/api/friends/request', (req, res) => {
  try {
    const fromUserId = req.session.userId;
    if (fromUserId == null) return res.status(401).json({ error: 'Not logged in' });
    const targetUserId = req.body && req.body.userId != null ? String(req.body.userId) : null;
    if (!targetUserId) return res.status(400).json({ error: 'userId required' });
    if (String(fromUserId) === targetUserId) return res.status(400).json({ error: 'Cannot request yourself' });
    const users = getUsersForAuth();
    if (!users.some(u => String(u.id) === targetUserId)) return res.status(404).json({ error: 'User not found' });
    getOrCreateProfile(targetUserId);
    withLock('profiles', () => {
      const profiles = loadProfiles();
      const targetKey = targetUserId;
      if (!Array.isArray(profiles[targetKey].friendRequestsIncoming)) profiles[targetKey].friendRequestsIncoming = [];
      if (profiles[targetKey].friendRequestsIncoming.indexOf(String(fromUserId)) === -1) {
        profiles[targetKey].friendRequestsIncoming.push(String(fromUserId));
      }
      saveProfiles(profiles);
    });
    res.json({ ok: true });
  } catch (error) {
    console.error('Error sending friend request:', error);
    res.status(500).json({ error: 'Failed to send request' });
  }
});

/** List users with roles (admin only). */
app.get('/api/users', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canAssignRoles(userId)) return res.status(403).json({ error: 'Admin only' });
    const users = getUsersForAuth();
    const list = users.map(u => ({ id: u.id, username: u.username || '', roles: (u.roles && Array.isArray(u.roles)) ? u.roles : [] }));
    res.json(list);
  } catch (error) {
    console.error('Error listing users:', error);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

/** Assign roles to a user (admin only). Only file users (id >= 2) can be edited. */
app.put('/api/users/:id/roles', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canAssignRoles(userId)) return res.status(403).json({ error: 'Admin only' });
    const targetId = Number(req.params.id);
    if (targetId === 1) return res.status(400).json({ error: 'Cannot change built-in admin roles' });
    const { roles } = req.body;
    if (!Array.isArray(roles)) return res.status(400).json({ error: 'roles must be an array' });
    const allowed = ['admin', 'moderator', 'designer', 'membership'];
    const valid = roles.filter(r => allowed.includes(r));
    let updatedRoles;
    withLock('users', () => {
      const users = loadUsers();
      const idx = users.findIndex(u => u && u.id === targetId);
      if (idx === -1) throw new Error('User not found');
      users[idx].roles = valid;
      saveUsers(users);
      updatedRoles = users[idx].roles;
    });
    res.json({ success: true, roles: updatedRoles });
  } catch (error) {
    if (error.message === 'User not found') return res.status(404).json({ error: 'User not found' });
    console.error('Error assigning roles:', error);
    res.status(500).json({ error: 'Failed to assign roles' });
  }
});

app.get('/profile', (req, res) => {
  if (req.session && req.session.userId) return res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  if (req.query && req.query.user) return res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  return res.redirect('/login');
});

app.get('/profile-page', (req, res) => {
  if (req.query && req.query.user) return res.redirect('/profile?user=' + encodeURIComponent(req.query.user));
  res.sendFile(path.join(__dirname, 'public', 'profile-page.html'));
});

app.get('/profile-bio', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile-bio.html'));
});

app.get('/profile-picture', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile-picture.html'));
});

app.get('/profile-saved-outfits', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile-saved-outfits.html'));
});

app.get('/saved-outfits', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'saved-outfits.html'));
});

app.get('/game', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wardrobe.html'));
});

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || req.session.userId == null) return res.redirect('/login');
    const roles = getRoles(req.session.userId);
    if (!allowedRoles.some(r => roles.includes(r))) return res.status(403).send('Access denied');
    next();
  };
}

app.get('/sticker-debug.html', requireLogin, requireRole('admin', 'moderator'), (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'sticker-debug.html'));
});
app.get('/wallpaper-debug.html', requireLogin, requireRole('admin', 'moderator'), (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(path.join(__dirname, 'public', 'wallpaper-debug.html'));
});

// Site settings (wallpaper): public read; upload/clear admin/moderator only
app.get('/api/site-settings', (req, res) => {
  try {
    const settings = loadSiteSettings();
    res.json({ wallpaperUrl: settings.wallpaperUrl || '' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load site settings' });
  }
});

const wallpaperStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
      cb(null, uploadsDir);
    } catch (e) {
      cb(e);
    }
  },
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '').toLowerCase() || '.png';
    const safe = ['.png', '.jpg', '.jpeg', '.gif', '.webp'].includes(ext) ? ext : '.png';
    cb(null, 'site-wallpaper' + safe);
  }
});
const wallpaperUploadMulter = multer({
  storage: wallpaperStorage,
  fileFilter: (req, file, cb) => {
    const mt = (file.mimetype || '').toLowerCase();
    cb(null, /^image\//.test(mt));
  }
});

app.post('/api/site-settings/wallpaper', requireLogin, requireRole('admin', 'moderator'), (req, res, next) => {
  wallpaperUploadMulter.single('wallpaper')(req, res, function (err) {
    if (err) {
      console.error('Wallpaper upload multer error:', err);
      return res.status(500).json({ error: err.message || 'Upload failed' });
    }
    next();
  });
}, (req, res) => {
  try {
    if (!req.file || !req.file.filename) return res.status(400).json({ error: 'No image uploaded. Choose a PNG, JPG, GIF, or WebP file.' });
    const url = '/Uploads/' + req.file.filename;
    withLock('siteSettings', () => {
      const settings = loadSiteSettings();
      settings.wallpaperUrl = url;
      saveSiteSettings(settings);
    });
    res.json({ wallpaperUrl: url });
  } catch (e) {
    console.error('Wallpaper save error:', e);
    res.status(500).json({ error: e.message || 'Failed to save wallpaper' });
  }
});

app.delete('/api/site-settings/wallpaper', requireLogin, requireRole('admin', 'moderator'), (req, res) => {
  try {
    let prev;
    withLock('siteSettings', () => {
      const settings = loadSiteSettings();
      prev = settings.wallpaperUrl || '';
      settings.wallpaperUrl = '';
      saveSiteSettings(settings);
    });
    if (prev && prev.startsWith('/Uploads/')) {
      const filePath = path.join(uploadsDir, path.basename(prev));
      if (fs.existsSync(filePath)) try { fs.unlinkSync(filePath); } catch (e) { /* ignore */ }
    }
    res.json({ wallpaperUrl: '' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to clear wallpaper' });
  }
});

app.get('/moderation.html', requireLogin, requireRole('admin', 'moderator'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'moderation.html'));
});

app.get('/dashboard-edit.html', requireLogin, (req, res, next) => {
  if (!canEditDashboard(req.session.userId)) return res.status(403).send('Access denied. Admin or moderator only.');
  next();
}, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard-edit.html'));
});

app.get('/dashboard-upload-image.html', requireLogin, (req, res, next) => {
  if (!canEditDashboard(req.session.userId)) return res.status(403).send('Access denied. Admin or moderator only.');
  next();
}, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard-upload-image.html'));
});

app.get('/store', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'store.html'));
});

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Uploads');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });
const profilePictureUpload = multer({ storage: multer.memoryStorage() });
const uploadCombo = multer({ storage }).fields([
  { name: 'item1', maxCount: 1 },
  { name: 'item2', maxCount: 1 }
]);

// Initialize files and directories
const itemsFile = path.join(__dirname, 'items.json');
const vintageFile = path.join(__dirname, 'vintage.json');
const wardrobeDebugLog = path.join(__dirname, 'wardrobe-debug.log');
const equippedFile = path.join(__dirname, 'equipped.json');
const outfitsFile = path.join(__dirname, 'outfits.json');
const profilesFile = path.join(__dirname, 'profiles.json');
const hoverCardFoilFile = path.join(__dirname, 'hover-card-foil.json');
const hoverCardStickersDir = path.join(uploadsDir, 'hover-card-stickers');
const hoverCardStickersFile = path.join(__dirname, 'hover-card-stickers.json');
// Serve sticker images so GET /Uploads/hover-card-stickers/:filename works
app.use('/Uploads/hover-card-stickers', express.static(hoverCardStickersDir));

const forumTopicsFile = path.join(__dirname, 'forumTopics.json');
const forumPostsFile = path.join(__dirname, 'forumPosts.json');
const forumEmotesFile = path.join(__dirname, 'forumEmotes.json');
const forumGifsFile = path.join(__dirname, 'forumGifs.json');
const reportsFile = path.join(__dirname, 'reports.json');
const dashboardSlidesFile = path.join(__dirname, 'dashboardSlides.json');
const projectsFile = path.join(__dirname, 'projects.json');
const messagesFile = path.join(__dirname, 'messages.json');
const siteSettingsFile = path.join(__dirname, 'siteSettings.json');
const gameScoresFile = path.join(__dirname, 'gameScores.json');

const GAME_IDS = ['jumpy-bird', 'snake', 'berry-catch', '2048'];
const MAX_SCORES_PER_GAME = 100;

function loadGameScores() {
  try {
    const raw = fs.readFileSync(gameScoresFile, 'utf8');
    const data = JSON.parse(raw);
    return typeof data === 'object' && data !== null ? data : {};
  } catch (e) {
    return {};
  }
}

function saveGameScores(data) {
  const normalized = {};
  GAME_IDS.forEach(function (id) {
    const list = Array.isArray(data[id]) ? data[id] : [];
    normalized[id] = list
      .filter(function (e) { return e && typeof e.score === 'number' && (e.username != null || e.name != null); })
      .sort(function (a, b) { return (b.score || 0) - (a.score || 0); })
      .slice(0, MAX_SCORES_PER_GAME);
  });
  fs.writeFileSync(gameScoresFile, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

app.get('/api/game-scores', (req, res) => {
  try {
    const game = (req.query.game || '').trim();
    if (!GAME_IDS.includes(game)) return res.status(400).json({ error: 'Invalid game id' });
    const data = loadGameScores();
    const list = Array.isArray(data[game]) ? data[game] : [];
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
    res.json({ game, scores: list.slice(0, limit) });
  } catch (e) {
    console.error('Error fetching game scores:', e);
    res.status(500).json({ error: 'Failed to load scores' });
  }
});

app.post('/api/game-scores', (req, res) => {
  try {
    const game = (req.body && req.body.game) ? String(req.body.game).trim() : '';
    const score = typeof req.body.score === 'number' ? req.body.score : parseInt(req.body.score, 10);
    if (!GAME_IDS.includes(game) || !Number.isFinite(score) || score < 0) {
      return res.status(400).json({ error: 'Invalid game or score' });
    }
    let username = 'Guest';
    if (req.session && req.session.userId != null) {
      try {
        const profiles = loadProfiles();
        const key = String(req.session.userId);
        const profile = profiles[key];
        if (profile && (profile.displayName || profile.username)) username = profile.displayName || profile.username || username;
      } catch (e) {}
    }
    const data = loadGameScores();
    if (!Array.isArray(data[game])) data[game] = [];
    data[game].push({ username: username, score: score });
    saveGameScores(data);
    res.json({ success: true, game, score });
  } catch (e) {
    console.error('Error submitting game score:', e);
    res.status(500).json({ error: 'Failed to save score' });
  }
});

function loadSiteSettings() {
  try {
    if (fs.existsSync(siteSettingsFile)) {
      const data = JSON.parse(fs.readFileSync(siteSettingsFile, 'utf8'));
      return typeof data === 'object' && data !== null ? data : {};
    }
  } catch (e) {
    console.error('loadSiteSettings failed:', e.message || e);
  }
  return {};
}

function saveSiteSettings(settings) {
  writeAtomic(siteSettingsFile, JSON.stringify(settings, null, 2));
}

const DEFAULT_EQUIPPED_SLOTS = {
  'body-slot': [], 'shirt-slot': [], 'pants-slot': [], 'skirt-slot': [], 'dress-slot': [],
  'jacket-slot': [], 'shoes-slot': [], 'hat-slot': [], 'jewelry-slot': [], 'other-slot': [],
  'hair-slot': [], 'socks-slot': []
};

const profilePicturesDir = path.join(__dirname, 'Uploads', 'profile-pictures');
const outfitsUploadDir = path.join(__dirname, 'Uploads', 'outfits');
try {
  if (!fs.existsSync('Uploads')) fs.mkdirSync('Uploads');
  if (!fs.existsSync(profilePicturesDir)) fs.mkdirSync(profilePicturesDir, { recursive: true });
  if (!fs.existsSync(outfitsUploadDir)) fs.mkdirSync(outfitsUploadDir, { recursive: true });
  if (!fs.existsSync(hoverCardStickersDir)) fs.mkdirSync(hoverCardStickersDir, { recursive: true });
  if (!fs.existsSync(hoverCardStickersFile)) fs.writeFileSync(hoverCardStickersFile, JSON.stringify([]), 'utf8');
  if (!fs.existsSync(itemsFile)) fs.writeFileSync(itemsFile, JSON.stringify([]));
  if (!fs.existsSync(vintageFile)) fs.writeFileSync(vintageFile, JSON.stringify([]));
  if (!fs.existsSync(equippedFile)) fs.writeFileSync(equippedFile, JSON.stringify(DEFAULT_EQUIPPED_SLOTS));
  if (!fs.existsSync(outfitsFile)) fs.writeFileSync(outfitsFile, JSON.stringify({}));
  if (!fs.existsSync(profilesFile)) fs.writeFileSync(profilesFile, JSON.stringify({}));
  if (!fs.existsSync(forumTopicsFile)) fs.writeFileSync(forumTopicsFile, JSON.stringify([]));
  if (!fs.existsSync(forumPostsFile)) fs.writeFileSync(forumPostsFile, JSON.stringify([]));
  if (!fs.existsSync(reportsFile)) fs.writeFileSync(reportsFile, JSON.stringify([]));
  if (!fs.existsSync(dashboardSlidesFile)) {
    const defaultSlides = [
      { id: '1', title: 'Home Dashboard', text: 'Welcome back! Explore your options.', imageUrl: '' },
      { id: '2', title: 'News Update', text: 'New wardrobe items available today!', imageUrl: '' },
      { id: '3', title: 'Special Offer', text: 'Get 20% off on select items this week!', imageUrl: '' }
    ];
    fs.writeFileSync(dashboardSlidesFile, JSON.stringify(defaultSlides, null, 2));
  }
  if (!fs.existsSync(projectsFile)) fs.writeFileSync(projectsFile, JSON.stringify({}));
  if (!fs.existsSync(messagesFile)) fs.writeFileSync(messagesFile, JSON.stringify([]));
  if (!fs.existsSync(siteSettingsFile)) fs.writeFileSync(siteSettingsFile, JSON.stringify({ wallpaperUrl: '' }, null, 2));
} catch (error) {
  console.error('Error initializing files/directories:', error);
}

const stickerUploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      if (!fs.existsSync(hoverCardStickersDir)) fs.mkdirSync(hoverCardStickersDir, { recursive: true });
      cb(null, hoverCardStickersDir);
    } catch (e) {
      cb(e);
    }
  },
  filename: (req, file, cb) => cb(null, Date.now() + (path.extname(file.originalname) || '.png'))
});
const stickerUploadMulter = multer({
  storage: stickerUploadStorage,
  fileFilter: (req, file, cb) => {
    const mt = (file.mimetype || '').toLowerCase();
    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    const ok = /^image\//.test(mt) || ['.png', '.gif', '.jpg', '.jpeg', '.webp'].includes(ext);
    cb(null, !!ok);
  }
});

const SCRAPPED_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function loadProjects() {
  try {
    if (fs.existsSync(projectsFile)) {
      const data = fs.readFileSync(projectsFile, 'utf8');
      const parsed = JSON.parse(data);
      const projects = typeof parsed === 'object' && parsed !== null ? parsed : {};
      // Purge scrapped projects older than 24 hours
      let changed = false;
      Object.keys(projects).forEach(id => {
        const p = projects[id];
        if (p && p.scrappedAt) {
          const age = Date.now() - new Date(p.scrappedAt).getTime();
          if (age > SCRAPPED_TTL_MS) {
            delete projects[id];
            changed = true;
          }
        }
      });
      if (changed) saveProjects(projects);
      return projects;
    }
  } catch (e) {
    console.error('loadProjects failed:', e.message || e);
  }
  return {};
}
function saveProjects(projects) {
  fs.writeFileSync(projectsFile, JSON.stringify(projects, null, 2), 'utf8');
}

function projectToListEntry(id, p) {
  return {
    id,
    name: p.name || 'Unnamed',
    createdAt: p.createdAt || null,
    released: !!p.released,
    scrappedAt: p.scrappedAt || null,
    itemCount: Array.isArray(p.items) ? p.items.length : 0,
    items: Array.isArray(p.items) ? p.items : []
  };
}

function loadProfiles() {
  try {
    if (fs.existsSync(profilesFile)) {
      const data = fs.readFileSync(profilesFile, 'utf8');
      const parsed = JSON.parse(data);
      return typeof parsed === 'object' && parsed !== null ? parsed : {};
    }
  } catch (e) {
    console.error('loadProfiles failed:', e.message || e);
  }
  return {};
}

function saveProfiles(profiles) {
  writeAtomic(profilesFile, JSON.stringify(profiles, null, 2));
}

function loadHoverCardFoilStore() {
  try {
    if (fs.existsSync(hoverCardFoilFile)) {
      const data = fs.readFileSync(hoverCardFoilFile, 'utf8');
      const parsed = JSON.parse(data);
      return typeof parsed === 'object' && parsed !== null ? parsed : {};
    }
  } catch (e) {
    console.error('loadHoverCardFoilStore failed:', e.message || e);
  }
  return {};
}

function saveHoverCardFoil(userId, foil) {
  const key = String(userId);
  const store = loadHoverCardFoilStore();
  if (foil != null && typeof foil === 'object' && !Array.isArray(foil)) {
    try { store[key] = JSON.parse(JSON.stringify(foil)); } catch (e) { store[key] = foil; }
  } else {
    delete store[key];
  }
  fs.writeFileSync(hoverCardFoilFile, JSON.stringify(store, null, 2), 'utf8');
}

function getHoverCardFoilForUser(userId) {
  const key = String(userId);
  const store = loadHoverCardFoilStore();
  let foil = store[key];
  if (foil != null && typeof foil === 'string') {
    try { foil = JSON.parse(foil); } catch (e) { foil = undefined; }
  }
  if (foil == null || typeof foil !== 'object' || Array.isArray(foil)) return undefined;
  return foil;
}

function loadHoverCardStickers() {
  try {
    if (fs.existsSync(hoverCardStickersFile)) {
      const data = fs.readFileSync(hoverCardStickersFile, 'utf8');
      const parsed = JSON.parse(data);
      return Array.isArray(parsed) ? parsed : [];
    }
  } catch (e) {
    console.error('loadHoverCardStickers failed:', e.message || e);
  }
  return [];
}

function saveHoverCardStickers(list) {
  const arr = Array.isArray(list) ? list : [];
  fs.writeFileSync(hoverCardStickersFile, JSON.stringify(arr, null, 2), 'utf8');
}

function getOrCreateProfile(userId) {
  const key = String(userId);
  const profiles = loadProfiles();
  if (!profiles[key]) {
    let equipped = JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS));
    if (key === '1' && fs.existsSync(equippedFile)) {
      try {
        const existing = JSON.parse(fs.readFileSync(equippedFile, 'utf8'));
        if (existing && typeof existing === 'object' && Object.keys(existing).length > 0) {
          equipped = existing;
        }
      } catch (e) { /* ignore */ }
    }
    profiles[key] = {
      currency: 1000,
      currency2: 0,
      currency3: 50,
      purchased: [],
      equipped,
      bio: '',
      displayName: '',
      accentColor: '',
      wishlistItems: [],
      wishlistSets: []
    };
    saveProfiles(profiles);
  }
  if (!Array.isArray(profiles[key].wishlistItems)) profiles[key].wishlistItems = [];
  if (!Array.isArray(profiles[key].wishlistSets)) profiles[key].wishlistSets = [];
  return profiles[key];
}

function getWishlistItems(profile) {
  const raw = profile && profile.wishlistItems;
  if (!Array.isArray(raw)) return [];
  return raw.map(id => String(id));
}
function getWishlistSets(profile) {
  const raw = profile && profile.wishlistSets;
  if (!Array.isArray(raw)) return [];
  return raw.map(id => String(id));
}

function loadOutfitsByUser() {
  try {
    if (!fs.existsSync(outfitsFile)) return {};
    const raw = fs.readFileSync(outfitsFile, 'utf8');
    const data = JSON.parse(raw);
    if (Array.isArray(data)) {
      const migrated = { '1': data };
      fs.writeFileSync(outfitsFile, JSON.stringify(migrated, null, 2));
      return migrated;
    }
    return typeof data === 'object' && data !== null ? data : {};
  } catch (e) {
    return {};
  }
}

/** Normalize name for duplicate check: trim and lowercase */
function normalizeNameForCheck(name) {
  return (typeof name === 'string' ? name.trim() : '').toLowerCase();
}

/** All names in use across outfits (all users) and item upload projects. Used to enforce unique names. */
function getAllNamesInUse(excludeProjectId = null) {
  const set = new Set();
  const byUser = loadOutfitsByUser();
  Object.keys(byUser).forEach(userId => {
    const list = byUser[userId];
    if (Array.isArray(list)) {
      list.forEach(o => {
        const n = normalizeNameForCheck(o && o.name);
        if (n) set.add(n);
      });
    }
  });
  const projects = loadProjects();
  Object.keys(projects).forEach(id => {
    if (excludeProjectId && id === excludeProjectId) return;
    const p = projects[id];
    if (p && !p.scrappedAt) {
      const n = normalizeNameForCheck(p.name);
      if (n) set.add(n);
    }
  });
  return set;
}

// API routes
// Ensure session has currency and purchased; for logged-in users use profile by id
function ensureUserInventory(req) {
  const userId = req.session.userId;
  if (userId != null) {
    const profile = getOrCreateProfile(userId);
    req.session.currency = typeof profile.currency === 'number' ? profile.currency : 1000;
    req.session.currency2 = typeof profile.currency2 === 'number' ? profile.currency2 : 0;
    req.session.currency3 = typeof profile.currency3 === 'number' ? profile.currency3 : 50;
    req.session.purchased = Array.isArray(profile.purchased) ? profile.purchased : [];
    req.session.wishlistItems = getWishlistItems(profile);
    req.session.wishlistSets = getWishlistSets(profile);
    req.session.gachaCards = (profile.gachaCards && typeof profile.gachaCards === 'object') ? { ...profile.gachaCards } : {};
    req.session.goldenTickets = typeof profile.goldenTickets === 'number' ? profile.goldenTickets : 0;
    return;
  }
  if (typeof req.session.currency !== 'number') req.session.currency = 1000;
  if (typeof req.session.currency2 !== 'number') req.session.currency2 = 0;
  if (typeof req.session.currency3 !== 'number') req.session.currency3 = 50;
  if (typeof req.session.goldenTickets !== 'number') req.session.goldenTickets = 0;
  if (!Array.isArray(req.session.purchased)) req.session.purchased = [];
  if (!Array.isArray(req.session.wishlistItems)) req.session.wishlistItems = [];
  if (!Array.isArray(req.session.wishlistSets)) req.session.wishlistSets = [];
  if (!req.session.gachaCards || typeof req.session.gachaCards !== 'object') req.session.gachaCards = {};
}

function saveWishlistToProfile(userId, wishlistItems, wishlistSets) {
  if (userId == null) return;
  const profiles = loadProfiles();
  const key = String(userId);
  if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', wishlistItems: [], wishlistSets: [] };
  profiles[key].wishlistItems = Array.isArray(wishlistItems) ? wishlistItems.map(x => String(x)) : [];
  profiles[key].wishlistSets = Array.isArray(wishlistSets) ? wishlistSets.map(x => String(x)) : [];
  saveProfiles(profiles);
}

function saveUserInventoryToProfile(userId, currency, purchased, currency2, currency3, goldenTickets) {
  const profiles = loadProfiles();
  const key = String(userId);
  if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '', goldenTickets: 0 };
  profiles[key].currency = currency;
  if (typeof currency2 === 'number') profiles[key].currency2 = currency2;
  if (typeof currency3 === 'number') profiles[key].currency3 = currency3;
  if (typeof goldenTickets === 'number') profiles[key].goldenTickets = goldenTickets;
  profiles[key].purchased = Array.isArray(purchased) ? purchased : [];
  saveProfiles(profiles);
}

const GACHA_CARDS_PER_SET = 10;
const GACHA_SET_REWARD_GOLD = 200;
/** Golden tickets granted when pulling an item you already own, by rarity (default common). */
const GACHA_GOLDEN_TICKETS_BY_RARITY = { common: 1, rare: 3, epic: 5, legendary: 10 };
const GACHA_SETS = [
  { id: 'classic', name: 'Classic Set', machineId: 'classic' },
  { id: 'premium', name: 'Premium Set', machineId: 'premium' },
  { id: 'daily', name: 'Daily Set', machineId: 'daily' }
];

function saveGachaCardsToProfile(userId, gachaCards) {
  if (userId == null || !gachaCards || typeof gachaCards !== 'object') return;
  const profiles = loadProfiles();
  const key = String(userId);
  if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)), bio: '' };
  profiles[key].gachaCards = { ...gachaCards };
  saveProfiles(profiles);
}

const DEFAULT_ITEM_PRICE = 100;

app.get('/api/user-inventory', (req, res) => {
  try {
    ensureUserInventory(req);
    try { fs.appendFileSync(wardrobeDebugLog, new Date().toISOString() + ' GET /api/user-inventory userId=' + (req.session && req.session.userId) + ' purchased=' + (req.session.purchased && req.session.purchased.length) + '\n'); } catch (_) {}
    res.json({ currency: req.session.currency, currency2: req.session.currency2 != null ? req.session.currency2 : 0, currency3: req.session.currency3 != null ? req.session.currency3 : 0, goldenTickets: req.session.goldenTickets != null ? req.session.goldenTickets : 0, purchased: req.session.purchased, gachaCards: req.session.gachaCards || {} });
  } catch (error) {
    try { fs.appendFileSync(wardrobeDebugLog, new Date().toISOString() + ' GET /api/user-inventory error=' + (error && error.message) + '\n'); } catch (_) {}
    console.error('Error fetching user inventory:', error);
    res.status(500).json({ error: 'Failed to fetch inventory' });
  }
});

app.post('/api/purchase/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    ensureUserInventory(req);
    if (req.session.purchased.includes(filename)) {
      return res.json({ success: true, alreadyOwned: true, currency: req.session.currency, currency2: req.session.currency2 != null ? req.session.currency2 : 0, currency3: req.session.currency3 != null ? req.session.currency3 : 0, purchased: req.session.purchased });
    }
    const items = JSON.parse(fs.readFileSync(itemsFile));
    const item = items.find(i => i.filename === filename);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    const price = (item.price != null && !isNaN(Number(item.price))) ? Number(item.price) : DEFAULT_ITEM_PRICE;
    if (req.session.currency < price) {
      return res.status(400).json({ error: 'Not enough currency', currency: req.session.currency, required: price });
    }
    req.session.currency -= price;
    req.session.purchased.push(filename);
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, currency: req.session.currency, currency2: req.session.currency2 != null ? req.session.currency2 : 0, currency3: req.session.currency3 != null ? req.session.currency3 : 0, purchased: req.session.purchased });
  } catch (error) {
    console.error('Error purchasing item:', error);
    res.status(500).json({ error: 'Failed to purchase' });
  }
});

// Vintage: items sold by users
function loadVintage() {
  try {
    const raw = fs.readFileSync(vintageFile, 'utf8');
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch (e) {
    return [];
  }
}
function saveVintage(listings) {
  fs.writeFileSync(vintageFile, JSON.stringify(listings, null, 2), 'utf8');
}

app.get('/api/vintage', (req, res) => {
  try {
    const listings = loadVintage();
    let items = [];
    try {
      const raw = fs.readFileSync(itemsFile, 'utf8');
      const data = JSON.parse(raw);
      items = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    } catch (e) { /* ignore */ }
    const itemByFilename = {};
    items.forEach(i => { if (i && i.filename) itemByFilename[i.filename] = i; });
    const merged = listings.map(l => {
      const item = itemByFilename[l.filename];
      return item ? { ...item, listingId: l.id, sellerId: l.sellerId, sellerName: l.sellerName || '', listedAt: l.listedAt } : null;
    }).filter(Boolean);
    res.json(merged);
  } catch (error) {
    console.error('Error fetching vintage:', error);
    res.status(500).json({ error: 'Failed to fetch vintage' });
  }
});

app.post('/api/vintage/sell/:filename', (req, res) => {
  try {
    ensureUserInventory(req);
    const { filename } = req.params;
    const purchased = req.session.purchased || [];
    if (!purchased.includes(filename)) {
      return res.status(400).json({ error: 'You do not own this item' });
    }
    const profiles = loadProfiles();
    const userId = req.session.userId;
    const profile = userId != null ? profiles[String(userId)] : null;
    const sellerName = (profile && profile.displayName) ? String(profile.displayName).trim() : '';
    const listings = loadVintage();
    const id = Date.now() + '-' + filename.replace(/[^a-zA-Z0-9.-]/g, '') + '-' + (userId || 0);
    listings.push({ id, filename, sellerId: userId, sellerName, listedAt: Date.now() });
    saveVintage(listings);
    req.session.purchased = purchased.filter(f => f !== filename);
    if (userId != null) {
      saveUserInventoryToProfile(userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, listing: { id, filename, sellerId: userId, sellerName, listedAt: listings[listings.length - 1].listedAt }, purchased: req.session.purchased });
  } catch (error) {
    console.error('Error selling to vintage:', error);
    res.status(500).json({ error: 'Failed to sell to vintage' });
  }
});

app.post('/api/vintage/purchase/:listingId', (req, res) => {
  try {
    ensureUserInventory(req);
    const { listingId } = req.params;
    const listings = loadVintage();
    const idx = listings.findIndex(l => l.id === listingId);
    if (idx === -1) {
      return res.status(404).json({ error: 'Listing not found or already sold' });
    }
    const listing = listings[idx];
    const filename = listing.filename;
    req.session.purchased = [...(req.session.purchased || []), filename];
    listings.splice(idx, 1);
    saveVintage(listings);
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, purchased: req.session.purchased });
  } catch (error) {
    console.error('Error purchasing from vintage:', error);
    res.status(500).json({ error: 'Failed to purchase from vintage' });
  }
});

// Earn currency from games (e.g. Berry Catch score). Also grants a small amount of silver (1 per 5 coins, max 5 per call).
app.post('/api/earn-currency', (req, res) => {
  try {
    ensureUserInventory(req);
    const amount = Math.floor(Number(req.body.amount) || 0);
    if (amount <= 0) return res.status(400).json({ error: 'Invalid amount', currency: req.session.currency });
    const capped = Math.min(amount, EARN_CURRENCY_CAP);
    req.session.currency += capped;
    const silverBonus = Math.min(Math.floor(capped / 5), 5);
    req.session.currency3 = (req.session.currency3 != null ? req.session.currency3 : 0) + silverBonus;
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, earned: capped, earnedSilver: silverBonus, currency: req.session.currency, currency2: req.session.currency2 != null ? req.session.currency2 : 0, currency3: req.session.currency3 != null ? req.session.currency3 : 0 });
  } catch (error) {
    console.error('Error earning currency:', error);
    res.status(500).json({ error: 'Failed to add currency' });
  }
});

const GACHA_COST_GOLD = 50;
const EARN_SILVER_CAP = 20;

app.post('/api/earn-silver', (req, res) => {
  try {
    ensureUserInventory(req);
    const amount = Math.floor(Number(req.body.amount) || 0);
    if (amount <= 0) return res.status(400).json({ error: 'Invalid amount', currency3: req.session.currency3 });
    const capped = Math.min(amount, EARN_SILVER_CAP);
    req.session.currency3 = (req.session.currency3 != null ? req.session.currency3 : 0) + capped;
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, earned: capped, currency3: req.session.currency3 });
  } catch (error) {
    console.error('Error earning silver:', error);
    res.status(500).json({ error: 'Failed to add silver' });
  }
});

// Debug: add unlimited coins and/or candies (admin/moderator only)
app.post('/api/debug-add-currency', requireLogin, (req, res) => {
  try {
    const roles = getRoles(req.session.userId);
    if (!roles.includes('admin') && !roles.includes('moderator')) return res.status(403).json({ error: 'Admin or moderator required' });
    ensureUserInventory(req);
    const coins = Math.floor(Number(req.body.coins) || 0);
    const gems = Math.floor(Number(req.body.gems) || 0);
    if (coins > 0) {
      req.session.currency = (req.session.currency != null ? req.session.currency : 0) + coins;
    }
    if (gems > 0) {
      req.session.currency2 = (req.session.currency2 != null ? req.session.currency2 : 0) + gems;
    }
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({
      success: true,
      currency: req.session.currency,
      currency2: req.session.currency2 != null ? req.session.currency2 : 0,
      currency3: req.session.currency3 != null ? req.session.currency3 : 0
    });
  } catch (error) {
    console.error('Error debug-add-currency:', error);
    res.status(500).json({ error: 'Failed to add currency' });
  }
});

app.post('/api/gacha', (req, res) => {
  try {
    ensureUserInventory(req);
    const gold = req.session.currency != null ? req.session.currency : 0;
    if (gold < GACHA_COST_GOLD) {
      return res.status(400).json({ error: 'Not enough gold coins', currency: gold, required: GACHA_COST_GOLD });
    }
    const machineId = (req.body && req.body.machineId) ? String(req.body.machineId) : 'classic';
    const setConfig = GACHA_SETS.find(s => s.machineId === machineId);
    const items = JSON.parse(fs.readFileSync(itemsFile, 'utf8'));
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(503).json({ error: 'No items available for gacha' });
    }
    const idx = Math.floor(Math.random() * items.length);
    const item = items[idx];
    const filename = item.filename;
    const alreadyOwned = req.session.purchased.includes(filename);
    req.session.currency = gold - GACHA_COST_GOLD;
    let goldenTicketsFromPull = 0;
    if (alreadyOwned) {
      const rarity = (item.rarity && typeof item.rarity === 'string') ? item.rarity.toLowerCase() : 'common';
      goldenTicketsFromPull = GACHA_GOLDEN_TICKETS_BY_RARITY[rarity] != null ? GACHA_GOLDEN_TICKETS_BY_RARITY[rarity] : GACHA_GOLDEN_TICKETS_BY_RARITY.common;
      req.session.goldenTickets = (req.session.goldenTickets != null ? req.session.goldenTickets : 0) + goldenTicketsFromPull;
    } else {
      req.session.purchased = req.session.purchased.slice();
      req.session.purchased.push(filename);
    }
    let setCompleted = false;
    let setCompletedName = null;
    if (setConfig) {
      const cards = req.session.gachaCards || {};
      const current = (cards[setConfig.id] != null && Number.isInteger(cards[setConfig.id])) ? cards[setConfig.id] : 0;
      const next = current + 1;
      req.session.gachaCards = { ...cards, [setConfig.id]: next };
      if (next >= GACHA_CARDS_PER_SET) {
        req.session.gachaCards[setConfig.id] = 0;
        req.session.currency += GACHA_SET_REWARD_GOLD;
        setCompleted = true;
        setCompletedName = setConfig.name;
        if (req.session.userId != null) saveGachaCardsToProfile(req.session.userId, req.session.gachaCards);
      }
    }
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3, req.session.goldenTickets);
      if (!setCompleted) saveGachaCardsToProfile(req.session.userId, req.session.gachaCards);
    }
    const rarity = (item.rarity && typeof item.rarity === 'string') ? item.rarity.toLowerCase() : 'common';
    res.json({
      success: true,
      item: {
        filename: item.filename,
        name: item.name || item.filename,
        rarity: rarity,
        alreadyOwned: alreadyOwned,
        goldenTickets: alreadyOwned ? (GACHA_GOLDEN_TICKETS_BY_RARITY[rarity] != null ? GACHA_GOLDEN_TICKETS_BY_RARITY[rarity] : GACHA_GOLDEN_TICKETS_BY_RARITY.common) : 0
      },
      alreadyOwned,
      goldenTicketsFromPull: goldenTicketsFromPull || undefined,
      goldenTickets: req.session.goldenTickets != null ? req.session.goldenTickets : 0,
      currency: req.session.currency,
      currency2: req.session.currency2 != null ? req.session.currency2 : 0,
      currency3: req.session.currency3 != null ? req.session.currency3 : 0,
      purchased: req.session.purchased,
      gachaCards: req.session.gachaCards || {},
      setCompleted: setCompleted || undefined,
      setCompletedName: setCompletedName || undefined
    });
  } catch (error) {
    console.error('Error gacha:', error);
    res.status(500).json({ error: 'Failed to pull gacha' });
  }
});

// Golden Ticket Store: items that can be bought with golden tickets (item.goldenTicketPrice must be a positive number)
app.get('/api/gacha-ticket-shop', (req, res) => {
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const price = (item) => (item && typeof item.goldenTicketPrice === 'number' && item.goldenTicketPrice > 0) ? item.goldenTicketPrice : 0;
    const shop = list.filter(item => item && item.filename && price(item) > 0).map(item => ({
      filename: item.filename,
      name: item.name || item.filename,
      slotId: item.slotId,
      goldenTicketPrice: price(item),
      designer: item.designer || ''
    }));
    res.json(shop);
  } catch (error) {
    console.error('Error fetching gacha ticket shop:', error);
    res.status(500).json({ error: 'Failed to load ticket shop' });
  }
});

app.post('/api/gacha-ticket-shop/purchase/:filename', (req, res) => {
  try {
    ensureUserInventory(req);
    const { filename } = req.params;
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const item = list.find(i => i && i.filename === filename);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    const price = (typeof item.goldenTicketPrice === 'number' && item.goldenTicketPrice > 0) ? item.goldenTicketPrice : 0;
    if (price <= 0) return res.status(400).json({ error: 'Item is not available for golden tickets' });
    const tickets = req.session.goldenTickets != null ? req.session.goldenTickets : 0;
    if (tickets < price) return res.status(400).json({ error: 'Not enough golden tickets', goldenTickets: tickets, required: price });
    if (req.session.purchased.includes(filename)) {
      return res.json({ success: true, alreadyOwned: true, goldenTickets: req.session.goldenTickets, purchased: req.session.purchased });
    }
    req.session.goldenTickets = tickets - price;
    req.session.purchased = [...req.session.purchased, filename];
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3, req.session.goldenTickets);
    }
    res.json({
      success: true,
      goldenTickets: req.session.goldenTickets,
      purchased: req.session.purchased,
      currency: req.session.currency,
      currency2: req.session.currency2 != null ? req.session.currency2 : 0,
      currency3: req.session.currency3 != null ? req.session.currency3 : 0
    });
  } catch (error) {
    console.error('Error purchasing with golden tickets:', error);
    res.status(500).json({ error: 'Failed to purchase' });
  }
});

app.get('/api/items', (req, res) => {
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    try { fs.appendFileSync(wardrobeDebugLog, new Date().toISOString() + ' GET /api/items count=' + list.length + '\n'); } catch (_) {}
    res.json(list);
  } catch (error) {
    try { fs.appendFileSync(wardrobeDebugLog, new Date().toISOString() + ' GET /api/items error=' + (error && error.message) + '\n'); } catch (_) {}
    console.error('Error fetching items:', error);
    res.status(500).json({ error: 'Failed to fetch items' });
  }
});

app.get('/api/items-count', (req, res) => {
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    res.json({ count: list.length });
  } catch (e) {
    res.status(500).json({ count: 0, error: (e && e.message) || 'error' });
  }
});

// Seed wardrobe with sample items (for testing when store is empty or user has no purchases)
app.post('/api/wardrobe-seed', (req, res) => {
  try {
    ensureUserInventory(req);
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data && data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const filenames = list.filter(item => item && item.filename).map(item => item.filename).slice(0, 10);
    const purchased = req.session.purchased || [];
    filenames.forEach(f => { if (!purchased.includes(f)) purchased.push(f); });
    req.session.purchased = purchased;
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, added: filenames.length, purchased: req.session.purchased });
  } catch (error) {
    console.error('Error seeding wardrobe:', error);
    res.status(500).json({ error: 'Failed to seed wardrobe' });
  }
});

// Wardrobe: only items the user has purchased
app.get('/api/wardrobe-items', (req, res) => {
  try {
    ensureUserInventory(req);
    const allItems = JSON.parse(fs.readFileSync(itemsFile));
    const list = Array.isArray(allItems) ? allItems : (allItems[0] && Array.isArray(allItems[0]) ? allItems.flat() : []);
    const purchased = req.session.purchased || [];
    const filtered = list.filter(item => item && item.filename && purchased.includes(item.filename));
    res.json(filtered);
  } catch (error) {
    console.error('Error fetching wardrobe items:', error);
    res.status(500).json({ error: 'Failed to fetch wardrobe items' });
  }
});

// Wishlist: per-user lists of item filenames and set ids
app.get('/api/wishlist', (req, res) => {
  try {
    ensureUserInventory(req);
    res.json({
      items: req.session.wishlistItems || [],
      sets: req.session.wishlistSets || []
    });
  } catch (error) {
    console.error('Error fetching wishlist:', error);
    res.status(500).json({ error: 'Failed to fetch wishlist' });
  }
});

app.post('/api/wishlist/toggle', (req, res) => {
  try {
    ensureUserInventory(req);
    const { type, id } = req.body || {};
    if (!type || (id !== 0 && !id)) {
      return res.status(400).json({ error: 'Body must include type ("item" or "set") and id' });
    }
    const idStr = String(id);
    const items = req.session.wishlistItems || [];
    const sets = req.session.wishlistSets || [];
    if (type === 'item') {
      const idx = items.indexOf(idStr);
      if (idx >= 0) {
        req.session.wishlistItems = items.filter((_, i) => i !== idx);
      } else {
        req.session.wishlistItems = [...items, idStr];
      }
    } else if (type === 'set') {
      const idx = sets.indexOf(idStr);
      if (idx >= 0) {
        req.session.wishlistSets = sets.filter((_, i) => i !== idx);
      } else {
        req.session.wishlistSets = [...sets, idStr];
      }
    } else {
      return res.status(400).json({ error: 'type must be "item" or "set"' });
    }
    if (req.session.userId != null) {
      saveWishlistToProfile(req.session.userId, req.session.wishlistItems, req.session.wishlistSets);
    }
    res.json({
      items: req.session.wishlistItems,
      sets: req.session.wishlistSets
    });
  } catch (error) {
    console.error('Error toggling wishlist:', error);
    res.status(500).json({ error: 'Failed to update wishlist' });
  }
});

app.post('/api/wishlist/reorder', (req, res) => {
  try {
    ensureUserInventory(req);
    const { items, sets } = req.body || {};
    const newItems = Array.isArray(items) ? items.map(x => String(x)) : (req.session.wishlistItems || []);
    const newSets = Array.isArray(sets) ? sets.map(x => String(x)) : (req.session.wishlistSets || []);
    const currentItems = req.session.wishlistItems || [];
    const currentSets = req.session.wishlistSets || [];
    if (newItems.length !== currentItems.length || newSets.length !== currentSets.length) {
      return res.status(400).json({ error: 'Reorder must include the same items and sets (no add/remove)' });
    }
    const itemSet = new Set(currentItems);
    const setSet = new Set(currentSets);
    if (newItems.some(id => !itemSet.has(id)) || newSets.some(id => !setSet.has(id))) {
      return res.status(400).json({ error: 'Reorder must only contain existing wishlist entries' });
    }
    if (new Set(newItems).size !== currentItems.length || new Set(newSets).size !== currentSets.length) {
      return res.status(400).json({ error: 'Reorder must include the same items and sets (no add/remove)' });
    }
    if (currentItems.some(id => !newItems.includes(id)) || currentSets.some(id => !newSets.includes(id))) {
      return res.status(400).json({ error: 'Reorder must include the same items and sets (no add/remove)' });
    }
    req.session.wishlistItems = newItems;
    req.session.wishlistSets = newSets;
    if (req.session.userId != null) {
      saveWishlistToProfile(req.session.userId, req.session.wishlistItems, req.session.wishlistSets);
    }
    res.json({ success: true, items: req.session.wishlistItems, sets: req.session.wishlistSets });
  } catch (error) {
    console.error('Error reordering wishlist:', error);
    res.status(500).json({ error: 'Failed to save order' });
  }
});

app.post('/api/items/upload', upload.single('item'), (req, res) => {
  try {
    const { name, slotId, tags, designer, isSet, defaultX, defaultY, defaultZ, frameCount, spriteSheetFrameW, spriteSheetFrameH } = req.body;
    const items = JSON.parse(fs.readFileSync(itemsFile));
    const newId = randomItemId();
    const newItem = {
      filename: req.file.filename,
      id: newId,
      name: name && String(name).trim() ? String(name).trim() : newId,
      slotId,
      tags: tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [],
      heart: false,
      designer: designer || '',
      isSet: isSet === 'true',
      defaultX: parseFloat(defaultX) || 0,
      defaultY: parseFloat(defaultY) || 0,
      defaultZ: parseInt(defaultZ) || 0,
      dateAdded: new Date().toISOString()
    };
    const fc = parseInt(frameCount, 10);
    if (fc > 1) {
      newItem.frameCount = fc;
      newItem.spriteSheetFrameW = Math.max(1, parseInt(spriteSheetFrameW, 10) || 0);
      newItem.spriteSheetFrameH = Math.max(1, parseInt(spriteSheetFrameH, 10) || 0);
    }
    items.push(newItem);
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    res.json(newItem);
  } catch (error) {
    console.error('Error uploading item:', error);
    res.status(500).json({ error: 'Failed to upload item' });
  }
});

// Profile picture (forum icon): upload cropped image from profile picture editor
app.post('/api/profile-picture', requireLogin, profilePictureUpload.single('picture'), (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!req.file || !req.file.buffer) return res.status(400).json({ error: 'No picture uploaded' });
    const ext = (req.file.mimetype === 'image/png') ? '.png' : '.jpg';
    const filename = String(userId) + ext;
    const filepath = path.join(profilePicturesDir, filename);
    fs.writeFileSync(filepath, req.file.buffer);
    const profilePictureUrl = '/Uploads/profile-pictures/' + filename;
    const key = String(userId);
    withLock('profiles', () => {
      const profiles = loadProfiles();
      if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)) };
      profiles[key].profilePictureUrl = profilePictureUrl;
      saveProfiles(profiles);
    });
    res.json({ success: true, profilePictureUrl });
  } catch (error) {
    console.error('Error saving profile picture:', error);
    res.status(500).json({ error: 'Failed to save profile picture' });
  }
});

// Upload combo: two files become one item; equips as two separate layers in wardrobe/store
app.post('/api/items/upload-combo', uploadCombo, (req, res) => {
  try {
    const file1 = req.files && req.files.item1 && req.files.item1[0];
    const file2 = req.files && req.files.item2 && req.files.item2[0];
    if (!file1 || !file2) {
      return res.status(400).json({ error: 'Both item1 and item2 files are required' });
    }
    const { name, slotId1, slotId2, defaultX1, defaultY1, defaultZ1, defaultX2, defaultY2, defaultZ2 } = req.body;
    const items = JSON.parse(fs.readFileSync(itemsFile));
    const part1 = {
      filename: file1.filename,
      slotId: slotId1 || 'body-slot',
      defaultX: parseFloat(defaultX1) || 0,
      defaultY: parseFloat(defaultY1) || 0,
      defaultZ: parseInt(defaultZ1) || 0
    };
    const part2 = {
      filename: file2.filename,
      slotId: slotId2 || 'other-slot',
      defaultX: parseFloat(defaultX2) || 0,
      defaultY: parseFloat(defaultY2) || 0,
      defaultZ: parseInt(defaultZ2) || 0
    };
    const newItem = {
      filename: file1.filename,
      name: name || (file1.originalname + ' + ' + file2.originalname),
      slotId: part1.slotId,
      tags: [],
      heart: false,
      designer: (req.body.designer || '').toString(),
      isSet: false,
      defaultX: part1.defaultX,
      defaultY: part1.defaultY,
      defaultZ: part1.defaultZ,
      bundleParts: [part1, part2],
      dateAdded: new Date().toISOString()
    };
    items.push(newItem);
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    res.json(newItem);
  } catch (error) {
    console.error('Error uploading combo:', error);
    res.status(500).json({ error: 'Failed to upload combo' });
  }
});

// Parse number from body; allow 0, only fall back to existing when value is missing/NaN
function parseNum(bodyVal, existing, parseFn) {
  const n = bodyVal !== undefined && bodyVal !== null && bodyVal !== ''
    ? parseFn(bodyVal) : NaN;
  return (n === n) ? n : (existing ?? 0); // NaN check: n === n is false for NaN
}

function randomItemId() {
  return require('crypto').randomBytes(4).toString('hex');
}

// Update only coordinates (so coords always persist even if full PUT has issues)
app.patch('/api/items/update/:filename/coordinates', (req, res) => {
  try {
    const { filename } = req.params;
    const body = req.body || {};
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const idx = list.findIndex(item => item && item.filename === filename);
    if (idx === -1) return res.status(404).json({ error: 'Item not found' });
    const item = list[idx];
    const x = (body.defaultX !== undefined && body.defaultX !== null && body.defaultX !== '') ? Number(body.defaultX) : NaN;
    const y = (body.defaultY !== undefined && body.defaultY !== null && body.defaultY !== '') ? Number(body.defaultY) : NaN;
    const z = (body.defaultZ !== undefined && body.defaultZ !== null && body.defaultZ !== '') ? parseInt(String(body.defaultZ), 10) : NaN;
    if (Number.isFinite(x)) item.defaultX = x;
    if (Number.isFinite(y)) item.defaultY = y;
    if (!isNaN(z) && z >= 0) item.defaultZ = z;
    fs.writeFileSync(itemsFile, JSON.stringify(list, null, 2), 'utf8');
    res.json({ defaultX: item.defaultX, defaultY: item.defaultY, defaultZ: item.defaultZ });
  } catch (err) {
    console.error('PATCH coordinates:', err);
    res.status(500).json({ error: 'Failed to update coordinates' });
  }
});

app.put('/api/items/update/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const body = req.body || {};
    const { name, id, slotId, tags, heart, designer, isSet, defaultX, defaultY, defaultZ, bundleParts, background, goldenTicketPrice, frameCount, spriteSheetFrameW, spriteSheetFrameH } = body;
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const itemIndex = list.findIndex(item => item && item.filename === filename);
    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }
    const prev = list[itemIndex];
    let backgroundVal = prev.background;
    if (background === null || background === '') {
      backgroundVal = null;
    } else if (background && typeof background === 'object' && background.filename) {
      backgroundVal = {
        filename: background.filename,
        defaultX: parseNum(background.defaultX, 0, parseFloat),
        defaultY: parseNum(background.defaultY, 0, parseFloat),
        defaultZ: parseInt(background.defaultZ, 10) || 0
      };
    }
    const rawTags = tags !== undefined ? (Array.isArray(tags) ? tags : []) : prev.tags;
    const normalizedTags = rawTags.filter(t => {
      if (typeof t !== 'string') return true;
      const v = t.replace(/^(set-id|set-name|set):/, '').trim();
      return v !== 'DefaultSet';
    });
    const newId = (id !== undefined && id !== null && String(id).trim()) ? String(id).trim() : (prev.id || randomItemId());
    // Coerce coordinates from body so they always persist (allow 0; only fall back to prev when missing)
    const coordX = (defaultX !== undefined && defaultX !== null && defaultX !== '') ? Number(defaultX) : (prev.defaultX != null ? Number(prev.defaultX) : 0);
    const coordY = (defaultY !== undefined && defaultY !== null && defaultY !== '') ? Number(defaultY) : (prev.defaultY != null ? Number(prev.defaultY) : 0);
    const coordZ = (defaultZ !== undefined && defaultZ !== null && defaultZ !== '') ? parseInt(String(defaultZ), 10) : (prev.defaultZ != null ? parseInt(prev.defaultZ, 10) : 0);
    const finalX = Number.isFinite(coordX) ? coordX : 0;
    const finalY = Number.isFinite(coordY) ? coordY : 0;
    const finalZ = (coordZ === coordZ && coordZ >= 0) ? coordZ : 0;
    const fc = frameCount !== undefined && frameCount !== null && frameCount !== '' ? parseInt(String(frameCount), 10) : prev.frameCount;
    const hasFrames = (fc > 1);
    const frameW = hasFrames && spriteSheetFrameW != null && spriteSheetFrameW !== '' ? Math.max(1, parseInt(spriteSheetFrameW, 10) || 0) : (prev.spriteSheetFrameW || 0);
    const frameH = hasFrames && spriteSheetFrameH != null && spriteSheetFrameH !== '' ? Math.max(1, parseInt(spriteSheetFrameH, 10) || 0) : (prev.spriteSheetFrameH || 0);
    list[itemIndex] = {
      ...prev,
      id: newId,
      name: name !== undefined && name !== null ? name : (prev.name || newId),
      slotId: slotId !== undefined && slotId !== null ? slotId : prev.slotId,
      tags: normalizedTags,
      heart: heart !== undefined ? !!heart : prev.heart,
      designer: designer !== undefined ? designer : prev.designer,
      isSet: isSet !== undefined ? (isSet === 'true' || isSet === true) : prev.isSet,
      defaultX: finalX,
      defaultY: finalY,
      defaultZ: finalZ,
      bundleParts: bundleParts !== undefined ? (Array.isArray(bundleParts) ? bundleParts : prev.bundleParts) : prev.bundleParts,
      background: backgroundVal,
      goldenTicketPrice: goldenTicketPrice !== undefined && goldenTicketPrice !== null && goldenTicketPrice !== '' ? Math.max(0, Math.floor(Number(goldenTicketPrice))) : prev.goldenTicketPrice,
      frameCount: hasFrames ? fc : (prev.frameCount || 1),
      spriteSheetFrameW: hasFrames ? frameW : (prev.spriteSheetFrameW || 0),
      spriteSheetFrameH: hasFrames ? frameH : (prev.spriteSheetFrameH || 0)
    };
    fs.writeFileSync(itemsFile, JSON.stringify(list, null, 2), 'utf8');
    res.json(list[itemIndex]);
  } catch (error) {
    console.error('Error updating item:', error);
    res.status(500).json({ error: 'Failed to update item' });
  }
});

// One-time migration: set every swatch item's coordinates to its parent item's coordinates
app.post('/api/items/sync-swatch-coordinates', (req, res) => {
  try {
    const raw = fs.readFileSync(itemsFile, 'utf8');
    const data = JSON.parse(raw);
    const list = Array.isArray(data) ? data : (data[0] && Array.isArray(data[0]) ? data.flat() : []);
    const byFilename = {};
    list.forEach(item => {
      if (item && item.filename) byFilename[item.filename] = item;
    });
    function getSwatchParentFilename(item) {
      if (!item || !Array.isArray(item.tags)) return null;
      const tag = item.tags.find(t => typeof t === 'string' && t.startsWith('swatch-parent:'));
      return tag ? tag.replace('swatch-parent:', '').trim() : null;
    }
    const updated = [];
    list.forEach(item => {
      if (!item || !item.filename) return;
      const parentFilename = getSwatchParentFilename(item);
      if (!parentFilename) return;
      const parent = byFilename[parentFilename];
      if (!parent) return;
      const x = parent.defaultX != null && !isNaN(Number(parent.defaultX)) ? Number(parent.defaultX) : 0;
      const y = parent.defaultY != null && !isNaN(Number(parent.defaultY)) ? Number(parent.defaultY) : 0;
      const z = parent.defaultZ != null && !isNaN(parseInt(parent.defaultZ, 10)) ? parseInt(parent.defaultZ, 10) : 0;
      item.defaultX = x;
      item.defaultY = y;
      item.defaultZ = z;
      updated.push(item.filename);
    });
    if (updated.length > 0) {
      fs.writeFileSync(itemsFile, JSON.stringify(list, null, 2), 'utf8');
    }
    res.json({ success: true, updated: updated.length, filenames: updated });
  } catch (err) {
    console.error('Sync swatch coordinates:', err);
    res.status(500).json({ error: 'Failed to sync swatch coordinates' });
  }
});

app.delete('/api/items/:filename', (req, res) => {
  try {
    const { filename } = req.params;
    const items = JSON.parse(fs.readFileSync(itemsFile));
    const itemIndex = items.findIndex(item => item.filename === filename);
    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }
    const item = items[itemIndex];
    items.splice(itemIndex, 1);
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    const uploadsDir = path.join(__dirname, 'Uploads');
    const filesToDelete = new Set([filename, ...(item.bundleParts || []).map(p => p.filename), ...(item.background && item.background.filename ? [item.background.filename] : [])]);
    filesToDelete.forEach(f => {
      const uploadsPath = path.join(uploadsDir, f);
      if (fs.existsSync(uploadsPath)) fs.unlinkSync(uploadsPath);
    });
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

// ----- Projects (upload workflow: create project → upload items to project → release into game) -----
app.get('/api/projects', (req, res) => {
  try {
    const projects = loadProjects();
    const active = [];
    const scrapped = [];
    Object.keys(projects).forEach(id => {
      const p = projects[id];
      const entry = projectToListEntry(id, p);
      if (p.scrappedAt) scrapped.push(entry);
      else active.push(entry);
    });
    active.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    scrapped.sort((a, b) => (b.scrappedAt || '').localeCompare(a.scrappedAt || ''));
    res.json({ active, scrapped });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

app.get('/api/names-in-use', (req, res) => {
  try {
    const set = getAllNamesInUse();
    res.json({ names: Array.from(set) });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch names' });
  }
});

app.post('/api/projects', (req, res) => {
  try {
    const name = (req.body.name || '').trim() || 'Unnamed Project';
    const namesInUse = getAllNamesInUse();
    if (namesInUse.has(normalizeNameForCheck(name))) {
      return res.status(400).json({ error: 'An outfit, item upload project, or pixel drawing project with this name already exists. Please choose a different name.' });
    }
    const projects = loadProjects();
    const id = 'proj_' + Date.now();
    projects[id] = {
      id,
      name,
      createdAt: new Date().toISOString(),
      released: false,
      items: []
    };
    saveProjects(projects);
    res.json(projects[id]);
  } catch (e) {
    res.status(500).json({ error: 'Failed to create project' });
  }
});

app.get('/api/projects/:id', (req, res) => {
  try {
    const { id } = req.params;
    const projects = loadProjects();
    const p = projects[id];
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (p.scrappedAt) return res.status(404).json({ error: 'Project was scrapped' });
    res.json(p);
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

app.put('/api/projects/:id', (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body || {};
    const projects = loadProjects();
    const p = projects[id];
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (p.scrappedAt) return res.status(400).json({ error: 'Project was scrapped' });
    if (typeof name === 'string' && name.trim() !== '') {
      const namesInUse = getAllNamesInUse(id);
      const newNorm = normalizeNameForCheck(name);
      if (namesInUse.has(newNorm)) {
        return res.status(400).json({ error: 'An outfit, item upload project, or pixel drawing project with this name already exists. Please choose a different name.' });
      }
      p.name = name.trim();
      saveProjects(projects);
    }
    res.json(p);
  } catch (e) {
    res.status(500).json({ error: 'Failed to update project' });
  }
});

function scrapProjectById(id) {
  const projects = loadProjects();
  const trimmed = (id || '').toString().trim();
  let p = projects[trimmed];
  if (!p && trimmed) {
    const key = Object.keys(projects).find(k => k === trimmed || (projects[k] && (projects[k].id === trimmed || projects[k].id === id)));
    if (key) p = projects[key];
  }
  if (!p) return { success: true, alreadyGone: true };
  p.scrappedAt = new Date().toISOString();
  saveProjects(projects);
  return { success: true, scrappedAt: p.scrappedAt };
}

app.delete('/api/projects/:id', (req, res) => {
  try {
    const id = (req.params.id || '').toString().trim();
    const result = scrapProjectById(id);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Failed to scrap project' });
  }
});

app.post('/api/projects/:id/scrap', (req, res) => {
  try {
    const id = (req.params.id || '').toString().trim();
    const result = scrapProjectById(id);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Failed to scrap project' });
  }
});

app.post('/api/projects/:id/restore', (req, res) => {
  try {
    const { id } = req.params;
    const projects = loadProjects();
    const p = projects[id];
    if (!p) return res.status(404).json({ error: 'Project not found' });
    if (!p.scrappedAt) return res.json(p);
    delete p.scrappedAt;
    saveProjects(projects);
    res.json(p);
  } catch (e) {
    res.status(500).json({ error: 'Failed to restore project' });
  }
});

app.post('/api/projects/:id/upload', upload.single('item'), (req, res) => {
  try {
    const { id } = req.params;
    const { name, slotId, tags, designer, isSet, defaultX, defaultY, defaultZ, frameCount, spriteSheetFrameW, spriteSheetFrameH } = req.body;
    const projects = loadProjects();
    const project = projects[id];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.scrappedAt) return res.status(400).json({ error: 'Project was scrapped' });
    if (project.released) return res.status(400).json({ error: 'Project already released' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const newItem = {
      filename: req.file.filename,
      name: name || req.file.originalname,
      slotId: slotId || 'other-slot',
      tags: tags ? tags.split(',').map(t => t.trim()).filter(t => t) : [],
      heart: false,
      designer: designer || '',
      isSet: isSet === 'true',
      defaultX: parseFloat(defaultX) || 0,
      defaultY: parseFloat(defaultY) || 0,
      defaultZ: parseInt(defaultZ) || 0,
      dateAdded: new Date().toISOString()
    };
    const fc = parseInt(frameCount, 10);
    if (fc > 1) {
      newItem.frameCount = fc;
      newItem.spriteSheetFrameW = Math.max(1, parseInt(spriteSheetFrameW, 10) || 0);
      newItem.spriteSheetFrameH = Math.max(1, parseInt(spriteSheetFrameH, 10) || 0);
    }
    if (!Array.isArray(project.items)) project.items = [];
    project.items.push(newItem);
    saveProjects(projects);
    res.json(newItem);
  } catch (e) {
    console.error('Error uploading to project:', e);
    res.status(500).json({ error: 'Failed to upload to project' });
  }
});

app.put('/api/projects/:id/items/:filename', (req, res) => {
  try {
    const { id, filename } = req.params;
    const { name, slotId, tags, defaultX, defaultY, defaultZ, bundleParts, background, frameCount, spriteSheetFrameW, spriteSheetFrameH } = req.body;
    const projects = loadProjects();
    const project = projects[id];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.scrappedAt) return res.status(400).json({ error: 'Project was scrapped' });
    const items = Array.isArray(project.items) ? project.items : [];
    const idx = items.findIndex(i => i.filename === filename);
    if (idx === -1) return res.status(404).json({ error: 'Item not found in project' });
    const prev = items[idx];
    let backgroundVal = prev.background;
    if (background === null || background === '') backgroundVal = null;
    else if (background && typeof background === 'object' && background.filename) {
      backgroundVal = {
        filename: background.filename,
        defaultX: parseNum(background.defaultX, 0, parseFloat),
        defaultY: parseNum(background.defaultY, 0, parseFloat),
        defaultZ: parseInt(background.defaultZ, 10) || 0
      };
    }
    const fc = frameCount !== undefined && frameCount !== null && frameCount !== '' ? parseInt(String(frameCount), 10) : prev.frameCount;
    const hasFrames = (fc > 1);
    const frameW = hasFrames && spriteSheetFrameW != null && spriteSheetFrameW !== '' ? Math.max(1, parseInt(spriteSheetFrameW, 10) || 0) : (prev.spriteSheetFrameW || 0);
    const frameH = hasFrames && spriteSheetFrameH != null && spriteSheetFrameH !== '' ? Math.max(1, parseInt(spriteSheetFrameH, 10) || 0) : (prev.spriteSheetFrameH || 0);
    items[idx] = {
      ...prev,
      name: name !== undefined && name !== null ? name : prev.name,
      slotId: slotId !== undefined && slotId !== null ? slotId : prev.slotId,
      tags: tags !== undefined ? (Array.isArray(tags) ? tags : []) : prev.tags,
      defaultX: parseNum(defaultX, prev.defaultX, parseFloat),
      defaultY: parseNum(defaultY, prev.defaultY, parseFloat),
      defaultZ: parseNum(defaultZ, prev.defaultZ, (v) => parseInt(v, 10)),
      bundleParts: bundleParts !== undefined ? (Array.isArray(bundleParts) ? bundleParts : prev.bundleParts) : prev.bundleParts,
      background: backgroundVal,
      frameCount: hasFrames ? fc : (prev.frameCount || 1),
      spriteSheetFrameW: hasFrames ? frameW : (prev.spriteSheetFrameW || 0),
      spriteSheetFrameH: hasFrames ? frameH : (prev.spriteSheetFrameH || 0)
    };
    saveProjects(projects);
    res.json(items[idx]);
  } catch (e) {
    console.error('Error updating project item:', e);
    res.status(500).json({ error: 'Failed to update project item' });
  }
});

app.delete('/api/projects/:id/items/:filename', (req, res) => {
  try {
    const { id, filename } = req.params;
    const projects = loadProjects();
    const project = projects[id];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.scrappedAt) return res.status(400).json({ error: 'Project was scrapped' });
    if (project.released) return res.status(400).json({ error: 'Project already released' });
    const items = Array.isArray(project.items) ? project.items : [];
    const idx = items.findIndex(i => i.filename === filename);
    if (idx === -1) return res.status(404).json({ error: 'Item not found in project' });
    project.items.splice(idx, 1);
    saveProjects(projects);
    res.json({ success: true });
  } catch (e) {
    console.error('Error deleting project item:', e);
    res.status(500).json({ error: 'Failed to delete project item' });
  }
});

app.post('/api/projects/:id/release', (req, res) => {
  try {
    const { id } = req.params;
    const projects = loadProjects();
    const project = projects[id];
    if (!project) return res.status(404).json({ error: 'Project not found' });
    if (project.scrappedAt) return res.status(400).json({ error: 'Project was scrapped' });
    if (project.released) return res.status(400).json({ error: 'Project already released' });
    const items = Array.isArray(project.items) ? project.items : [];
    const mainItems = JSON.parse(fs.readFileSync(itemsFile, 'utf8'));
    const setAsSet = items.length > 1;
    const setId = id;
    const setName = (project.name || 'Set').replace(/\s+/g, ' ').trim() || 'Set';
    items.forEach(it => {
      const copy = { ...it };
      if (!copy.dateAdded) copy.dateAdded = new Date().toISOString();
      if (setAsSet) {
        copy.tags = [...(Array.isArray(copy.tags) ? copy.tags : [])];
        if (!copy.tags.some(t => typeof t === 'string' && t.startsWith('set-id:'))) copy.tags.push('set-id:' + setId);
        if (!copy.tags.some(t => typeof t === 'string' && t.startsWith('set-name:'))) copy.tags.push('set-name:' + setName);
        if (!copy.tags.some(t => typeof t === 'string' && t.startsWith('set:'))) copy.tags.push('set:' + setName);
      }
      mainItems.push(copy);
    });
    fs.writeFileSync(itemsFile, JSON.stringify(mainItems, null, 2));
    project.released = true;
    saveProjects(projects);
    res.json({ success: true, released: items.length, setAsSet: setAsSet });
  } catch (e) {
    console.error('Error releasing project:', e);
    res.status(500).json({ error: 'Failed to release project' });
  }
});

app.get('/api/equipped-items', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId != null) {
      const profile = getOrCreateProfile(userId);
      const equipped = profile.equipped && typeof profile.equipped === 'object'
        ? profile.equipped
        : JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS));
      return res.json(equipped);
    }
    const equipped = JSON.parse(fs.readFileSync(equippedFile, 'utf8'));
    res.json(equipped);
  } catch (error) {
    console.error('Error fetching equipped items:', error);
    res.status(500).json({ error: 'Failed to fetch equipped items' });
  }
});

app.post('/api/equipped-items', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId != null) {
      const key = String(userId);
      withLock('profiles', () => {
        const profiles = loadProfiles();
        if (!profiles[key]) profiles[key] = { currency: 1000, currency2: 0, currency3: 50, purchased: [], equipped: JSON.parse(JSON.stringify(DEFAULT_EQUIPPED_SLOTS)) };
        profiles[key].equipped = req.body;
        saveProfiles(profiles);
      });
      return res.json({ success: true });
    }
    fs.writeFileSync(equippedFile, JSON.stringify(req.body, null, 2));
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving equipped items:', error);
    res.status(500).json({ error: 'Failed to save equipped items' });
  }
});

app.get('/api/outfits', (req, res) => {
  try {
    const userId = req.session && req.session.userId;
    if (userId == null) {
      return res.status(401).json({ error: 'Not logged in' });
    }
    const byUser = loadOutfitsByUser();
    const list = byUser[String(userId)];
    res.json(Array.isArray(list) ? list : []);
  } catch (error) {
    console.error('Error fetching outfits:', error);
    res.status(500).json({ error: 'Failed to fetch outfits' });
  }
});

/** Get another user's outfits (for forum hover card full avatar). Returns same shape as GET /api/outfits. */
app.get('/api/users/:id/outfits', (req, res) => {
  try {
    const targetUserId = req.params.id;
    const byUser = loadOutfitsByUser();
    const list = (targetUserId != null && byUser[String(targetUserId)]) ? byUser[String(targetUserId)] : [];
    res.json(Array.isArray(list) ? list : []);
  } catch (error) {
    console.error('Error fetching user outfits:', error);
    res.status(500).json({ error: 'Failed to fetch outfits' });
  }
});

const outfitUploadMulter = multer({ storage: multer.memoryStorage() });

app.post('/api/outfits', (req, res, next) => {
  const isMultipart = req.is('multipart/form-data');
  if (isMultipart) {
    outfitUploadMulter.fields([
      { name: 'merged', maxCount: 1 },
      { name: 'name', maxCount: 1 },
      { name: 'items', maxCount: 1 },
      { name: 'mergedFramesW', maxCount: 1 },
      { name: 'mergedFrameDuration', maxCount: 1 }
    ])(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message || 'Upload failed' });
      handlePostOutfits(req, res);
    });
  } else {
    next();
  }
}, (req, res) => {
  handlePostOutfits(req, res);
});

function handlePostOutfits(req, res) {
  try {
    const userId = req.session.userId;
    if (userId == null) {
      return res.status(401).json({ error: 'Login required to save outfits' });
    }
    let name, items, mergedImageUrl, mergedFramesW, mergedFrameDuration;
    if (req.is('multipart/form-data') && req.files) {
      const b = req.body || {};
      const nameVal = b.name != null ? (Array.isArray(b.name) ? b.name[0] : b.name) : '';
      name = (nameVal !== '' && nameVal != null) ? String(nameVal).trim() : '';
      const itemsVal = b.items != null ? (Array.isArray(b.items) ? b.items[0] : b.items) : undefined;
      let itemsStr = undefined;
      if (itemsVal != null) {
        if (typeof itemsVal === 'string') itemsStr = itemsVal;
        else if (Buffer.isBuffer(itemsVal)) itemsStr = itemsVal.toString('utf8');
        else itemsStr = JSON.stringify(itemsVal);
      }
      items = itemsStr ? (() => { try { return JSON.parse(itemsStr); } catch (e) { return null; } })() : null;
      const mergedFile = req.files.merged && req.files.merged[0];
      if (mergedFile && mergedFile.buffer) {
        const filename = userId + '-' + Date.now() + '.png';
        const filepath = path.join(outfitsUploadDir, filename);
        fs.writeFileSync(filepath, mergedFile.buffer);
        mergedImageUrl = '/Uploads/outfits/' + filename;
      }
      mergedFramesW = b.mergedFramesW != null && b.mergedFramesW !== '' ? Math.max(1, parseInt(b.mergedFramesW, 10) || 1) : 1;
      mergedFrameDuration = b.mergedFrameDuration != null && b.mergedFrameDuration !== '' ? Math.max(50, parseInt(b.mergedFrameDuration, 10) || 150) : 150;
    } else {
      name = req.body && (req.body.name || '').trim();
      items = req.body && req.body.items;
      mergedFramesW = req.body && (req.body.mergedFramesW != null && req.body.mergedFramesW !== '') ? Math.max(1, parseInt(req.body.mergedFramesW, 10) || 1) : 1;
      mergedFrameDuration = req.body && (req.body.mergedFrameDuration != null && req.body.mergedFrameDuration !== '') ? Math.max(50, parseInt(req.body.mergedFrameDuration, 10) || 150) : 150;
      const mergedBase64 = req.body && req.body.merged;
      if (mergedBase64 && typeof mergedBase64 === 'string') {
        try {
          const buffer = Buffer.from(mergedBase64, 'base64');
          if (buffer.length > 0) {
            const filename = userId + '-' + Date.now() + '.png';
            const filepath = path.join(outfitsUploadDir, filename);
            fs.writeFileSync(filepath, buffer);
            mergedImageUrl = '/Uploads/outfits/' + filename;
          }
        } catch (e) {
          console.error('Outfit merged base64 decode error:', e.message);
        }
      }
    }
    if (!name) {
      return res.status(400).json({ error: 'Outfit name is required' });
    }
    if (items == null || typeof items !== 'object') {
      return res.status(400).json({ error: 'Outfit items are required' });
    }
    const namesInUse = getAllNamesInUse();
    if (namesInUse.has(normalizeNameForCheck(name))) {
      return res.status(400).json({ error: 'An outfit, item upload project, or pixel drawing project with this name already exists. Please choose a different name.' });
    }
    const byUser = loadOutfitsByUser();
    const key = String(userId);
    if (!Array.isArray(byUser[key])) byUser[key] = [];
    const outfit = { name, items };
    if (mergedImageUrl) {
      outfit.mergedImageUrl = mergedImageUrl;
      if (mergedFramesW > 1) outfit.mergedFramesW = mergedFramesW;
      outfit.mergedFrameDuration = mergedFrameDuration || 150;
    }
    byUser[key].push(outfit);
    fs.writeFileSync(outfitsFile, JSON.stringify(byUser, null, 2));
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving outfit:', error);
    res.status(500).json({ error: error.message || 'Failed to save outfit' });
  }
}

app.delete('/api/outfits', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) {
      return res.status(401).json({ error: 'Login required to delete outfits' });
    }
    const name = (req.query.name != null ? String(req.query.name) : (req.body && req.body.name != null ? String(req.body.name) : '')).trim();
    if (!name) {
      return res.status(400).json({ error: 'Outfit name is required' });
    }
    const byUser = loadOutfitsByUser();
    const key = String(userId);
    if (!Array.isArray(byUser[key])) {
      return res.status(404).json({ error: 'Outfit not found' });
    }
    const idx = byUser[key].findIndex(o => o && String(o.name).trim() === name);
    if (idx === -1) {
      return res.status(404).json({ error: 'Outfit not found' });
    }
    byUser[key].splice(idx, 1);
    fs.writeFileSync(outfitsFile, JSON.stringify(byUser, null, 2));
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting outfit:', error);
    res.status(500).json({ error: error.message || 'Failed to delete outfit' });
  }
});

// ----- Messages (inbox, send, mark read) -----
function loadMessages() {
  try {
    if (!fs.existsSync(messagesFile)) return [];
    const data = fs.readFileSync(messagesFile, 'utf8');
    const list = JSON.parse(data);
    return Array.isArray(list) ? list : [];
  } catch (e) { return []; }
}
function saveMessages(list) {
  fs.writeFileSync(messagesFile, JSON.stringify(list, null, 2), 'utf8');
}

app.get('/api/messages/unread-count', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const list = loadMessages();
    const mine = list.filter(m => String(m.toUserId) === String(userId) && !m.read);
    res.json({ unreadCount: mine.length });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});

app.get('/api/messages', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const list = loadMessages();
    const mine = list.filter(m => String(m.toUserId) === String(userId));
    mine.sort((a, b) => (new Date(b.createdAt) || 0) - (new Date(a.createdAt) || 0));
    const unreadCount = mine.filter(m => !m.read).length;
    res.json({ messages: mine, unreadCount });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/messages', (req, res) => {
  try {
    const userId = req.session.userId;
    const username = req.session.user || null;
    if (userId == null || !username) return res.status(401).json({ error: 'Not logged in' });
    const { toUserId, body } = req.body || {};
    const toId = toUserId != null ? String(toUserId) : null;
    const text = (body || '').toString().trim();
    if (!toId || !text) return res.status(400).json({ error: 'Recipient and message body required' });
    const users = getUsersForAuth();
    const toUser = users.find(u => String(u.id) === toId);
    if (!toUser) return res.status(400).json({ error: 'Recipient not found' });
    if (toId === String(userId)) return res.status(400).json({ error: 'Cannot message yourself' });
    const list = loadMessages();
    const id = 'msg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 9);
    list.push({
      id,
      fromUserId: userId,
      fromUsername: username,
      toUserId: toId,
      body: text,
      createdAt: new Date().toISOString(),
      read: false
    });
    saveMessages(list);
    res.json({ success: true, id });
  } catch (e) {
    console.error('Error sending message:', e);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.patch('/api/messages/:id/read', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const { id } = req.params;
    const list = loadMessages();
    const msg = list.find(m => m.id === id && String(m.toUserId) === String(userId));
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    msg.read = true;
    saveMessages(list);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

// ----- Forum (server-side) -----
function loadForumTopics() {
  try {
    const data = fs.readFileSync(forumTopicsFile, 'utf8');
    const list = JSON.parse(data);
    return Array.isArray(list) ? list : [];
  } catch (e) { return []; }
}
function saveForumTopics(topics) {
  fs.writeFileSync(forumTopicsFile, JSON.stringify(topics, null, 2));
}
function loadForumPosts() {
  try {
    const data = fs.readFileSync(forumPostsFile, 'utf8');
    const list = JSON.parse(data);
    return Array.isArray(list) ? list : [];
  } catch (e) { return []; }
}
function saveForumPosts(posts) {
  fs.writeFileSync(forumPostsFile, JSON.stringify(posts, null, 2));
}

const FORUM_BUILTIN_EMOTES = {
  ':smile:': '😀', ':sad:': '😢', ':heart:': '❤️', ':laugh:': '😂', ':cool:': '😎',
  ':wink:': '😉', ':angry:': '😠', ':think:': '🤔', ':fire:': '🔥', ':star:': '⭐',
  ':thumbsup:': '👍', ':thumbsdown:': '👎', ':clap:': '👏', ':wave:': '👋'
};

function loadForumEmotes() {
  try {
    if (fs.existsSync(forumEmotesFile)) {
      const data = JSON.parse(fs.readFileSync(forumEmotesFile, 'utf8'));
      return Array.isArray(data.custom) ? data.custom : [];
    }
  } catch (e) {
    console.error('loadForumEmotes failed:', e.message || e);
  }
  return [];
}

function saveForumEmotes(custom) {
  fs.writeFileSync(forumEmotesFile, JSON.stringify({ custom: custom || [] }, null, 2));
}

function loadForumGifs() {
  try {
    if (fs.existsSync(forumGifsFile)) {
      const data = JSON.parse(fs.readFileSync(forumGifsFile, 'utf8'));
      return Array.isArray(data.custom) ? data.custom : [];
    }
  } catch (e) { /* ignore */ }
  return [];
}

function saveForumGifs(custom) {
  fs.writeFileSync(forumGifsFile, JSON.stringify({ custom: custom || [] }, null, 2));
}

app.post('/api/forum/upload', requireLogin, upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const mimetype = (req.file.mimetype || '').toLowerCase();
    const isImage = /^image\//.test(mimetype);
    const isVideo = /^video\//.test(mimetype);
    if (!isImage && !isVideo) return res.status(400).json({ error: 'Only images and videos are allowed' });
    const url = '/Uploads/' + path.basename(req.file.path);
    res.json({ url, type: isImage ? 'image' : 'video' });
  } catch (e) {
    console.error('Forum upload error:', e);
    res.status(500).json({ error: 'Failed to upload' });
  }
});

app.get('/api/forum/emotes', (req, res) => {
  try {
    const custom = loadForumEmotes();
    res.json({ builtin: FORUM_BUILTIN_EMOTES, custom });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load emoticons' });
  }
});

const EMOTE_COST_GEMS = 10;

app.post('/api/forum/emotes', requireLogin, upload.single('image'), (req, res) => {
  try {
    const roles = getRoles(req.session.userId);
    if (!roles.includes('admin') && !roles.includes('moderator')) return res.status(403).json({ error: 'Admin or moderator required to add custom emoticons' });
    ensureUserInventory(req);
    const gems = req.session.currency2 != null ? req.session.currency2 : 0;
    if (gems < EMOTE_COST_GEMS) return res.status(400).json({ error: 'Not enough candies. Uploading an emoticon costs ' + EMOTE_COST_GEMS + ' candies.', required: EMOTE_COST_GEMS, currency2: gems });
    const shortcode = (req.body && req.body.shortcode) ? String(req.body.shortcode).trim() : '';
    if (!shortcode || !/^:[a-zA-Z0-9_]+:$/.test(shortcode)) return res.status(400).json({ error: 'Shortcode must be like :name:' });
    if (!req.file) return res.status(400).json({ error: 'No image uploaded' });
    const mimetype = (req.file.mimetype || '').toLowerCase();
    if (!/^image\//.test(mimetype)) return res.status(400).json({ error: 'Only images allowed for emoticons' });
    const url = '/Uploads/' + path.basename(req.file.path);
    const custom = loadForumEmotes();
    if (custom.some(e => e.shortcode === shortcode)) return res.status(400).json({ error: 'That shortcode already exists' });
    custom.push({ shortcode, url });
    saveForumEmotes(custom);
    req.session.currency2 = gems - EMOTE_COST_GEMS;
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, shortcode, url, currency2: req.session.currency2 });
  } catch (e) {
    console.error('Add emote error:', e);
    res.status(500).json({ error: 'Failed to add emoticon' });
  }
});

const GIF_COST_GEMS = 10;

app.get('/api/forum/gifs', (req, res) => {
  try {
    const custom = loadForumGifs();
    res.json({ custom });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load gifs' });
  }
});

const GIPHY_API_KEY = process.env.GIPHY_API_KEY || 'dc6zaTOxFJmzC';
app.get('/api/forum/giphy-search', (req, res) => {
  const q = (req.query.q || '').toString().trim();
  if (!q) return res.status(400).json({ error: 'Query required' });
  const url = 'https://api.giphy.com/v1/gifs/search?api_key=' + encodeURIComponent(GIPHY_API_KEY) + '&q=' + encodeURIComponent(q) + '&limit=20&rating=g';
  https.get(url, (giphyRes) => {
    let body = '';
    giphyRes.on('data', (chunk) => { body += chunk; });
    giphyRes.on('end', () => {
      try {
        const data = JSON.parse(body);
        res.json(data);
      } catch (e) {
        res.status(502).json({ error: 'Invalid response from GIF search' });
      }
    });
  }).on('error', (e) => {
    console.error('Giphy proxy error:', e);
    res.status(502).json({ error: 'GIF search failed' });
  });
});

app.post('/api/forum/gifs', requireLogin, upload.single('gif'), (req, res) => {
  try {
    const roles = getRoles(req.session.userId);
    if (!roles.includes('admin') && !roles.includes('moderator') && !roles.includes('membership')) {
      return res.status(403).json({ error: 'Exclusive membership (or admin/moderator) required to upload GIFs' });
    }
    ensureUserInventory(req);
    const gems = req.session.currency2 != null ? req.session.currency2 : 0;
    if (gems < GIF_COST_GEMS) return res.status(400).json({ error: 'Not enough candies. Uploading a GIF costs ' + GIF_COST_GEMS + ' candies.', required: GIF_COST_GEMS, currency2: gems });
    const shortcode = (req.body && req.body.shortcode) ? String(req.body.shortcode).trim() : '';
    if (!shortcode || !/^:[a-zA-Z0-9_]+:$/.test(shortcode)) return res.status(400).json({ error: 'Shortcode must be like :name:' });
    if (!req.file) return res.status(400).json({ error: 'No GIF uploaded' });
    const mimetype = (req.file.mimetype || '').toLowerCase();
    if (mimetype !== 'image/gif') return res.status(400).json({ error: 'Only GIF images allowed' });
    const url = '/Uploads/' + path.basename(req.file.path);
    const custom = loadForumGifs();
    if (custom.some(g => g.shortcode === shortcode)) return res.status(400).json({ error: 'That shortcode already exists' });
    custom.push({ shortcode, url });
    saveForumGifs(custom);
    req.session.currency2 = gems - GIF_COST_GEMS;
    if (req.session.userId != null) {
      saveUserInventoryToProfile(req.session.userId, req.session.currency, req.session.purchased, req.session.currency2, req.session.currency3);
    }
    res.json({ success: true, shortcode, url, currency2: req.session.currency2 });
  } catch (e) {
    console.error('Add GIF error:', e);
    res.status(500).json({ error: 'Failed to add GIF' });
  }
});

app.get('/api/forum/topics', (req, res) => {
  try {
    const topics = loadForumTopics();
    const posts = loadForumPosts();
    const profiles = loadProfiles();
    const enriched = topics.map(t => {
      const copy = { ...t };
      copy.authorRoles = getRoles(t.authorId);
      copy.locked = !!t.locked;
      if (!copy.createdAt) {
        const initialPost = posts.find(p => p.topicId === t.id && p.parentId == null);
        copy.createdAt = initialPost ? initialPost.timestamp : (t.latestPost || '—');
      }
      if (!copy.lastCommenter) {
        const topicPosts = posts.filter(p => p.topicId === t.id);
        const byTime = topicPosts.slice().sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
        copy.lastCommenter = byTime.length ? (byTime[0].username || '—') : (t.author || '—');
      }
      return copy;
    });
    res.json(enriched);
  } catch (error) {
    console.error('Error fetching forum topics:', error);
    res.status(500).json({ error: 'Failed to fetch topics' });
  }
});

app.get('/api/forum/posts', (req, res) => {
  try {
    const topicId = req.query.topicId;
    const posts = loadForumPosts();
    const filtered = topicId ? posts.filter(p => String(p.topicId || '') === String(topicId)) : posts;
    const profiles = loadProfiles();
    const enriched = filtered.map(p => {
      const copy = { ...p };
      const profileKey = p.userId != null ? String(p.userId) : null;
      const prof = profileKey && profiles[profileKey] ? profiles[profileKey] : (profileKey ? getOrCreateProfile(p.userId) : null);
      if (p.userId != null && prof && prof.profilePictureUrl) {
        copy.profilePictureUrl = prof.profilePictureUrl;
      }
      copy.authorRoles = getRoles(p.userId);
      let ap = null;
      if (p.userId != null) {
        try {
          const profileToUse = prof || getOrCreateProfile(p.userId);
          ap = {
            userId: p.userId,
            username: p.username || '',
            bio: (profileToUse && profileToUse.bio != null) ? profileToUse.bio : '',
            forumPostHeader: (profileToUse && typeof profileToUse.forumPostHeader === 'string') ? profileToUse.forumPostHeader.slice(0, 200) : '',
            forumHeaderGraphic: (profileToUse && typeof profileToUse.forumHeaderGraphic === 'string' && profileToUse.forumHeaderGraphic.trim()) ? profileToUse.forumHeaderGraphic.trim().slice(0, 500) : '',
            forumPostColor: (profileToUse && typeof profileToUse.forumPostColor === 'string' && /^#[0-9A-Fa-f]{3,6}$/.test(profileToUse.forumPostColor)) ? profileToUse.forumPostColor : '',
            forumNameColor: (profileToUse && typeof profileToUse.forumNameColor === 'string' && /^#[0-9A-Fa-f]{3,6}$/.test(profileToUse.forumNameColor)) ? profileToUse.forumNameColor : '',
            forumNameFont: (profileToUse && typeof profileToUse.forumNameFont === 'string') ? profileToUse.forumNameFont.slice(0, 80) : '',
            forumBlinkies: (profileToUse && Array.isArray(profileToUse.forumBlinkies)) ? profileToUse.forumBlinkies.filter(u => typeof u === 'string' && u.length > 0 && u.length < 500).slice(0, 10) : [],
            hoverCardBgOpacity: (profileToUse && typeof profileToUse.hoverCardBgOpacity === 'number') ? profileToUse.hoverCardBgOpacity : null,
            hoverCardBlurPx: (profileToUse && typeof profileToUse.hoverCardBlurPx === 'number') ? profileToUse.hoverCardBlurPx : null,
            hoverCardBorderOpacity: (profileToUse && typeof profileToUse.hoverCardBorderOpacity === 'number') ? profileToUse.hoverCardBorderOpacity : null,
            hoverCardAvatarBgOpacity: (profileToUse && typeof profileToUse.hoverCardAvatarBgOpacity === 'number') ? profileToUse.hoverCardAvatarBgOpacity : null,
            hoverCardAvatarBlurPx: (profileToUse && typeof profileToUse.hoverCardAvatarBlurPx === 'number') ? profileToUse.hoverCardAvatarBlurPx : null,
            hoverCardFoil: (function () {
              let foil = getHoverCardFoilForUser(p.userId);
              if (foil === undefined && profileToUse && profileToUse.hoverCardFoil) {
                foil = profileToUse.hoverCardFoil;
                if (typeof foil === 'string') { try { foil = JSON.parse(foil); } catch (e) { foil = null; } }
              }
              return (foil != null && typeof foil === 'object' && !Array.isArray(foil)) ? foil : null;
            })(),
            hoverCardSignature: (profileToUse && typeof profileToUse.hoverCardSignature === 'string') ? profileToUse.hoverCardSignature.trim().slice(0, 120) : '',
            hoverCardSignatureImage: (profileToUse && typeof profileToUse.hoverCardSignatureImage === 'string' && profileToUse.hoverCardSignatureImage.indexOf('data:image/') === 0) ? profileToUse.hoverCardSignatureImage.slice(0, 100000) : '',
            hoverCardStickers: (profileToUse && Array.isArray(profileToUse.hoverCardStickers)) ? profileToUse.hoverCardStickers.filter(s => s && typeof s.id === 'string' && typeof s.x === 'number' && typeof s.y === 'number').slice(0, 12) : []
          };
        } catch (e) {
          ap = { userId: p.userId, username: p.username || '', bio: '' };
        }
      }
      copy.authorProfile = ap;
      return copy;
    });
    res.json(enriched);
  } catch (error) {
    console.error('Error fetching forum posts:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

app.post('/api/forum/topics', (req, res) => {
  try {
    const username = req.session.user || 'Guest';
    const userId = req.session.userId != null ? req.session.userId : null;
    const { title, category, postContent, attachments } = req.body;
    const t = (title || '').toString().trim();
    const c = (category || '').toString().trim();
    const content = (postContent || '').toString().trim();
    if (!t || !c || !content) {
      return res.status(400).json({ error: 'Title, category, and post content required' });
    }
    const topicId = Date.now().toString();
    const postId = (Date.now() + 1).toString();
    const now = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
    const topics = loadForumTopics();
    const newTopic = {
      id: topicId,
      topic: t,
      category: c,
      posts: 1,
      author: username,
      authorId: userId,
      createdAt: now,
      latestPost: now,
      lastCommenter: username,
      locked: false
    };
    topics.unshift(newTopic);
    saveForumTopics(topics);
    const outfitItems = req.body.outfitItems || null;
    const att = Array.isArray(attachments) ? attachments.filter(a => a && (a.type === 'image' || a.type === 'video') && typeof a.url === 'string' && a.url) : [];
    const firstPost = {
      id: postId,
      topicId,
      parentId: null,
      username,
      userId,
      message: content,
      banner: '',
      bannerText: '',
      timestamp: now,
      avatar: 'https://p4vl0v.neocities.org/dfer5erer.png',
      outfitItems,
      attachments: att.length ? att : undefined,
      replies: []
    };
    const posts = loadForumPosts();
    posts.unshift(firstPost);
    saveForumPosts(posts);
    res.json({ success: true, topicId, postId });
  } catch (error) {
    console.error('Error creating forum topic:', error);
    res.status(500).json({ error: 'Failed to create topic' });
  }
});

app.post('/api/forum/posts', (req, res) => {
  try {
    const username = req.session.user || 'Guest';
    const userId = req.session.userId != null ? req.session.userId : null;
    const { topicId, parentId, message, banner, bannerText, outfitItems, attachments } = req.body;
    const content = (message || '').toString().trim();
    if (!content) return res.status(400).json({ error: 'Message required' });
    const topicIdStr = topicId != null ? String(topicId) : '';
    const topics = loadForumTopics();
    const topic = topics.find(t => String(t.id) === topicIdStr);
    if (topic && topic.locked) {
      const roles = getRoles(userId);
      const canPostInLocked = roles.includes('admin') || roles.includes('moderator');
      if (!canPostInLocked) return res.status(403).json({ error: 'This thread is locked' });
    }
    const postId = Date.now().toString();
    const now = new Date().toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
    const att = Array.isArray(attachments) ? attachments.filter(a => a && (a.type === 'image' || a.type === 'video') && typeof a.url === 'string' && a.url) : [];
    const newPost = {
      id: postId,
      topicId: topicIdStr || null,
      parentId: null,
      username,
      userId,
      message: content,
      banner: banner || '',
      bannerText: bannerText || '',
      timestamp: now,
      avatar: 'https://p4vl0v.neocities.org/dfer5erer.png',
      outfitItems: outfitItems || null,
      attachments: att.length ? att : undefined,
      replies: []
    };
    const posts = loadForumPosts();
    posts.push(newPost);
    if (topicIdStr) {
      const firstPost = posts.find(p => String(p.topicId || '') === topicIdStr && (p.parentId == null || p.parentId === '') && p.id !== postId);
      if (firstPost) {
        firstPost.replies = firstPost.replies || [];
        firstPost.replies.push(postId);
      }
      const topics = loadForumTopics();
      const topic = topics.find(t => String(t.id) === topicIdStr);
      if (topic) {
        topic.posts = (topic.posts || 0) + 1;
        topic.latestPost = now;
        topic.lastCommenter = username;
        saveForumTopics(topics);
      }
    }
    saveForumPosts(posts);
    res.json({ success: true, postId });
  } catch (error) {
    console.error('Error creating forum post:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

/** Edit forum/topic (title, category, optional initial post) — author only. */
app.patch('/api/forum/topics/:topicId', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const topicId = (req.params.topicId || '').toString();
    if (!topicId) return res.status(400).json({ error: 'Topic ID required' });
    const topics = loadForumTopics();
    const topic = topics.find(t => t.id === topicId);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });
    if (topic.authorId != null && String(topic.authorId) !== String(userId)) return res.status(403).json({ error: 'Only the author can edit this forum' });
    const { title, category, postContent } = req.body;
    let changed = false;
    if (title !== undefined) {
      const t = (title || '').toString().trim();
      if (t) { topic.topic = t; changed = true; }
    }
    if (category !== undefined) {
      const c = (category || '').toString().trim();
      if (c) { topic.category = c; changed = true; }
    }
    if (changed) saveForumTopics(topics);
    if (postContent !== undefined || req.body.attachments !== undefined) {
      const posts = loadForumPosts();
      const firstPost = posts.find(p => p.topicId === topicId && (p.parentId == null || p.parentId === ''));
      if (firstPost && (firstPost.userId == null || String(firstPost.userId) === String(userId))) {
        if (postContent !== undefined) {
          const content = (postContent || '').toString().trim();
          if (content) firstPost.message = content;
        }
        if (req.body.attachments !== undefined) {
          const att = Array.isArray(req.body.attachments) ? req.body.attachments.filter(a => a && (a.type === 'image' || a.type === 'video') && typeof a.url === 'string' && a.url) : [];
          firstPost.attachments = att.length ? att : undefined;
        }
        saveForumPosts(posts);
      }
    }
    res.json({ success: true, topic: { id: topic.id, topic: topic.topic, category: topic.category } });
  } catch (error) {
    console.error('Error editing forum topic:', error);
    res.status(500).json({ error: 'Failed to edit topic' });
  }
});

/** Edit a post (message, banner, bannerText) — author only. */
app.patch('/api/forum/posts/:postId', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const postId = (req.params.postId || '').toString();
    if (!postId) return res.status(400).json({ error: 'Post ID required' });
    const posts = loadForumPosts();
    const post = posts.find(p => String(p.id) === String(postId));
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (post.userId == null || String(post.userId) !== String(userId)) return res.status(403).json({ error: 'Only the author can edit this comment' });
    const { message, banner, bannerText, attachments } = req.body;
    if (message !== undefined) {
      const content = (message || '').toString().trim();
      post.message = content;
    }
    if (banner !== undefined) post.banner = (banner || '').toString();
    if (bannerText !== undefined) post.bannerText = (bannerText || '').toString();
    if (attachments !== undefined) {
      const att = Array.isArray(attachments) ? attachments.filter(a => a && (a.type === 'image' || a.type === 'video') && typeof a.url === 'string' && a.url) : [];
      post.attachments = att.length ? att : undefined;
    }
    saveForumPosts(posts);
    res.json({ success: true, post: { id: post.id, message: post.message, banner: post.banner, bannerText: post.bannerText } });
  } catch (error) {
    console.error('Error editing forum post:', error);
    res.status(500).json({ error: 'Failed to edit post' });
  }
});

/** Delete a post (comment) — author only; cannot delete the first post of a topic. */
app.delete('/api/forum/posts/:postId', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    const postId = (req.params.postId || '').toString();
    if (!postId) return res.status(400).json({ error: 'Post ID required' });
    const posts = loadForumPosts();
    const post = posts.find(p => String(p.id) === String(postId));
    if (!post) return res.status(404).json({ error: 'Post not found' });
    if (post.userId == null || String(post.userId) !== String(userId)) return res.status(403).json({ error: 'Only the author can delete this comment' });
    const topicIdStr = (post.topicId || '').toString();
    const firstPost = topicIdStr ? posts.find(p => String(p.topicId) === topicIdStr && (p.parentId == null || p.parentId === '') && String(p.id) !== String(postId)) : null;
    if (!firstPost) return res.status(400).json({ error: 'Cannot delete the first post of a topic' });
    const idx = posts.findIndex(p => String(p.id) === String(postId));
    if (idx !== -1) posts.splice(idx, 1);
    if (firstPost.replies && Array.isArray(firstPost.replies)) {
      firstPost.replies = firstPost.replies.filter(id => String(id) !== String(postId));
    }
    const topics = loadForumTopics();
    const topic = topics.find(t => String(t.id) === topicIdStr);
    if (topic && topic.posts > 0) {
      topic.posts = Math.max(0, topic.posts - 1);
      saveForumTopics(topics);
    }
    saveForumPosts(posts);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting forum post:', error);
    res.status(500).json({ error: 'Failed to delete post' });
  }
});

app.patch('/api/forum/topics/:topicId/lock', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canLockForum(userId)) return res.status(403).json({ error: 'Admin or moderator required to lock threads' });
    const topicId = (req.params.topicId || '').toString();
    if (!topicId) return res.status(400).json({ error: 'Topic ID required' });
    const topics = loadForumTopics();
    const topic = topics.find(t => t.id === topicId);
    if (!topic) return res.status(404).json({ error: 'Topic not found' });
    const locked = req.body.locked === true || req.body.locked === 'true';
    topic.locked = !!locked;
    saveForumTopics(topics);
    res.json({ success: true, locked: topic.locked });
  } catch (error) {
    console.error('Error locking forum topic:', error);
    res.status(500).json({ error: 'Failed to update lock' });
  }
});

app.delete('/api/forum/topics/:topicId', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canDeleteForum(userId)) return res.status(403).json({ error: 'Admin or moderator required to delete forums' });
    const topicId = (req.params.topicId || '').toString();
    if (!topicId) return res.status(400).json({ error: 'Topic ID required' });
    const topics = loadForumTopics();
    const idx = topics.findIndex(t => t.id === topicId);
    if (idx === -1) return res.status(404).json({ error: 'Topic not found' });
    topics.splice(idx, 1);
    saveForumTopics(topics);
    const posts = loadForumPosts();
    const filtered = posts.filter(p => p.topicId !== topicId);
    saveForumPosts(filtered);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting forum topic:', error);
    res.status(500).json({ error: 'Failed to delete topic' });
  }
});

// ——— Reports ———
const REPORT_CATEGORIES = [
  'Spam',
  'Harassment/Bullying',
  'Toxic behaviour',
  'Hate speech/Bigotry',
  'Threats/Violence',
  'Illegal content',
  'NSFW',
  'Others'
];

function loadReports() {
  try {
    if (fs.existsSync(reportsFile)) {
      const data = fs.readFileSync(reportsFile, 'utf8');
      const list = JSON.parse(data);
      return Array.isArray(list) ? list : [];
    }
  } catch (e) {
    console.error('loadReports failed:', e.message || e);
  }
  return [];
}
function saveReports(reports) {
  writeAtomic(reportsFile, JSON.stringify(reports, null, 2));
}

/** List report categories (for UI). */
app.get('/api/reports/categories', (req, res) => {
  res.json(REPORT_CATEGORIES);
});

/** Create a report (logged-in user). */
app.post('/api/reports', requireLogin, (req, res) => {
  try {
    const userId = req.session.userId;
    const username = (req.session.user || '').toString();
    const { targetType, targetId, topicId, category, reason } = req.body;
    const type = (targetType || '').toString();
    const id = (targetId || '').toString();
    if (!type || !id) return res.status(400).json({ error: 'targetType and targetId required' });
    if (type !== 'forum_post' && type !== 'user' && type !== 'forum_topic') return res.status(400).json({ error: 'targetType must be forum_post, user, or forum_topic' });
    const categoryVal = (category || '').toString().trim();
    if (!REPORT_CATEGORIES.includes(categoryVal)) return res.status(400).json({ error: 'Valid category required. Use one of: ' + REPORT_CATEGORIES.join(', ') });
    const reportId = Date.now().toString();
    const now = new Date().toISOString();
    const report = {
      id: reportId,
      reporterId: userId,
      reporterUsername: username,
      targetType: type,
      targetId: id,
      topicId: topicId != null ? String(topicId) : null,
      category: categoryVal,
      reason: (reason || '').toString().trim() || null,
      status: 'open',
      createdAt: now
    };
    withLock('reports', () => {
      const reports = loadReports();
      reports.unshift(report);
      saveReports(reports);
    });
    res.status(201).json({ success: true, id: reportId });
  } catch (error) {
    console.error('Error creating report:', error);
    res.status(500).json({ error: 'Failed to create report' });
  }
});

/** List reports (admin or moderator). */
app.get('/api/reports', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canViewReports(userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const reports = loadReports();
    res.json(reports);
  } catch (error) {
    console.error('Error listing reports:', error);
    res.status(500).json({ error: 'Failed to list reports' });
  }
});

/** Update report status (admin or moderator). */
app.patch('/api/reports/:id', (req, res) => {
  try {
    const userId = req.session.userId;
    if (userId == null) return res.status(401).json({ error: 'Not logged in' });
    if (!canViewReports(userId)) return res.status(403).json({ error: 'Admin or moderator required' });
    const reportId = (req.params.id || '').toString();
    const { status } = req.body;
    const newStatus = (status || '').toString();
    if (!['resolved', 'dismissed'].includes(newStatus)) return res.status(400).json({ error: 'status must be resolved or dismissed' });
    let report;
    withLock('reports', () => {
      const reports = loadReports();
      const idx = reports.findIndex(r => r.id === reportId);
      if (idx === -1) throw new Error('Report not found');
      reports[idx].status = newStatus;
      saveReports(reports);
      report = reports[idx];
    });
    res.json({ success: true, report });
  } catch (error) {
    if (error.message === 'Report not found') return res.status(404).json({ error: 'Report not found' });
    console.error('Error updating report:', error);
    res.status(500).json({ error: 'Failed to update report' });
  }
});

// Global error handler: catch unhandled errors and next(err) from routes
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message || err);
  if (res.headersSent) return next(err);
  const isApi = req.path.startsWith('/api');
  if (isApi) {
    res.status(500).json({ error: 'An error occurred. Please try again.' });
  } else {
    res.status(500).send('Something went wrong. Please try again.');
  }
});

// Start server on all network interfaces
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://192.168.86.249:${port}`);
});