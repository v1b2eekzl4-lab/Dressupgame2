require('dotenv').config();
const fs = require('fs');
const path = require('path');

const KEY = process.env.IMGBB_API_KEY;
const ROOT = path.join(__dirname, '..');
const UPLOADS = path.join(ROOT, 'Uploads');
const CACHE_FILE = path.join(ROOT, '.imgbb-cache.json');
const HOSTED_FILE = path.join(ROOT, 'hosted-uploads.json');
const ITEMS_FILE = path.join(ROOT, 'items.json');
const DELAY_MS = 800;
const MAX_BYTES = 32 * 1024 * 1024;
const MEDIA_DIRS = ['profile-pictures', 'hover-card-stickers', 'dashboard', 'slide-gallery', 'outfits'];
const SKIP_EXT = new Set(['.mp4', '.webm', '.ogg', '.ogv']);

if (!KEY) {
  console.error('IMGBB_API_KEY is missing from .env');
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return fallback;
  }
}

function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach((ent) => {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) out.push(...walkFiles(full));
    else if (ent.isFile()) out.push(full);
  });
  return out;
}

async function uploadToImgBB(filePath, name) {
  const buffer = fs.readFileSync(filePath);
  if (buffer.length > MAX_BYTES) throw new Error('file larger than 32MB');
  const form = new FormData();
  form.append('key', KEY);
  form.append('image', buffer.toString('base64'));
  form.append('name', path.basename(name, path.extname(name)));
  const res = await fetch('https://api.imgbb.com/1/upload', { method: 'POST', body: form });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (_) {
    throw new Error('non-JSON ' + res.status + ' ' + text.slice(0, 160));
  }
  if (!data.success || !data.data || !data.data.url) {
    const msg = data.error ? (data.error.message || JSON.stringify(data.error)) : ('HTTP ' + res.status);
    const retry = res.status === 429 || res.status >= 500 || /rate limit/i.test(String(msg));
    throw Object.assign(new Error(msg), { retry });
  }
  if (res.status === 429) throw Object.assign(new Error('rate limited'), { retry: true });
  return data.data.url;
}

async function uploadWithRetry(filePath, name) {
  let lastErr;
  for (let attempt = 1; attempt <= 6; attempt++) {
    try {
      return await uploadToImgBB(filePath, name);
    } catch (err) {
      lastErr = err;
      console.warn('[media] retry', attempt, name, err.message);
      await sleep(err.retry ? 15000 * attempt : 1200 * attempt);
    }
  }
  throw lastErr;
}

function publicPathFor(absPath) {
  const rel = path.relative(UPLOADS, absPath).replace(/\\/g, '/');
  return '/Uploads/' + rel;
}

(async function main() {
  const cache = loadJson(CACHE_FILE, {});
  const hosted = loadJson(HOSTED_FILE, {});
  const items = loadJson(ITEMS_FILE, []);
  if (Array.isArray(items)) {
    items.forEach((item) => {
      if (item && item.filename && item.imageUrl) {
        hosted['/Uploads/' + item.filename] = item.imageUrl;
      }
    });
  }

  const files = [];
  MEDIA_DIRS.forEach((dir) => {
    walkFiles(path.join(UPLOADS, dir)).forEach((full) => files.push(full));
  });
  ['forumEmotes.json', 'forumGifs.json'].forEach((name) => {
    const list = loadJson(path.join(ROOT, name), []);
    (Array.isArray(list) ? list : []).forEach((entry) => {
      const url = entry && entry.url;
      if (typeof url !== 'string' || !url.startsWith('/Uploads/')) return;
      const full = path.join(UPLOADS, url.replace('/Uploads/', ''));
      if (fs.existsSync(full)) files.push(full);
    });
  });

  const unique = [...new Set(files)];
  let uploaded = 0;
  let skipped = 0;
  for (const filePath of unique) {
    const ext = path.extname(filePath).toLowerCase();
    if (SKIP_EXT.has(ext)) {
      skipped++;
      continue;
    }
    const publicPath = publicPathFor(filePath);
    const cacheKey = path.relative(UPLOADS, filePath).replace(/\\/g, '/');
    if (hosted[publicPath] || cache[cacheKey]) {
      hosted[publicPath] = hosted[publicPath] || cache[cacheKey];
      skipped++;
      continue;
    }
    try {
      const url = await uploadWithRetry(filePath, path.basename(filePath));
      cache[cacheKey] = url;
      hosted[publicPath] = url;
      uploaded++;
      console.log('[media]', publicPath, '->', url);
    } catch (err) {
      console.warn('[media] skip', publicPath, err.message);
      skipped++;
    }
    saveJson(CACHE_FILE, cache);
    saveJson(HOSTED_FILE, hosted);
    await sleep(DELAY_MS);
  }

  saveJson(HOSTED_FILE, hosted);
  saveJson(CACHE_FILE, cache);
  console.log('[media] done. uploaded', uploaded, 'skipped', skipped, 'mapped', Object.keys(hosted).length);
})().catch((err) => {
  console.error('[media] fatal', err);
  process.exit(1);
});
