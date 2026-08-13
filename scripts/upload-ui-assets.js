require('dotenv').config();
const fs = require('fs');
const path = require('path');

const KEY = process.env.IMGBB_API_KEY;
const ROOT = path.join(__dirname, '..');
const UPLOADS = path.join(ROOT, 'Uploads');
const DELAY_MS = 800;
const MAX_BYTES = 32 * 1024 * 1024;

if (!KEY) {
  console.error('IMGBB_API_KEY is missing from .env');
  process.exit(1);
}

/** Logical /Uploads/ name -> file on disk (some HTML names never existed as files). */
const UI_ASSETS = {
  'character.png': 'character.png',
  'arrow-circle-up.svg': 'arrow-circle-up.svg',
  'arrow-circle-down.svg': 'arrow-circle-down.svg',
  'heart-icon.png': 'heart-icon.svg',
  'heart-icon.svg': 'heart-icon.svg',
  'heart_true.svg': 'heart_true.svg',
  'heart_false.svg': 'heart_false.svg',
  'site-wallpaper.png': 'site-wallpaper.png',
  'move-up.png': 'move-up.png',
  'dfer5erer.png': 'dfer5erer.png',
  'body-icon.png': 'body1.png',
  'shirt-icon.png': 'shirt1.png',
  'pants-icon.png': 'pants1.png',
  'shoes-icon.png': 'shoes1.png',
  'socks-icon.png': 'socks1.png',
  'other-icon.png': 'body1.png',
  'full-sets-icon.png': 'shirt2.png',
  'saved-outfits-icon.png': 'shirt2.png',
  'hat-icon.png': 'body1.png',
  'dress-icon.png': 'body1.png',
  'skirt-icon.png': 'pants1.png',
  'jewelry-icon.png': 'body1.png',
  'jacket-icon.png': 'shirt1.png',
  'hair-icon.png': 'body1.png',
  'makeup-icon.png': 'body1.png'
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
  if (res.status === 429) throw Object.assign(new Error('rate limited'), { retry: true });
  if (!data.success || !data.data || !data.data.url) {
    const msg = data.error ? (data.error.message || JSON.stringify(data.error)) : ('HTTP ' + res.status);
    throw Object.assign(new Error(msg), { retry: res.status >= 500 });
  }
  return data.data.url;
}

async function uploadWithRetry(filePath, name) {
  let lastErr;
  for (let attempt = 1; attempt <= 6; attempt++) {
    try {
      return await uploadToImgBB(filePath, name);
    } catch (err) {
      lastErr = err;
      console.warn('[ui-assets] retry', attempt, name, err.message);
      await sleep(err.retry ? 4000 * attempt : 1200 * attempt);
    }
  }
  throw lastErr;
}

function rewritePublicFiles(urlMap) {
  const names = Object.keys(urlMap).sort((a, b) => b.length - a.length);
  function walk(dir) {
    fs.readdirSync(dir, { withFileTypes: true }).forEach((ent) => {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(full);
        return;
      }
      if (!/\.(html|js)$/.test(ent.name)) return;
      let text = fs.readFileSync(full, 'utf8');
      const original = text;
      names.forEach((name) => {
        text = text.split('/Uploads/' + name).join(urlMap[name]);
      });
      if (text !== original) {
        fs.writeFileSync(full, text, 'utf8');
        console.log('[ui-assets] updated', path.relative(ROOT, full));
      }
    });
  }
  walk(path.join(ROOT, 'public'));
}

(async function main() {
  const urlMap = {};
  const uploadedFiles = new Map();
  const publicImg = path.join(ROOT, 'public', 'img');
  if (!fs.existsSync(publicImg)) fs.mkdirSync(publicImg, { recursive: true });

  for (const [logical, diskName] of Object.entries(UI_ASSETS)) {
    const filePath = path.join(UPLOADS, diskName);
    if (!fs.existsSync(filePath)) {
      console.warn('[ui-assets] missing', diskName, 'for', logical);
      continue;
    }
    const ext = path.extname(diskName).toLowerCase();
    if (ext === '.svg') {
      const destName = diskName;
      fs.copyFileSync(filePath, path.join(publicImg, destName));
      urlMap[logical] = '/img/' + destName;
      console.log('[ui-assets]', logical, '-> /img/' + destName);
      continue;
    }
    if (uploadedFiles.has(diskName)) {
      urlMap[logical] = uploadedFiles.get(diskName);
      continue;
    }
    const url = await uploadWithRetry(filePath, diskName);
    uploadedFiles.set(diskName, url);
    urlMap[logical] = url;
    console.log('[ui-assets]', logical, '->', url);
    await sleep(DELAY_MS);
  }

  const characterSrc = path.join(UPLOADS, 'character.png');
  if (fs.existsSync(characterSrc)) {
    fs.copyFileSync(characterSrc, path.join(publicImg, 'character.png'));
  }

  fs.writeFileSync(
    path.join(ROOT, 'public', 'assets.json'),
    JSON.stringify(urlMap, null, 2),
    'utf8'
  );
  fs.writeFileSync(
    path.join(ROOT, 'public', 'js', 'site-assets.js'),
    'window.SITE_ASSETS = ' + JSON.stringify(urlMap, null, 2) + ';\n' +
    'window.assetUrl = function (path) {\n' +
    '  var name = String(path || "").replace(/^\\/Uploads\\//, "");\n' +
    '  return (window.SITE_ASSETS && window.SITE_ASSETS[name]) || path;\n' +
    '};\n' +
    'window.CHARACTER_BASE = (window.SITE_ASSETS && window.SITE_ASSETS["character.png"]) || "/img/character.png";\n',
    'utf8'
  );

  rewritePublicFiles(urlMap);
  console.log('[ui-assets] complete', Object.keys(urlMap).length, 'linked assets');
})().catch((err) => {
  console.error('[ui-assets] fatal', err);
  process.exit(1);
});
