const fs = require('fs');
const path = require('path');
const { getSupabase, isSupabaseConfigured } = require('./supabase');
const hostedUploads = require('./hosted-uploads');

const BUCKET = 'assets';
let bucketReady = false;

function guessMime(filePath, fallback) {
  const ext = path.extname(filePath || '').toLowerCase();
  const map = {
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.ogg': 'video/ogg',
    '.ogv': 'video/ogg',
    '.mov': 'video/quicktime',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp'
  };
  return map[ext] || fallback || 'application/octet-stream';
}

function storageDest(publicPath) {
  const key = hostedUploads.normalizeKey(publicPath).replace(/^\//, '');
  return key || ('Uploads/' + Date.now());
}

async function ensureAssetBucket() {
  if (bucketReady) return true;
  const sb = getSupabase();
  if (!sb) return false;
  const { data, error } = await sb.storage.listBuckets();
  if (error) console.warn('[storage] listBuckets:', error.message);
  if (!error && !(data || []).some((b) => b.name === BUCKET)) {
    const created = await sb.storage.createBucket(BUCKET, {
      public: true,
      fileSizeLimit: 50 * 1024 * 1024
    });
    if (created.error && !/already exists|duplicate/i.test(created.error.message || '')) {
      console.warn('[storage] createBucket:', created.error.message);
    }
  }
  bucketReady = true;
  return true;
}

async function uploadPersistentFile(absPath, publicPath, mimetype) {
  if (!isSupabaseConfigured() || !absPath || !fs.existsSync(absPath)) return null;
  const sb = getSupabase();
  if (!sb) return null;
  await ensureAssetBucket();
  const dest = storageDest(publicPath);
  const buf = fs.readFileSync(absPath);
  const { error } = await sb.storage.from(BUCKET).upload(dest, buf, {
    contentType: guessMime(absPath, mimetype),
    upsert: true
  });
  if (error) {
    console.warn('[storage] upload failed', dest, error.message);
    return null;
  }
  const { data } = sb.storage.from(BUCKET).getPublicUrl(dest);
  const url = data && data.publicUrl;
  if (url) hostedUploads.setUrl(publicPath, url);
  return url || null;
}

module.exports = { uploadPersistentFile, ensureAssetBucket };
