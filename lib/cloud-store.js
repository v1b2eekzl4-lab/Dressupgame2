const fs = require('fs');
const path = require('path');
const { getSupabase, isSupabaseConfigured } = require('./supabase');
const { syncKeyToTables } = require('./pg-sync');

const origWriteFileSync = fs.writeFileSync.bind(fs);
const origRenameSync = fs.renameSync.bind(fs);

const trackedPaths = new Map();
const pushTimers = new Map();
let hooksInstalled = false;
let syncing = false;

function hasMeaningfulData(value) {
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') return Object.keys(value).length > 0;
  return true;
}

function registerFiles(files) {
  trackedPaths.clear();
  Object.entries(files).forEach(([key, filePath]) => {
    if (filePath) trackedPaths.set(path.resolve(filePath), key);
  });
}

function keyForPath(filePath) {
  return trackedPaths.get(path.resolve(String(filePath)));
}

async function pushFile(filePath, key) {
  if (!fs.existsSync(filePath)) return;
  let data;
  try {
    data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return;
  }
  const { error } = await getSupabase().from('json_store').upsert(
    { key, data, updated_at: new Date().toISOString() },
    { onConflict: 'key' }
  );
  if (error) console.error('[supabase] save failed:', key, error.message);
  try {
    await syncKeyToTables(key, data);
  } catch (e) {
    console.error('[postgres] table sync failed:', key, e.message || e);
  }
}

function queuePush(filePath) {
  if (syncing || !isSupabaseConfigured()) return;
  const key = keyForPath(filePath);
  if (!key) return;
  clearTimeout(pushTimers.get(key));
  pushTimers.set(key, setTimeout(() => {
    pushFile(filePath, key).catch((e) => {
      console.error('[supabase] save failed:', key, e.message || e);
    });
  }, 400));
}

function installHooks() {
  if (hooksInstalled) return;
  hooksInstalled = true;
  fs.writeFileSync = function writeFileSyncTracked(file, data, options) {
    origWriteFileSync(file, data, options);
    queuePush(file);
  };
  fs.renameSync = function renameSyncTracked(src, dest) {
    origRenameSync(src, dest);
    queuePush(dest);
  };
}

async function startCloudSync(files) {
  registerFiles(files);
  installHooks();
  if (!isSupabaseConfigured()) {
    console.log('[supabase] skipped (missing URL or key)');
    return;
  }

  const sb = getSupabase();
  const { data: rows, error } = await sb.from('json_store').select('key, data');
  if (error) {
    console.error('[supabase] could not read json_store:', error.message);
    return;
  }

  const byKey = Object.fromEntries((rows || []).map((row) => [row.key, row.data]));
  const cloudHasData = (rows || []).some((row) => hasMeaningfulData(row.data));
  const preferCloud = process.env.NODE_ENV === 'production' || Boolean(process.env.DATA_DIR) || Boolean(process.env.RENDER);

  if (!cloudHasData) {
    console.log('[supabase] cloud is empty — uploading local JSON files');
    syncing = true;
    for (const [filePath, key] of trackedPaths.entries()) {
      await pushFile(filePath, key);
    }
    syncing = false;
    console.log('[supabase] initial upload complete');
    return;
  }

  if (!preferCloud) {
    const restoreIfMissing = ['users.json', 'profiles.json'];
    syncing = true;
    for (const key of restoreIfMissing) {
      if (!(key in byKey) || !hasMeaningfulData(byKey[key])) continue;
      const entry = [...trackedPaths.entries()].find(([, k]) => k === key);
      if (!entry) continue;
      const filePath = entry[0];
      let localEmpty = !fs.existsSync(filePath);
      if (!localEmpty) {
        try {
          localEmpty = !hasMeaningfulData(JSON.parse(fs.readFileSync(filePath, 'utf8')));
        } catch (_) {
          localEmpty = true;
        }
      }
      if (localEmpty) {
        origWriteFileSync(filePath, JSON.stringify(byKey[key], null, 2), 'utf8');
        console.log('[supabase] restoring', key, '(missing locally)');
      }
    }
    const cloudItems = byKey['items.json'];
    const itemsPath = [...trackedPaths.entries()].find(([, key]) => key === 'items.json');
    const cloudHasHostedImages = Array.isArray(cloudItems) && cloudItems.some((item) => item && item.imageUrl);
    if (cloudHasHostedImages && itemsPath) {
      console.log('[supabase] restoring items.json from cloud (ImgBB URLs)');
      origWriteFileSync(itemsPath[0], JSON.stringify(cloudItems, null, 2), 'utf8');
    } else {
      console.log('[supabase] connected; local JSON kept. Saves also go to the cloud.');
    }
    syncing = false;
    return;
  }

  console.log('[supabase] restoring JSON files from the cloud');
  syncing = true;
  for (const [filePath, key] of trackedPaths.entries()) {
    if (!(key in byKey)) continue;
    origWriteFileSync(filePath, JSON.stringify(byKey[key], null, 2), 'utf8');
  }
  syncing = false;
  console.log('[supabase] restore complete');
}

module.exports = { startCloudSync };
