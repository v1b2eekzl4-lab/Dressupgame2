const { getSupabase } = require('./supabase');

const ITEM_FIELDS = new Set([
  'id', 'filename', 'name', 'slotId', 'tags', 'heart', 'designer', 'isSet',
  'defaultX', 'defaultY', 'defaultZ', 'goldenTicketPrice', 'frameCount',
  'spriteSheetFrameW', 'spriteSheetFrameH', 'imageUrl'
]);

async function upsert(table, rows, onConflict) {
  if (!rows.length) return;
  const sb = getSupabase();
  const chunkSize = 200;
  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);
    const { error } = await sb.from(table).upsert(chunk, onConflict ? { onConflict } : undefined);
    if (error) throw new Error(table + ': ' + error.message);
  }
}

function extraOf(obj, known) {
  const extra = {};
  Object.entries(obj || {}).forEach(([key, value]) => {
    if (!known.has(key)) extra[key] = value;
  });
  return extra;
}

function mapUser(user) {
  return {
    id: Number(user.id),
    username: String(user.username),
    password_hash: String(user.password || user.password_hash || ''),
    roles: Array.isArray(user.roles) ? user.roles : []
  };
}

function mapItem(item, index, usedIds) {
  let id = String(item.id || item.filename || 'item-' + index);
  if (usedIds.has(id)) id = id + '-' + index;
  usedIds.add(id);
  const extra = extraOf(item, ITEM_FIELDS);
  extra.defaultX = item.defaultX;
  extra.defaultY = item.defaultY;
  extra.defaultZ = item.defaultZ;
  return {
    id,
    filename: item.filename || null,
    name: item.name || null,
    slot_id: item.slotId || null,
    tags: Array.isArray(item.tags) ? item.tags : [],
    heart: !!item.heart,
    designer: item.designer || '',
    is_set: !!item.isSet,
    default_x: Math.round(Number(item.defaultX) || 0),
    default_y: Math.round(Number(item.defaultY) || 0),
    default_z: Math.round(Number(item.defaultZ) || 0),
    golden_ticket_price: Number(item.goldenTicketPrice) || 0,
    frame_count: Number(item.frameCount) || 1,
    sprite_sheet_frame_w: Number(item.spriteSheetFrameW) || 0,
    sprite_sheet_frame_h: Number(item.spriteSheetFrameH) || 0,
    image_url: item.imageUrl || null,
    extra: extraOf(item, ITEM_FIELDS)
  };
}

function mapTopic(topic) {
  const known = new Set(['id', 'topic', 'category', 'author', 'authorId', 'locked']);
  const authorId = topic.authorId == null ? null : Number(topic.authorId);
  return {
    id: String(topic.id),
    topic: String(topic.topic || ''),
    category: topic.category || null,
    author: topic.author || null,
    author_id: Number.isFinite(authorId) ? authorId : null,
    locked: !!topic.locked,
    extra: extraOf(topic, known)
  };
}

function mapPost(post) {
  const known = new Set(['id', 'topicId', 'parentId', 'userId', 'username', 'message']);
  const userId = post.userId == null ? null : Number(post.userId);
  return {
    id: String(post.id),
    topic_id: post.topicId ? String(post.topicId) : null,
    parent_id: post.parentId ? String(post.parentId) : null,
    user_id: Number.isFinite(userId) ? userId : null,
    username: post.username || null,
    message: post.message || null,
    extra: extraOf(post, known)
  };
}

async function syncUsers(users) {
  const list = Array.isArray(users) ? users.filter((u) => u && u.id != null && u.username) : [];
  const rows = [
    { id: 1, username: process.env.ADMIN_USERNAME || 'admin', password_hash: 'builtin', roles: ['admin'] },
    ...list.map(mapUser).filter((u) => u.id !== 1)
  ];
  await upsert('app_users', rows, 'id');
}

async function syncProfiles(profiles) {
  if (!profiles || typeof profiles !== 'object') return;
  const rows = Object.entries(profiles).map(([userId, data]) => ({
    user_id: Number(userId),
    data: data && typeof data === 'object' ? data : {},
    updated_at: new Date().toISOString()
  })).filter((row) => Number.isFinite(row.user_id));
  await upsert('profiles', rows, 'user_id');
}

async function syncItems(items) {
  if (!Array.isArray(items)) return;
  const usedIds = new Set();
  const rows = items.filter(Boolean).map((item, i) => mapItem(item, i, usedIds));
  await upsert('items', rows, 'id');
}

async function syncForumTopics(topics) {
  if (!Array.isArray(topics)) return;
  await upsert('forum_topics', topics.filter((t) => t && t.id).map(mapTopic), 'id');
}

async function syncForumPosts(posts) {
  if (!Array.isArray(posts)) return;
  await upsert('forum_posts', posts.filter((p) => p && p.id).map(mapPost), 'id');
}

async function syncOutfits(byUser) {
  if (!byUser || typeof byUser !== 'object') return;
  const rows = [];
  Object.entries(byUser).forEach(([userId, list]) => {
    const uid = Number(userId);
    if (!Number.isFinite(uid) || !Array.isArray(list)) return;
    const used = new Set();
    list.forEach((outfit, i) => {
      if (!outfit) return;
      let name = String(outfit.name || 'outfit-' + i);
      if (used.has(name)) name = name + '-' + i;
      used.add(name);
      rows.push({
        user_id: uid,
        name,
        items: outfit.items && typeof outfit.items === 'object' ? outfit.items : {}
      });
    });
  });
  await upsert('outfits', rows, 'user_id,name');
}

async function syncGameScores(scores) {
  if (!scores || typeof scores !== 'object') return;
  const rows = [];
  Object.entries(scores).forEach(([game, list]) => {
    (Array.isArray(list) ? list : []).forEach((entry) => {
      if (!entry || typeof entry.score !== 'number') return;
      rows.push({
        game,
        username: String(entry.username || entry.name || 'Guest'),
        score: entry.score
      });
    });
  });
  const sb = getSupabase();
  const { error: delError } = await sb.from('game_scores').delete().neq('game', '__never__');
  if (delError) throw new Error('game_scores delete: ' + delError.message);
  await upsert('game_scores', rows);
}

async function syncProjects(projects) {
  if (!projects || typeof projects !== 'object') return;
  const rows = Object.values(projects).filter(Boolean).map((project) => ({
    id: String(project.id),
    name: project.name || null,
    released: !!project.released,
    data: project,
    created_at: project.createdAt || null
  }));
  await upsert('projects', rows, 'id');
}

async function syncSlides(slides) {
  if (!Array.isArray(slides)) return;
  const rows = slides.filter((s) => s && s.id).map((slide) => ({
    id: String(slide.id),
    data: slide
  }));
  await upsert('dashboard_slides', rows, 'id');
}

async function syncSiteSettings(settings) {
  if (!settings || typeof settings !== 'object') return;
  await upsert('site_settings', [{ id: 'default', data: settings }], 'id');
}

async function syncMessages(list) {
  if (!Array.isArray(list) || !list.length) return;
  const rows = list.filter((m) => m && (m.id != null)).map((message) => ({
    id: String(message.id),
    data: message
  }));
  await upsert('messages', rows, 'id');
}

const SYNCERS = {
  'users.json': syncUsers,
  'profiles.json': syncProfiles,
  'items.json': syncItems,
  'forumTopics.json': syncForumTopics,
  'forumPosts.json': syncForumPosts,
  'outfits.json': syncOutfits,
  'gameScores.json': syncGameScores,
  'projects.json': syncProjects,
  'dashboardSlides.json': syncSlides,
  'siteSettings.json': syncSiteSettings,
  'messages.json': syncMessages
};

async function syncKeyToTables(key, data) {
  const fn = SYNCERS[key];
  if (!fn) return;
  await fn(data);
}

async function importMappedFiles(files) {
  const order = [
    'users.json',
    'profiles.json',
    'items.json',
    'forumTopics.json',
    'forumPosts.json',
    'outfits.json',
    'gameScores.json',
    'projects.json',
    'dashboardSlides.json',
    'siteSettings.json',
    'messages.json'
  ];
  for (const key of order) {
    if (!(key in files)) continue;
    console.log('[postgres] importing', key);
    await syncKeyToTables(key, files[key]);
  }
}

module.exports = { syncKeyToTables, importMappedFiles, SYNCERS };
