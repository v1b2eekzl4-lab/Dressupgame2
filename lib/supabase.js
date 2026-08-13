const { createClient } = require('@supabase/supabase-js');

let client = null;

function getSupabaseKey() {
  return (
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.SUPABASE_ANON_KEY ||
    ''
  );
}

function isSupabaseConfigured() {
  return Boolean(process.env.SUPABASE_URL && getSupabaseKey());
}

function getSupabase() {
  if (client) return client;
  const url = process.env.SUPABASE_URL;
  const key = getSupabaseKey();
  if (!url || !key) return null;
  client = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  return client;
}

module.exports = { getSupabase, isSupabaseConfigured };
