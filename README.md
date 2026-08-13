# Dress-Up Game

A browser-based dress-up game with wardrobe, store, forum (bulletin board), and user accounts.

## Setup

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Environment**
   - Copy `.env.example` to `.env`
   - Set `SESSION_SECRET` to a long random string (e.g. `openssl rand -hex 32`)
   - For production: set `ADMIN_PASSWORD` (and optionally `ADMIN_USERNAME`) so the default admin account is secure
   - For Supabase: set `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` from **Project Settings → API**

## Supabase

The GitHub integration watches this repo. Set **Working directory** to `.` in **Project Settings → Integrations**.

On startup the server syncs JSON data files (`users.json`, `items.json`, `profiles.json`, and the rest) with the `json_store` table:

- First run (empty cloud): uploads your local JSON
- Production (`NODE_ENV=production` or `DATA_DIR` set): restores JSON from the cloud, so Render deploys keep accounts and items
- Local development: keeps your local files; saves still upload to the cloud

Set these on Render (and in `.env` locally): `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`.

`GET /api/health` returns `{ ok, supabase: { configured, connected } }`.

3. **Run**
   ```bash
   npm start
   ```
   Server listens on `PORT` (default 3000). Open `http://localhost:3000` in a browser.

## Scripts

- `npm start` — run the server (node server.js)
- `npm test` — run tests (Jest)
- `npm run build:css` — build Tailwind CSS

## Health check

- `GET /api/health` returns `{ "ok": true }` for load balancers or monitoring.

## Production

- Set `NODE_ENV=production` so session cookies use `secure` and static assets are cached.
- Set `SESSION_SECRET` and `ADMIN_PASSWORD` in `.env` (see `.env.example`).
- If the app runs behind a reverse proxy (nginx, etc.), set `TRUST_PROXY=1` so rate limiting and logs use the real client IP.

## More

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for recent changes and further recommendations.
