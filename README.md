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
