# Improvements

## Done in this pass

- **Security**: Default admin (id 1) username/password can be overridden via `ADMIN_USERNAME` and `ADMIN_PASSWORD` in `.env`. Documented in `.env.example`. In production, set a strong `ADMIN_PASSWORD` and optionally `SESSION_SECRET`.
- **Navigation**: Header nav links use root-relative URLs (`/home`, `/wardrobe.html`, etc.) so they work correctly from any page depth and avoid broken links when using path-based routes.
- **Health check**: `GET /api/health` returns `{ "ok": true }` for load balancers or monitoring.
- **Rate limiting**: Login and register limited to 10 attempts per 15 minutes per IP; redirect with `?error=rate` and user-visible message on limit; successful auth clears count for that IP.
- **Session cookies**: In production, session cookie uses `secure: true`, `sameSite: 'strict'`, and `maxAge: 7d`.
- **README**: README.md added with install, `.env` setup, `npm start`, and health check. `npm start` script added to package.json.
- **Error logging**: `loadUsers`, `loadDashboardSlides`, `loadDashboardSlideSubmissions`, `loadSiteSettings`, and `loadProfiles` log failures to stderr instead of swallowing them.
- **Security headers**: Global middleware sets `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN`. All `/api/*` responses get `Cache-Control: no-store, no-cache, must-revalidate, private` so user/session data is not cached.
- **Input validation**: Login and register enforce maximum lengths (username ≤ 30, password ≤ 500 chars). Register shows “Password is too long” for `?error=password-long`.
- **Error logging**: `loadProjects`, `loadHoverCardFoilStore`, `loadHoverCardStickers`, `loadForumEmotes`, and `loadReports` now log failures to stderr.
- **Global error handler**: A four-arg middleware catches unhandled errors and `next(err)`; logs to stderr and returns 500 (JSON for `/api/*`, plain text otherwise) so the server doesn’t crash.
- **Trust proxy**: If `TRUST_PROXY=1` is set, `app.set('trust proxy', 1)` so `req.ip` is correct behind a reverse proxy. Documented in `.env.example` and README.
- **README**: “Production” section added (NODE_ENV, SESSION_SECRET, ADMIN_PASSWORD, TRUST_PROXY).
- **Concurrency / multi-user**: (1) **Sessions**: Each request is tied to one user via `express-session` (cookie); no cross-user data leak. (2) **Atomic file writes**: `saveUsers`, `saveProfiles`, `saveDashboardSlides`, `saveReports`, and `saveSiteSettings` write via temp-then-rename. (3) **In-process locks**: `withLock(key, fn)` serializes access per key. Used for: `users` (register + role assign), `dashboardSlides` (PUT save + approve), `siteSettings` (wallpaper upload + delete), `reports` (POST create + PATCH status), and `profiles` (PUT profile, PUT forum-post-customization, PUT/PATCH hover-card-customization, friend request, profile picture upload, POST equipped-items). (4) **Online users**: "Online" = active in the last 5 minutes; `/api/users/online` excludes the current user and expires stale entries on read.
- **Home**: Bulletin Board title added and centered; "Updated" time moved to bottom of the panel and centered.
- **Gacha**: Prize ball appearance delayed by 600 ms so the handle spin animation finishes first; decorative balls in the machine made uniform size (38px), two-tone (different colored half per ball), and increased to 20 balls in a larger pile.

## Suggested improvements

### High impact
- **Loading states**: Add spinners or "Loading…" (and disable buttons) for gacha pull, forum post/topic create, outfit save, profile save, and store purchase so users get feedback during slow requests.
- **API errors in UI**: Show the server’s `error` message (e.g. "Not enough gold coins") in toasts or inline instead of a generic "Failed"; already returned by many routes.
- **Meta descriptions**: Add `<meta name="description" content="…">` (and optional Open Graph tags) to key pages (home, store, gacha, forum) for better SEO and link previews.
- **Image `alt` text**: Ensure item images, avatars, and decorative images have meaningful `alt` attributes (or `alt=""` where purely decorative) for accessibility and SEO.

### UX
- **Offline / retry**: On fetch failure, show a "Retry" option instead of only an error message.
- **Form feedback**: After profile edit, forum post, or outfit save, show a short success message (e.g. toast) so users know the action succeeded.
- **Gacha**: Optionally show "Next pull in set: X/10" or set progress so users see how close they are to the set reward.
- **Empty states**: Consistent empty-state copy and optional call-to-action (e.g. "No outfits yet — try saving one from the Wardrobe") on wishlist, saved outfits, and forum.

### Accessibility
- **Focus trap**: Trap focus inside modals (gacha play, prize reveal, rewards bar) and restore focus on close; close on Escape where it makes sense.
- **Skip link**: Add a "Skip to main content" link at the top for keyboard users.
- **Live regions**: Use `aria-live` for dynamic messages (e.g. gacha result, form errors) so screen readers announce them.

### Performance
- **Cache static assets**: Set `Cache-Control` (e.g. `max-age=86400`) for `/css/`, `/js/`, and static images so repeat visits load faster.
- **Lazy-load images**: Use `loading="lazy"` (or Intersection Observer) for item grids and forum avatars so below-the-fold images load on demand.
- **Hot-path cache**: Add a short TTL in-memory cache for `loadUsers()` / `loadProfiles()` (or at least read-through cache) if traffic grows.

### Code / maintainability
- **Split server.js**: Move routes into modules (e.g. `routes/auth.js`, `routes/forum.js`, `routes/gacha.js`, `lib/users.js`, `middleware/requireLogin.js`) and require them in `server.js` to make the codebase easier to navigate and test.
- **Shared front-end bundle**: Extract common logic (auth check, header update, API helpers, toasts) into a small shared JS (and optionally CSS) so fixes and behavior stay consistent across the 50+ HTML pages.
- **Consistent role checks**: Use `requireRole('admin','moderator')` (or similar) everywhere instead of ad-hoc `getRoles()` + `includes()` checks.

### Optional features
- **PWA**: Add a simple service worker and manifest for "Add to home screen" and basic offline caching of static assets.
- **Dark mode**: Toggle or system-preference-based dark theme using CSS variables already used in the design.
- **Notifications**: Optional in-browser notification when someone replies to a forum topic or sends a message (with permission).

## Recommended next steps

### Security
- **Session secret**: Never run production with the default `SESSION_SECRET`. Use a long random string (e.g. from `openssl rand -hex 32`) in `.env`.
- **HTTPS**: Use HTTPS in production; session cookie is already configured for `secure` when `NODE_ENV=production`.

### Reliability
- **Error handling**: Many loaders now log on failure; a global error handler returns 500 for uncaught errors. Remaining `try/catch` blocks (e.g. in route-specific code) could be updated to log or use `next(err)`.
- **File writes**: Critical saves now use atomic write (temp + rename). For multi-process deployment, use a shared store (DB or Redis) instead of file.
- **Input validation**: Auth now enforces length limits; consider stricter validation (e.g. `express-validator`) for other user-generated content APIs.

### Code quality
- **server.js size**: The single ~3800-line file is hard to maintain. Split into modules (e.g. `routes/auth.js`, `routes/forum.js`, `lib/users.js`, `middleware/requireLogin.js`).
- **Duplicate role checks**: Patterns like `getRoles(userId)` then `roles.includes('admin') || roles.includes('moderator')` repeat. Consider `requireRole('admin','moderator')` (you have this) and using it consistently; some routes still do manual checks.
- **Front-end**: Many HTML pages use large inline scripts. Consider shared JS bundles for auth, header, and common UI so fixes apply everywhere.

### UX / accessibility
- **Loading states**: Some fetch calls don’t show loading or disable buttons; add spinners or “Loading…” where actions take time.
- **Error messages**: Surface API error messages (e.g. `res.json({ error: '...' })`) in the UI instead of generic “Failed” toasts.
- **Focus and keyboard**: You already have `:focus-visible` in `common.css`; ensure modals and dropdowns trap focus and close on Escape where appropriate.

### Performance
- **Static assets**: Ensure `Cache-Control` headers for images/CSS/JS (e.g. `max-age` with immutable or versioned filenames).
- **JSON reads**: `loadUsers()`, `loadDashboardSlides()`, etc. read from disk on every request. For hot paths, consider in-memory cache with periodic or event-based reload.

### DevOps / docs
- **README**, **health check**, and **Production** notes are in place.
