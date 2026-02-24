# Debugging & Improvement Ideas

Quick reference for making the dress-up game more robust and maintainable.

**Implemented (latest pass):** .gitignore (users.json, .env), dotenv + .env.example, bcrypt password hashing + legacy plain-text login, session secret from env, earn-currency cap (50), registration validation (username 3–30 chars, alphanumeric+underscore, password min 6), common.css + shared header (partials/header.html + header.js), toast.js (showToast/showError), Room mouseleave + persist avatar position + touch drag, loading state on home outfit, API error handling in Berry Catch + adjust showError→toast, aria-labels on room chat, basic Jest tests (GET /api/items, POST /api/earn-currency cap). **Plus:** shared `js/slots.js` (VALID_SLOT_IDS, SLOT_LAYER_ORDER) for Store and Wardrobe; Store loading state (“Loading store…”) and empty state (“No items in this category.”); forum topics/posts on server (forumTopics.json, forumPosts.json).

---

## Debugging

### 1. **Centralized error handling (frontend)** — mostly done
- Toast/notification component: **Done** (`toast.js`, showToast/showError used across pages).
- In `catch` blocks, log with `console.error(message, err)` where useful; add where still missing.

### 2. **API error responses**
- Ensure failed `fetch()` calls show a clear message (e.g. “Network error” vs “Server error”). Check `res.ok` and optionally `res.status` and `res.json().then(d => d.error)` to display the server’s error message when available.

### 3. **Room drag when mouse leaves window**
- If the user drags the avatar and the cursor leaves the browser window, `mouseup` might fire on another window and the room can get stuck in “dragging” state. Listen for `mouseleave` on `document` or `window` and set `isDragging = false` when the pointer leaves.

### 4. **Games: stop loops when leaving the game**
- When the user navigates away (e.g. Back to games) without ending the round, `requestAnimationFrame` / `setTimeout` can keep running. Already partially handled by checking `section.classList.contains('active')`; double-check Berry Catch and Snake cancel timers when their section is hidden.

### 5. **Forum / home: localStorage sync**
- Forum topics and home “forum box” use `localStorage`. If a user has multiple tabs, one tab’s changes don’t show in the other until refresh. Consider `storage` event (already used on home) and/or a small “last updated” hint so users know data can be tab-specific.

---

## Security & data

### 6. **Passwords in users.json**
- Passwords are stored in plain text. For real use, hash them (e.g. `bcrypt`) before saving and compare hashes on login. Keep `users.json` out of version control (add to `.gitignore` if it isn’t already).

### 7. **Session secret**
- Move `secret: 'your-secret-key'` to an environment variable (e.g. `process.env.SESSION_SECRET`) and use a long random value in production so session cookies can’t be forged.

### 8. **Earn-currency abuse**
- `POST /api/earn-currency` accepts any positive amount. Consider a per-game cap (e.g. max 50 ◎ per Berry Catch round) or server-side validation of “last score” so the client can’t send arbitrary amounts.

### 9. **Registration validation**
- Trim and validate username (length, allowed characters). Optionally require a minimum password length and reject obviously weak passwords.

---

## UX & polish

### 10. **Loading states**
- On pages that call `/api/outfits`, `/api/items`, `/api/user-inventory`, show a “Loading…” or spinner until data arrives, and a “No outfit yet” / “No items” state when the list is empty so the user knows the request finished.

### 11. **Wardrobe / Store: image load errors**
- You already use `onerror` on some images. Consistently set a placeholder or hide broken images so missing assets don’t show as broken icons.

### 12. **Room: persist avatar position** — done
- Avatar position saved to `sessionStorage` and restored on load.

### 13. **Accessibility**
- Add `aria-label` or visible labels for icon-only buttons. Ensure focus stays in modals/chat and that keyboard users can reach “Send” and game controls (you already support arrow keys and Space in games).

### 14. **Mobile: touch for room and games**
- Room avatar drag: add `touchstart` / `touchmove` / `touchend` (with `preventDefault()` where needed) so the avatar can be dragged on touch devices. Same idea for games (e.g. tap to jump in Jumpy Bird).

---

## Code quality

### 15. **Shared header / nav**
- The header HTML is duplicated in every page. Consider a single `header.html` included via fetch + `innerHTML`, or a simple server-side include / template, so adding a new nav link is done in one place. **Done:** header.js + partials/header.html load the shared header.

### 16. **Shared styles**
- Common classes (e.g. `.header-button`, `.header-container`) are repeated. Move them into one CSS file (e.g. `common.css`) and link it on every page to avoid drift and make global style changes easier. **Done:** common.css linked on pages. **New:** `js/slots.js` shares VALID_SLOT_IDS and SLOT_LAYER_ORDER between Store and Wardrobe.

### 17. **Environment and config** — done
- `dotenv`, `.env.example`, `.env` in `.gitignore`.

### 18. **Tests** — partial
- Jest tests for GET /api/items (200, array), POST /api/earn-currency (cap 50, invalid amount 400). Tests use a minimal app copy; consider testing the real server or more routes.

---

## Optional features

- **Room:** Undo last decoration, or a “Clear decorations” button.
- **Berry Catch:** Show “+1 ◎” briefly when a berry is caught.
- **Snake / Jumpy Bird:** Persist best score in `localStorage` so it survives refresh.
- **Forums:** Basic sanitization of topic/post text (e.g. strip `<script>`) if you ever render HTML.

Pick what fits your priorities (e.g. security first, then UX, then code structure) and tackle items in small steps.

---

## Status summary (quick reference)

- **Done:** 1 (toast), 2 (API error messages via api.js + handleApiResponse), 3 (mouseleave), 4 (games stop loops on leave — cancelAnimationFrame/clearTimeout), 5 (forum tab sync + storage event + “Updated” on home), 6 (bcrypt), 7 (session secret), 8 (earn cap), 9 (registration), 10 (loading states — wardrobe, store), 11 (image onerror — store/wardrobe), 12 (room persist), 13 (accessibility — aria-labels on header, canvases, room Send), 14 (mobile touch — room already had it; Jumpy Bird touchstart/touchend), 15 (header), 16 (common.css, slots.js), 17 (.env), 18 (basic tests). Optional: Room “Clear decorations” button, Berry Catch “+1 ◎” feedback, persist best score (Snake/Jumpy Bird in localStorage).
- **Still open:** Forum sanitization (strip/escape HTML in post/topic text if rendered as HTML).
