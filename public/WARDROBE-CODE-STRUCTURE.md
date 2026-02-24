# Wardrobe Code Structure (wardrobe.html)

This file is **one large HTML file** with **multiple inline script blocks**. The wardrobe uses a **single code path** only (no bootstrap). Do not add a second "bootstrap" or "fallback" path that draws the list—it causes races and breaks equipping/categories. To avoid breaking the wardrobe: (1) Do not remove or bypass the main path's init (initializeGame → loadEquippedItems → fetchWardrobeItems → updateWardrobeDisplay). (2) Keep loadEquippedItems non-throwing so fetchWardrobeItems always runs. (3) If updateWardrobeDisplay throws, renderWardrobeFallback is used so the list and handlers still attach.

---

## 1. Script blocks (current)

| Order | Role |
|-------|------|
| 1 | Early helpers: fallback globals (getFlatItemsForMerge, equippedItems, compositeOutfitToCanvas, loadSavedOutfits, showError), `parseTransformXY`, `getEquippedFromDOM`. |
| 2 | One-liner: sets `wardrobe-debug` text. |
| 3 | Fallback globals: `VALID_SLOT_IDS`, `SLOT_LAYER_ORDER` (if `slots.js` didn’t set them). |
| 4 | **Main path**: `wardrobeItems`, `updateWardrobeDisplay()`, `fetchWardrobeItems()`, `initializeGame()`, search, drag, save outfit, icon menu, etc. |

All wardrobe UI is driven by the main path. `handleSaveOutfitClick` is defined in the main block and assigned to `window.handleSaveOutfitClick` there (Save Outfit button works after the page has loaded).

---

## 2. Single init path

- **`DOMContentLoaded`** → **`initializeGame()`** runs.
- **`initializeGame()`** does: load equipped items, **`fetchWardrobeItems()`** (inventory + `/api/items`, filter to owned), **`updateWardrobeDisplay()`**, load saved outfits, then in `finally`: setup Save Outfit, drag, icon menu, move up/down, remove, reset, **`initWardrobeSearch()`**, `updateEquippedItems()`.
- **`fetchWardrobeItems()`** sets **`window.__wardrobeMainDrawn = true`** after the first successful draw (kept for any code that might still check it).
- One data source: **`wardrobeItems`** (owned items). One state: **`equippedItems`**. One renderer: **`updateWardrobeDisplay()`**.

---

## 3. Initialization order

1. Script blocks 1–4 run in order.
2. On **`DOMContentLoaded`**, the main block’s listener runs **`initializeGame()`**.
3. **`initWardrobeSearch()`** is called from the **`finally`** block of **`initializeGame()`**, so it always runs after the main path is set up.

No competing bootstrap path; init order is predictable.

---

## 4. Duplicate logic (reduced)

- **Removed**: bootstrap state and helpers (`bootstrapItems`, `bootstrapEquipped`, `renderInto()`, `showCategory()`, etc.).
- **Single** rendering path: **`updateWardrobeDisplay()`** (with **`renderWardrobeFallback()`** used when the main grid throws).
- **Single** Save Outfit implementation: async **`handleSaveOutfitClick`** in the main block (early block no longer defines it).

---

## 5. Search bar

- Search lives in the main path; **`initWardrobeSearch()`** is called from **`initializeGame()`** `finally`, so it runs after the main path is ready.
- The search wrap uses **z-index** and **pointer-events** so it reliably receives hover/click alongside the category list.

---

## 6. Recommendations for future edits

1. **Keep a single path**  
   All UI and data flow go through **`initializeGame()`** → **`fetchWardrobeItems()`** → **`updateWardrobeDisplay()`**. Add new features (filters, new categories, etc.) in this path only.

2. **Init from the main entry point**  
   Wire new features (event listeners, UI inits) in **`initializeGame()`** or its `finally` block so they run after wardrobe data and display are ready.

3. **Extract scripts (optional)**  
   Moving the main block into an external file (e.g. **`js/wardrobe.js`**) would make navigation and refactors easier; behavior can stay the same.

---

## 7. Quick reference

- **Main path**: single large script block (after the fallback-globals block). Contains: `updateWardrobeDisplay`, `fetchWardrobeItems`, `initializeGame`, search, drag, save outfit, icon menu, etc.
- **Search**: **`initWardrobeSearch()`** in main block; called from **`initializeGame()`** `finally`.
- **Slots**: **`slots.js`** (preferred); fallback in block 3.
