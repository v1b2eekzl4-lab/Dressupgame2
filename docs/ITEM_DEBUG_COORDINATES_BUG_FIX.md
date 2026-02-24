# Item Debug: Coordinates Reset After Save — Bug & Fix

**Date documented:** 2025  
**Area:** Item Debug (`public/item-debug.html`), Items API (`server.js`)

---

## The Bug

In Item Debug, after changing an item’s coordinates (X, Y, Z) and saving (either the single-item Save button or “Save all”), the coordinates would **reset** — either immediately in the UI or after refresh. Persisted values in `items.json` did not reflect what the user had saved.

---

## Root Causes

1. **Server (PUT handler)**  
   Coordinates from the request body were passed through `parseNum()` and then assigned. In some cases (e.g. type coercion, `0`, or missing fallbacks) the values written to disk could be wrong or not written consistently. The handler did not explicitly guarantee that `defaultX`, `defaultY`, and `defaultZ` were always stored as valid numbers.

2. **Server (PATCH coordinates)**  
   The PATCH endpoint that updates only coordinates used `parseFloat`/`parseInt` without ensuring the result was a finite number before writing, which could lead to inconsistent or non-numeric values in `items.json`.

3. **Client (UI after save)**  
   After a successful save, the merged response was applied to in-memory state (`lastLoadedList`, `itemsByFilename`, `selectedItem`), but the **table row** coord inputs and the **align panel** inputs were not updated from that merged item. So the UI could still show old values, or the row could be bound to a stale object reference, making it look like coordinates had “reset.”

4. **Save flow**  
   The flow used PATCH (coordinates-only) then PUT (full item). If PATCH failed, the code could throw and skip the PUT, so coordinates were never persisted. The fix made PATCH best-effort and always run the PUT so the full body (including coordinates) is saved.

---

## The Fix

### 1. Server — PUT `/api/items/update/:filename` (`server.js`)

- **Explicit coordinate coercion from body:**  
  `defaultX` and `defaultY`: use `Number(...)` and then `Number.isFinite(...) ? value : 0` so only valid numbers (including `0`) are written.  
  `defaultZ`: use `parseInt(String(defaultZ), 10)` and ensure it’s a non-negative integer; otherwise use `0`.

- **Fallback when body omits coords:**  
  If a coordinate is missing from the body, use the previous item’s value (also coerced to number), not `undefined` or NaN.

- **Written fields:**  
  The stored item always gets `defaultX`, `defaultY`, and `defaultZ` as numbers so `items.json` stays consistent.

### 2. Server — PATCH `/api/items/update/:filename/coordinates` (`server.js`)

- Use `Number(body.defaultX)` / `Number(body.defaultY)` and `Number.isFinite(...)` before assigning to the item.
- Use `parseInt(String(body.defaultZ), 10)` and only assign when the result is a valid non-negative integer.
- Ensures only valid numeric coordinates are written to the file.

### 3. Client — Save flow resilience (`public/item-debug.html`)

- **Single-item save:**  
  PATCH is best-effort (`.catch` and continue). The PUT always runs afterward so the full item (including coordinates) is persisted even if PATCH fails.

- **Save all:**  
  PATCH is wrapped in try/catch; on failure we still run the PUT for each item so coordinates are saved via the full payload.

### 4. Client — UI sync after single-item save (`public/item-debug.html`)

- After a successful PUT response, the **merged** item (response or fallback with saved coords) is used to:
  - Update the **table row** for that item: set `.coord-x`, `.coord-y`, `.coord-z` input values from `merged.defaultX`, `merged.defaultY`, `merged.defaultZ`.
  - Update the **align panel** inputs: `#align-x`, `#align-y`, and `#align-z` (if present) from the same merged values.
- So the table and align panel always show the coordinates that were just saved, and the row is not left showing stale values.

---

## Files Touched

| File | Changes |
|------|--------|
| `server.js` | PUT: explicit coercion of `defaultX`/`defaultY`/`defaultZ` from body; PATCH: same for coordinates-only update; both write only valid numbers. |
| `public/item-debug.html` | Single-item save: PATCH optional then PUT; merge response and sync row + align inputs from merged item. Save all: PATCH in try/catch then PUT so coords always saved. |

---

## How to Verify

1. Open Item Debug, select an item, change X/Y/Z (table or align panel).
2. Click Save (or Save all if editing multiple).
3. Confirm the table and align panel show the new values.
4. Refresh the page (or click Refresh) and confirm the coordinates in the table and in `items.json` match what you saved.

---

## If It Regresses

- Check that the PUT handler still coerces `defaultX`/`defaultY`/`defaultZ` from `req.body` and writes `finalX`/`finalY`/`finalZ` (or equivalent) as numbers.
- Check that the client sends numeric values (e.g. `Number(item.defaultX)`) in the PUT body and that after save it updates the row and align inputs from the merged response.
- Ensure no other code path overwrites `items.json` with stale data after a save.
