/**
 * Shared slot constants for Store and Wardrobe.
 * Single source of truth for valid slots and layer order (bottom=0 to top=11).
 */
(function () {
  var VALID_SLOT_IDS = new Set([
    'body-slot', 'shirt-slot', 'pants-slot', 'skirt-slot', 'dress-slot',
    'jacket-slot', 'shoes-slot', 'hat-slot', 'makeup-slot', 'jewelry-slot',
    'other-slot', 'hair-slot', 'socks-slot'
  ]);
  var SLOT_LAYER_ORDER = {
    'body-slot': 0, 'pants-slot': 1, 'skirt-slot': 2, 'dress-slot': 3,
    'shirt-slot': 4, 'jacket-slot': 5, 'socks-slot': 6, 'shoes-slot': 7,
    'hat-slot': 8, 'makeup-slot': 9, 'jewelry-slot': 10, 'hair-slot': 11,
    'other-slot': 12
  };
  /** Z-index for layers under the character base (background images). Lower = further back. */
  window.BACKGROUND_LAYER_Z = 0;
  window.VALID_SLOT_IDS = VALID_SLOT_IDS;
  window.SLOT_LAYER_ORDER = SLOT_LAYER_ORDER;
})();
