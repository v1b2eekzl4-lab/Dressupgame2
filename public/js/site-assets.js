window.SITE_ASSETS = {
  "character.png": "/img/character.png",
  "arrow-circle-up.svg": "/img/arrow-circle-up.svg",
  "arrow-circle-down.svg": "/img/arrow-circle-down.svg",
  "heart-icon.png": "/img/heart-icon.svg",
  "heart-icon.svg": "/img/heart-icon.svg",
  "heart_true.svg": "/img/heart_true.svg",
  "heart_false.svg": "/img/heart_false.svg",
  "site-wallpaper.png": "https://i.ibb.co/xqGngknQ/site-wallpaper.png",
  "move-up.png": "https://i.ibb.co/Q3Pb7z60/move-up.png",
  "dfer5erer.png": "/img/character.png",
  "body-icon.png": "/img/body1.png",
  "shirt-icon.png": "/img/shirt1.png",
  "pants-icon.png": "/img/pants1.png",
  "shoes-icon.png": "/img/shoes1.png",
  "socks-icon.png": "/img/socks1.png",
  "other-icon.png": "/img/body1.png",
  "full-sets-icon.png": "/img/shirt2.png",
  "saved-outfits-icon.png": "/img/shirt2.png",
  "hat-icon.png": "/img/body1.png",
  "dress-icon.png": "/img/body1.png",
  "skirt-icon.png": "/img/pants1.png",
  "jewelry-icon.png": "/img/body1.png",
  "jacket-icon.png": "/img/shirt1.png",
  "hair-icon.png": "/img/body1.png",
  "makeup-icon.png": "/img/body1.png"
};
window.assetUrl = function (path) {
  var name = String(path || "").replace(/^\/Uploads\//, "");
  return (window.SITE_ASSETS && window.SITE_ASSETS[name]) || path;
};
window.CHARACTER_BASE = "/img/character.png";
