window.SITE_ASSETS = {
  "character.png": "https://i.ibb.co/938sCGCJ/character.png",
  "arrow-circle-up.svg": "/img/arrow-circle-up.svg",
  "arrow-circle-down.svg": "/img/arrow-circle-down.svg",
  "heart-icon.png": "/img/heart-icon.svg",
  "heart-icon.svg": "/img/heart-icon.svg",
  "heart_true.svg": "/img/heart_true.svg",
  "heart_false.svg": "/img/heart_false.svg",
  "site-wallpaper.png": "https://i.ibb.co/xqGngknQ/site-wallpaper.png",
  "move-up.png": "https://i.ibb.co/Q3Pb7z60/move-up.png",
  "dfer5erer.png": "https://i.ibb.co/8gv72hPT/dfer5erer.png",
  "body-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "shirt-icon.png": "https://i.ibb.co/wFNWnRJR/shirt1.png",
  "pants-icon.png": "https://i.ibb.co/zV6R2TYC/pants1.png",
  "shoes-icon.png": "https://i.ibb.co/rGfkB6Gh/1770807444609.png",
  "socks-icon.png": "https://i.ibb.co/sJjPHwmf/socks1.png",
  "other-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "full-sets-icon.png": "https://i.ibb.co/rfRFkd0t/1770808865798.png",
  "saved-outfits-icon.png": "https://i.ibb.co/rfRFkd0t/1770808865798.png",
  "hat-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "dress-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "skirt-icon.png": "https://i.ibb.co/zV6R2TYC/pants1.png",
  "jewelry-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "jacket-icon.png": "https://i.ibb.co/wFNWnRJR/shirt1.png",
  "hair-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png",
  "makeup-icon.png": "https://i.ibb.co/2pKRg9R/1769879784069.png"
};
window.assetUrl = function (path) {
  var name = String(path || "").replace(/^\/Uploads\//, "");
  return (window.SITE_ASSETS && window.SITE_ASSETS[name]) || path;
};
window.CHARACTER_BASE = (window.SITE_ASSETS && window.SITE_ASSETS["character.png"]) || "/img/character.png";
