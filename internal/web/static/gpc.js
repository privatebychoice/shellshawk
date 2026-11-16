// Shows a notice when the browser sends Global Privacy Control
// (navigator.globalPrivacyControl). The server also detects the Sec-GPC
// header. Nothing is stored or sent.
(function () {
  if (navigator.globalPrivacyControl === true) {
    var el = document.getElementById("gpc-js");
    if (el) { el.hidden = false; }
  }
})();
