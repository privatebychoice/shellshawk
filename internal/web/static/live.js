// Live panels (e.g. conference thread chat): new lines arrive over
// server-sent events from this server, and the form sends without
// reloading the page. Without JavaScript the panel still works: the form
// posts normally and the page shows the logged history. Nothing is stored
// in the browser and no other site is contacted.
(function () {
  "use strict";
  var MAX_LINES = 300;
  if (!window.EventSource) { return; }
  var panels = document.querySelectorAll("[data-live-events]");
  Array.prototype.forEach.call(panels, function (panel) {
    var log = panel.querySelector("[data-live-log]");
    var status = panel.querySelector("[data-live-status]");
    var form = panel.querySelector("form[data-live-form]");
    var input = form ? form.querySelector("[name=message]") : null;
    if (!log) { return; }

    function say(text) {
      if (status) { status.textContent = text; }
    }
    function add(text) {
      var empty = log.querySelector("[data-live-empty]");
      if (empty) { log.removeChild(empty); }
      var li = document.createElement("li");
      li.textContent = text;
      log.appendChild(li);
      while (log.children.length > MAX_LINES) { log.removeChild(log.firstElementChild); }
      log.scrollTop = log.scrollHeight;
    }

    log.scrollTop = log.scrollHeight;
    var es = new EventSource(panel.getAttribute("data-live-events"));
    es.addEventListener("open", function () { say("Connected: new messages appear as they are sent."); });
    es.addEventListener("line", function (e) { add(e.data); });
    es.addEventListener("end", function (e) {
      es.close();
      if (e.data) { add(e.data); }
      say("This chat has ended for you. Reload the page to check again.");
      if (form) { form.hidden = true; }
    });
    es.addEventListener("error", function () {
      if (es.readyState === EventSource.CLOSED) {
        say("Live updates stopped. Reload the page to reconnect.");
      } else {
        say("Connection lost. Reconnecting; messages sent meanwhile may be missed.");
      }
    });

    if (form && input && window.fetch && window.URLSearchParams && window.FormData) {
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        if (!input.value.trim()) { return; }
        fetch(form.action, {
          method: "POST",
          body: new URLSearchParams(new FormData(form)),
          headers: { "Accept": "text/plain" },
          credentials: "same-origin",
          redirect: "manual"
        }).then(function (res) {
          if (res.ok || res.type === "opaqueredirect") {
            input.value = "";
            input.focus();
            return;
          }
          return res.text().then(function (t) { say(t || "Your message was not sent."); });
        }).catch(function () {
          say("Your message was not sent: the server could not be reached.");
        });
      });
    }
  });
})();
