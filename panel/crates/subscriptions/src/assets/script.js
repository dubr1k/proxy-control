
(function () {
  function fallback(text) {
    var box = document.createElement("textarea");
    box.value = text;
    box.setAttribute("readonly", "");
    box.className = "offscreen";
    document.body.appendChild(box);
    box.select();
    var done = false;
    try { done = document.execCommand("copy"); } catch (error) { done = false; }
    document.body.removeChild(box);
    return done;
  }
  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-copy]") : null;
    if (!button || button.getAttribute("data-busy")) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source) return;
    var text = source.textContent;
    var label = button.textContent;
    function finish(ok) {
      button.setAttribute("data-busy", "1");
      button.textContent = button.getAttribute(ok ? "data-done" : "data-fail");
      setTimeout(function () { button.textContent = label; button.removeAttribute("data-busy"); }, 2000);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { finish(true); }, function () { finish(fallback(text)); });
    } else {
      finish(fallback(text));
    }
  });
})();
