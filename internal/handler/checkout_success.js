/* Behavior for the checkout success page. The provisioned API key is read
   from the DOM (#api-key) — this file is static and never contains
   templated values. */

/* Copy-to-clipboard for the provisioned API key */
(function() {
  var btn = document.getElementById('copy-key');
  var keyEl = document.getElementById('api-key');
  if (!btn || !keyEl) return;

  btn.addEventListener('click', function() {
    var key = keyEl.textContent;
    navigator.clipboard.writeText(key).then(function() {
      btn.textContent = 'Copied!';
      setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
    });
  });
})();

/* Follow system theme changes when no explicit preference is stored */
(function() {
  var storageKey = "sa-docs-theme";
  var root = document.documentElement;
  if (!window.matchMedia) return;
  var media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", function(event) {
    var saved;
    try { saved = localStorage.getItem(storageKey); } catch (e) {}
    if (saved === "light" || saved === "dark") return;
    root.setAttribute("data-theme", event.matches ? "dark" : "light");
    root.style.colorScheme = event.matches ? "dark" : "light";
  });
})();
