(function() {
  var storageKey = "sa-docs-theme";
  var root = document.documentElement;
  var theme = null;

  try {
    theme = localStorage.getItem(storageKey);
  } catch (err) {}

  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  root.setAttribute("data-theme", theme);
  root.style.colorScheme = theme;
})();
