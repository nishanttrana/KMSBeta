/* global document, localStorage, window */
// Sets the saved or system theme before first paint. It is a file, not an
// inline script, because the console's CSP (script-src 'self') refuses
// inline scripts.
(function () {
  var theme = "dark";
  try {
    var saved = localStorage.getItem("vecta.theme");
    if (saved === "dark" || saved === "light") theme = saved;
    else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) theme = "light";
  } catch { /* storage unavailable: keep dark */ }
  document.documentElement.setAttribute("data-theme", theme);
})();
