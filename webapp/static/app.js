// Ask before a destructive form submits (inline handlers are blocked by the CSP).
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// Tell the server this browser's time zone, so reports show your local time.
try {
  document.cookie = "tz=" + Intl.DateTimeFormat().resolvedOptions().timeZone +
    "; path=/; SameSite=Lax; max-age=31536000";
} catch (e) {}
