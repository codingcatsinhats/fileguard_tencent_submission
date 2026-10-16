// token show/hide toggle (delegated: works on both login pages)
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.token-toggle');
  if (!btn) return;
  var input = btn.parentElement.querySelector('input');
  var hiding = input.type === 'text';
  input.type = hiding ? 'password' : 'text';
  btn.classList.toggle('is-off', hiding);
  btn.setAttribute('aria-pressed', String(hiding));
  btn.setAttribute('aria-label', hiding ? 'Show token' : 'Hide token');
  input.focus();
});

// login failures arrive as 4xx, which htmx will not swap — show the body
document.addEventListener("htmx:responseError", function (e) {
  const t = e.detail.target;
  if (t && t.id === "login-result") {
    t.innerHTML = e.detail.xhr.responseText || "Incorrect token.";
  }
});
