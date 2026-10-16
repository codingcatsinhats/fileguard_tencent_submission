/* Audit chat: form-POST composer (PRG — full reload per message) + starters.
 * Kept separate from chat.js (which streams the user chat over SSE). */
(function () {
  function init() {
    const ta = document.getElementById("amessage");
    if (!ta) return; // not on the audit chat page
    const send = document.getElementById("asend");
    const submit = () => {
      const m = ta.value.trim();
      if (!m) return;
      // loading state: freeze the composer, show a spinner row while the
      // POST round-trip runs. Clear the box too — the redirect lands on
      // the same URL, and browsers restore form state on same-URL loads.
      ta.value = "";
      ta.disabled = true;
      send.disabled = true;
      const log = document.getElementById("achatlog");
      if (log) {
        const empty = document.getElementById("aempty");
        if (empty) empty.remove();
        // show the sent message immediately, then the pending row —
        // otherwise the round-trip looks like nothing happened
        const mine = document.createElement("div");
        mine.className = "achat-msg user";
        mine.textContent = m;
        log.appendChild(mine);
        const load = document.createElement("div");
        load.className = "achat-msg achat-loading";
        load.innerHTML = '<span class="spinner"></span>Querying the audit log…';
        log.appendChild(load);
        log.scrollTop = log.scrollHeight;
      }
      const f = document.createElement("form");
      f.method = "post";
      f.action = "/audit/chat/send";
      const i = document.createElement("input");
      i.type = "hidden"; i.name = "message"; i.value = m;
      f.appendChild(i);
      document.body.appendChild(f);
      f.submit();
    };
    send.addEventListener("click", submit);
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    document.querySelectorAll("#astarters button").forEach((b) => {
      b.addEventListener("click", () => {
        ta.value = b.dataset.message || "";
        ta.focus();
      });
    });
    // after a PRG reload, land on the newest exchange
    const log = document.getElementById("achatlog");
    if (log) log.scrollTop = log.scrollHeight;
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
