/* Chat streaming: POST /chat, consume SSE frames from the response body.
 * Live turns render as an agent block: collapsible steps (one per SSE stage
 * event), then the answer text and any source chips the server rendered.
 * htmx handles discrete actions (login, logout, confirm); this handles the
 * live stream, which htmx cannot. */
(function () {
  const HELD = Number(document.body.dataset.heldIndex || 3);
  const LV = ["open", "confidential", "secret", "top secret"];
  const cap = t => t.charAt(0).toUpperCase() + t.slice(1);

  function init() {
    const composer = document.getElementById("composer");
    if (!composer) return; // signed-out or other page

    const messages = document.getElementById("messages");
    const logwrap = document.getElementById("logwrap");
    const input = document.getElementById("message");
    const send = document.getElementById("send");
    const defc = document.getElementById("default-clearance");
    const hint = document.getElementById("defhint");
    const cmpHint = document.getElementById("cmpHint");
    const starters = document.getElementById("starters");
    const empty = document.getElementById("empty");
    let busy = false;

    const scroll = () => requestAnimationFrame(() => {
      logwrap.scrollTop = logwrap.scrollHeight;
    });

    // citation chips toggle their per-source box; the box's ✕ closes it.
    // Delegated on #messages: works for both server-rendered history and
    // SSE-streamed turns (CSP forbids inline handlers).
    messages.addEventListener("click", (e) => {
      const chip = e.target.closest(".cite-chip");
      if (chip) {
        const msg = chip.closest(".msg");
        const box = msg && msg.querySelector(`.cite-box[data-src="${chip.dataset.src}"]`);
        if (box) box.hidden = !box.hidden;
        return;
      }
      const close = e.target.closest(".cite-close");
      if (close) {
        const box = close.closest(".cite-box");
        if (box) box.hidden = true;
      }
    });

    // default-clearance hint, as in the design
    function hints() {
      if (!defc || !hint) return;
      const sel = LV.indexOf(defc.value), over = sel > HELD;
      hint.textContent = over
        ? `Above your clearance. The server will limit requests to ${cap(LV[HELD])}.`
        : "A suggestion for the assistant. It may ask for more. Top-secret access always needs your confirmation.";
      hint.classList.toggle("warn", over);
      if (cmpHint) cmpHint.textContent =
        `Starting at ${cap(LV[Math.min(sel < 0 ? HELD : sel, HELD)])} · Enter to send, Shift+Enter for a new line`;
    }
    if (defc) defc.addEventListener("change", hints);
    hints();

    // starters + confirm-card acknowledgment (delegated; list is swapped often)
    if (starters) starters.addEventListener("click", (ev) => {
      const b = ev.target.closest("button");
      if (b && !busy) { input.value = b.dataset.message; submit(); }
    });
    messages.addEventListener("click", (ev) => {
      const btn = ev.target.closest(".confirm .acts .btn");
      if (!btn) return;
      const card = btn.closest(".confirm");
      if (!card || card.classList.contains("resolved")) return;
      const approved = btn.dataset.approved === "true";
      card.classList.add("resolved");
      const line = card.querySelector(".confirm-progress");
      if (line) {
        line.innerHTML = '<span class="spinner"></span> ' + (approved
          ? "Approved — the agent is working…"
          : "Denied — the agent continues without it…");
        line.classList.add(approved ? "ok" : "no");
      }
      // the confirm post resumes the harness; keep a visible "working" cue
      // and lock the composer until the server swaps in the finished turn
      send.disabled = true;
      busy = true;
    });

    // live agent turn block
    function agentTurn() {
      empty && empty.remove();
      const m = document.createElement("article");
      m.className = "msg agent";
      const g = document.createElement("div"); g.className = "glyph";
      g.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/></svg>';
      const b = document.createElement("div");
      const det = document.createElement("details"); det.className = "steps"; det.open = true;
      const sum = document.createElement("summary"); sum.textContent = "Working…";
      const ul = document.createElement("ul");
      det.append(sum, ul);
      const txt = document.createElement("div"); txt.className = "text";
      b.append(det, txt); m.append(g, b); messages.append(m); scroll();
      let n = 0, last = null;
      return {
        step(label) {
          n++;
          if (last) last();
          const li = document.createElement("li"); li.className = "run";
          const sp = document.createElement("span"); sp.textContent = label;
          li.append(document.createElement("i"), sp); ul.append(li); scroll();
          last = () => { li.className = "done"; };
          return (d) => { li.className = "done"; if (d) { const sm = document.createElement("small"); sm.textContent = d; sp.append(sm); } };
        },
        say(t) {
          if (last) last();
          sum.textContent = `${n} steps completed`; det.open = false;
          txt.innerHTML = t; scroll();
        },
      };
    }

    async function submit() {
      const text = input.value.trim();
      if (!text || busy) return;
      busy = true; send.disabled = true;
      empty && empty.remove();
      starters && (starters.hidden = true);

      const um = document.createElement("div"); um.className = "msg user";
      um.textContent = text; messages.append(um);
      input.value = ""; input.style.height = "auto";
      const turn = agentTurn();
      scroll();

      try {
        const resp = await fetch("/chat", {
          method: "POST",
          body: new URLSearchParams({
            message: text,
            default_clearance: defc ? defc.value : "",
          }),
        });
        if (resp.status === 401) { window.location.href = "/"; return; }
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "", done = false;
        while (!done) {
          const r = await reader.read();
          done = r.done;
          buffer += decoder.decode(r.value || { stream: true });
          let idx;
          while ((idx = buffer.indexOf("\n\n")) !== -1) {
            const frame = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            let event = "message", data = "";
            for (const line of frame.split("\n")) {
              if (line.startsWith("event: ")) event = line.slice(7).trim();
              else if (line.startsWith("data: ")) data += line.slice(6);
            }
            if (!data) continue;
            const d = JSON.parse(data);
            if (event === "stage") turn.step(d.label);
            else if (event === "messages") {
              messages.innerHTML = d.html;
              if (window.htmx) window.htmx.process(messages);
              scroll();
            }
          }
        }
      } catch (err) {
        turn.say("Connection error — please try again.");
      } finally {
        busy = false; send.disabled = false; input.focus();
      }
    }

    // htmx drives the confirm post: release the composer when the resumed
    // turn lands (or when the post errors, so the UI never stays locked)
    const unlock = () => { busy = false; send.disabled = false; input.focus(); };
    document.addEventListener("htmx:afterSwap", (e) => {
      if (e.detail.target && e.detail.target.id === "messages") unlock();
    });
    document.addEventListener("htmx:responseError", (e) => {
      if (e.detail.target && e.detail.target.id === "messages") unlock();
    });

    send.addEventListener("click", submit);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
    });
    input.addEventListener("input", () => {
      input.style.height = "auto";
      input.style.height = Math.min(input.scrollHeight, 160) + "px";
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
