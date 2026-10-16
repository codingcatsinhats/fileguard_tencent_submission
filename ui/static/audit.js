/* Audit console: row selection + session highlight, details panel
 * toggle/resize (persisted), top-secret-only filter chips. */
(function () {
  function init() {
    const app = document.getElementById("auditApp");
    if (!app) return;
    const dwrap = document.getElementById("dwrap");
    const detail = document.getElementById("detail");
    const grip = document.getElementById("grip");
    const toggle = document.getElementById("toggleDetail");
    const tbody = document.getElementById("tbody");
    const store = {
      get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } },
      set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
    };

    // row click -> fetch the record into the panel; highlight sel + session relatives
    function pick(tr) {
      // a closed panel must come back when the user picks an entry
      if (app.classList.contains("closed")) setOpen(true, true);
      const live = document.getElementById("tbody");  // htmx swaps swap this node
      const seq = tr.dataset.seq;
      live.querySelectorAll("tr.sel, tr.rel").forEach(r => r.classList.remove("sel", "rel"));
      tr.classList.add("sel");
      const sess = tr.dataset.session;
      if (sess) {
        live.querySelectorAll('tr[data-session="' + sess + '"]')
          .forEach(r => { if (r !== tr) r.classList.add("rel"); });
      }
      fetch("/audit/detail/" + seq)
        .then(r => r.ok ? r.text() : Promise.reject(r.status))
        .then(html => { detail.innerHTML = html; })
        .catch(() => { detail.innerHTML = '<p class="meta">Could not load this entry.</p>'; });
    }
    // delegated at document level so the binding survives htmx panel swaps
    document.addEventListener("click", (ev) => {
      const tr = ev.target.closest("tr[data-seq]");
      if (tr) pick(tr);
    });

    // tier filter: frontend-only view filter over the rendered rows —
    // never touches the backend query (bound at document level so it
    // survives htmx swaps of the table)
    document.addEventListener("change", (ev) => {
      if (ev.target && ev.target.id === "tier-filter") {
        filterRows(ev.target.value);
      }
    });

    function filterRows(tier) {
      const live = document.getElementById("tbody");
      if (!live) return;
      live.querySelectorAll("tr[data-tier]").forEach((tr) => {
        tr.hidden = tier !== "" && tr.dataset.tier !== tier;
      });
    }
    document.addEventListener("keydown", (ev) => {
      if (ev.key !== "Enter" && ev.key !== " ") return;
      const tr = ev.target.closest("tr[data-seq]");
      if (tr) { ev.preventDefault(); pick(tr); }
    });

    // Clearance-level filter chips (server renders them for top_secret log view).
    // "All entries" is exclusive — selecting it clears secret/ts. Secret and
    // Top secret are toggle chips: click to activate, click again to deactivate,
    // both can be active simultaneously. When neither is active, "All entries"
    // re-activates.
    // Delegated at document level so the binding survives htmx #amain swaps
    // (sign checkpoint / refresh log replace #chips with fresh HTML).
    document.addEventListener("click", (ev) => {
      const chips = ev.target.closest("#chips");
      if (!chips) return;
      const b = ev.target.closest("button");
      if (!b) return;
      const allBtn = chips.querySelector('button[data-f="all"]');
      const secretBtn = chips.querySelector('button[data-f="secret"]');
      const tsBtn = chips.querySelector('button[data-f="ts"]');

      if (b.dataset.f === "all") {
        // exclusive: clears the toggles
        allBtn.setAttribute("aria-pressed", "true");
        if (secretBtn) secretBtn.setAttribute("aria-pressed", "false");
        if (tsBtn) tsBtn.setAttribute("aria-pressed", "false");
      } else {
        // toggle this chip
        const pressed = b.getAttribute("aria-pressed") === "true";
        b.setAttribute("aria-pressed", String(!pressed));
        // if at least one toggle is active, "all" deactivates; else re-activates
        const secOn = secretBtn && secretBtn.getAttribute("aria-pressed") === "true";
        const tsOn = tsBtn && tsBtn.getAttribute("aria-pressed") === "true";
        allBtn.setAttribute("aria-pressed", String(!(secOn || tsOn)));
      }

      // compute active filter set
      const secOn = secretBtn && secretBtn.getAttribute("aria-pressed") === "true";
      const tsOn = tsBtn && tsBtn.getAttribute("aria-pressed") === "true";
      const filtering = secOn || tsOn;

      const live = document.getElementById("tbody");
      if (!live) return;
      live.querySelectorAll("tr[data-tier-row]").forEach(r => {
        const tier = r.dataset.tierRow;
        if (!filtering) {
          r.hidden = false;
        } else {
          const show = (secOn && tier === "secret") || (tsOn && tier === "ts");
          r.hidden = !show;
        }
      });
      const seams = live.querySelectorAll("tr.seam");
      seams.forEach(r => { r.hidden = filtering; });
    });

    // details panel: toggle + resizable, both persisted
    const MINW = 320, DEF = 420;
    const cw = () => document.documentElement.clientWidth;
    const maxW = () => Math.max(MINW, Math.min(760, cw() - 232 - 360));
    let dw = Number(store.get("fg.dw")) || DEF;

    function setW(w, save) {
      dw = Math.round(Math.min(maxW(), Math.max(MINW, w)));
      app.style.setProperty("--dw", dw + "px");
      if (save) store.set("fg.dw", dw);
    }
    function setOpen(open, save) {
      app.classList.toggle("closed", !open);
      if (toggle) toggle.setAttribute("aria-expanded", String(open));
      if (save) store.set("fg.open", open ? "1" : "0");
    }
    if (toggle) toggle.addEventListener("click", () =>
      setOpen(app.classList.contains("closed"), true));
    const dclose = document.getElementById("dclose");
    if (dclose) dclose.addEventListener("click", () => { setOpen(false, true); });
    dwrap.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") { setOpen(false, true); if (toggle) toggle.focus(); }
    });
    if (grip) {
      grip.addEventListener("pointerdown", (ev) => {
        grip.setPointerCapture(ev.pointerId); grip.classList.add("drag");
        document.body.style.userSelect = "none";
      });
      grip.addEventListener("pointermove", (ev) => {
        if (grip.hasPointerCapture(ev.pointerId)) setW(cw() - ev.clientX);
      });
      const end = (ev) => {
        if (grip.hasPointerCapture(ev.pointerId)) grip.releasePointerCapture(ev.pointerId);
        grip.classList.remove("drag"); document.body.style.userSelect = "";
        store.set("fg.dw", dw);
      };
      grip.addEventListener("pointerup", end);
      grip.addEventListener("pointercancel", end);
      grip.addEventListener("dblclick", () => setW(DEF, true));
      grip.addEventListener("keydown", (ev) => {
        const st = ev.shiftKey ? 48 : 16;
        if (ev.key === "ArrowLeft") { ev.preventDefault(); setW(dw + st, true); }
        if (ev.key === "ArrowRight") { ev.preventDefault(); setW(dw - st, true); }
      });
    }
    addEventListener("resize", () => setW(dw));
    setW(Number(store.get("fg.dw")) || DEF);
    setOpen(store.get("fg.open") !== "0", false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
