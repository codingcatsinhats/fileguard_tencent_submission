/* Upload page: multi-file queue with per-file display names, then one
 * sequential POST /upload per file (the endpoint is single-file).
 * Also handles tab switching and file-list search filtering. */
(function () {
  function init() {
    const drop = document.getElementById("drop");
    if (!drop) return;
    const fileIn = document.getElementById("file");
    const choose = document.getElementById("choose");
    const pendingUl = document.getElementById("pending");
    const msg = document.getElementById("upMsg");
    const go = document.getElementById("upGo");
    const level = document.getElementById("clearance");
    const result = document.getElementById("upload-result");
    const pending = [];
    const LV = ["open", "confidential", "secret", "top secret"];
    const HELD = Number(document.body.dataset.heldIndex || 3);
    const kb = n => n < 1048576 ? Math.max(1, Math.round(n / 1024)) + " KB"
                                : (n / 1048576).toFixed(1) + " MB";

    // --- tab switching ---
    const tabs = document.querySelectorAll(".uptab");
    const panels = document.querySelectorAll(".uptab-panel");
    tabs.forEach(tab => {
      tab.addEventListener("click", () => {
        tabs.forEach(t => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
        tab.classList.add("active");
        tab.setAttribute("aria-selected", "true");
        const target = tab.dataset.tab;
        panels.forEach(p => {
          const show = p.dataset.panel === target;
          p.hidden = !show;
          if (show) p.classList.add("active");
          else p.classList.remove("active");
        });
      });
    });

    // --- file list search ---
    const search = document.getElementById("fileSearch");
    const fileList = document.getElementById("fileList");
    const fileCount = document.getElementById("fileCount");
    const noMatch = document.getElementById("noMatch");
    const noFiles = document.getElementById("noFiles");

    if (search && fileList) {
      const items = [...fileList.querySelectorAll("li[data-name]")];
      const total = items.length;

      function filterFiles() {
        const q = search.value.trim().toLowerCase();
        let shown = 0;
        items.forEach(li => {
          const name = (li.dataset.name || "").toLowerCase();
          const match = !q || name.includes(q);
          li.style.display = match ? "" : "none";
          if (match) shown++;
        });
        if (fileCount) fileCount.textContent = shown + (shown === 1 ? " file" : " files");
        if (noMatch) noMatch.style.display = (shown === 0 && q) ? "block" : "none";
        if (noFiles) noFiles.style.display = (total === 0) ? "" : "none";
      }

      search.addEventListener("input", filterFiles);
    }

    function renderPending() {
      pendingUl.replaceChildren(...pending.map((p, i) => {
        const li = document.createElement("li");
        const fmt = document.createElement("span"); fmt.className = "fmt";
        fmt.textContent = p.f.name.split(".").pop().toUpperCase().slice(0, 4);
        const nm = document.createElement("span"); nm.className = "nm";
        nm.textContent = p.f.name;
        const small = document.createElement("small"); small.textContent = kb(p.f.size);
        nm.append(small);
        const inp = document.createElement("input"); inp.className = "dn";
        inp.placeholder = "Display name (defaults to file name)";
        inp.maxLength = 120;
        inp.setAttribute("aria-label", "Display name for " + p.f.name);
        inp.addEventListener("input", () => { p.name = inp.value; });
        const x = document.createElement("button"); x.className = "ibtn"; x.textContent = "×";
        x.setAttribute("aria-label", "Remove " + p.f.name);
        x.addEventListener("click", () => { pending.splice(i, 1); renderPending(); });
        li.append(fmt, nm, inp, x);
        return li;
      }));
      go.disabled = !pending.length;
    }

    function addFiles(list) {
      const skipped = [];
      msg.textContent = "";
      for (const f of list) {
        const ext = (f.name.split(".").pop() || "").toLowerCase();
        if (["pdf", "docx", "xlsx"].includes(ext)) pending.push({ f, name: "" });
        else skipped.push(f.name);
      }
      if (skipped.length) msg.textContent = "Skipped (unsupported format): " + skipped.join(", ");
      renderPending();
    }

    choose.addEventListener("click", () => fileIn.click());
    fileIn.addEventListener("change", () => { addFiles(fileIn.files); fileIn.value = ""; });
    ["dragenter", "dragover"].forEach(n => drop.addEventListener(n, (e) => {
      e.preventDefault(); drop.classList.add("over");
    }));
    ["dragleave", "drop"].forEach(n => drop.addEventListener(n, (e) => {
      e.preventDefault(); drop.classList.remove("over");
    }));
    drop.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
    drop.addEventListener("click", (e) => { if (e.target === drop) fileIn.click(); });

    go.addEventListener("click", async () => {
      const batch = pending.splice(0);
      renderPending();
      const groups = [...document.querySelectorAll("#uGrp input:checked")].map(c => c.value);
      let okCount = 0;
      for (const { f, name } of batch) {
        const body = new FormData();
        body.append("file", f);
        body.append("clearance", level.value);
        body.append("display_name", name.trim());
        for (const g of groups) body.append("groups", g);
        try {
          const r = await fetch("/upload", { method: "POST", body });
          if (r.ok) okCount++;
          else {
            const txt = await r.text();
            msg.textContent = "Upload failed: " + (txt.replace(/<[^>]+>/g, " ").trim() || r.status);
          }
        } catch (e) {
          msg.textContent = "Upload failed: connection error.";
        }
      }
      if (okCount) {
        result.innerHTML = '<p class="hint">Encrypted and indexed ' + okCount +
          ' file' + (okCount > 1 ? "s" : "") + '.</p>';
        setTimeout(() => window.location.reload(), 800);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
