// ti2dac web UI: progressive enhancement only. Every form posts normally without this file.
(function () {
  "use strict";
  var doc = document.documentElement;
  doc.classList.remove("no-js");
  doc.classList.add("js");

  function store(kind, key, val) {
    try {
      var s = kind === "local" ? window.localStorage : window.sessionStorage;
      if (val === undefined) return s.getItem(key);
      s.setItem(key, val);
    } catch (e) { return null; }
  }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // ---------------------------------------------------------------- theme
  function isDark() {
    var t = doc.getAttribute("data-theme");
    return t ? t === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
  }
  $$("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var next = isDark() ? "light" : "dark";
      doc.setAttribute("data-theme", next);
      store("local", "ti2dac-theme", next);
    });
  });

  // ---------------------------------------------------------------- mobile sidebar
  $$("[data-nav-toggle]").forEach(function (el) {
    el.addEventListener("click", function () { document.body.classList.toggle("nav-open"); });
  });

  // ---------------------------------------------------------------- tabs
  // <div data-tabs="key"> with [role=tab][data-tab=x] and [role=tabpanel][data-panel=x]
  function activate(group, name, remember) {
    var tabs = $$('[role="tab"]', group).filter(function (t) { return t.closest("[data-tabs]") === group; });
    var panels = $$('[role="tabpanel"]', group).filter(function (p) { return p.closest("[data-tabs]") === group; });
    if (!tabs.some(function (t) { return t.dataset.tab === name; })) return false;
    tabs.forEach(function (t) {
      var on = t.dataset.tab === name;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
    });
    panels.forEach(function (p) { p.classList.toggle("active", p.dataset.panel === name); });
    if (remember && group.dataset.tabs) store("session", "tab:" + group.dataset.tabs, name);
    return true;
  }
  $$("[data-tabs]").forEach(function (group) {
    var tabs = $$('[role="tab"]', group).filter(function (t) { return t.closest("[data-tabs]") === group; });
    if (!tabs.length) return;
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { activate(group, t.dataset.tab, true); });
      t.addEventListener("keydown", function (e) {
        var d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        var n = tabs[(i + d + tabs.length) % tabs.length];
        activate(group, n.dataset.tab, true);
        n.focus();
      });
    });
    var hash = location.hash.slice(1);
    var saved = group.dataset.tabs ? store("session", "tab:" + group.dataset.tabs) : null;
    activate(group, hash, false) || (group.dataset.open && activate(group, group.dataset.open, true)) ||
      (saved && activate(group, saved, false)) || activate(group, tabs[0].dataset.tab, false);
  });

  // ---------------------------------------------------------------- copy buttons
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (ok, fail) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? ok() : fail(); } catch (e) { fail(e); }
      document.body.removeChild(ta);
    });
  }
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    var src = btn.getAttribute("data-copy");
    var text = src && src.charAt(0) === "#" ? (document.querySelector(src) || {}).textContent : src;
    if (!text) {
      var pre = btn.closest(".code") && btn.closest(".code").querySelector("pre");
      text = pre ? pre.textContent : "";
    }
    copyText(text).then(function () {
      var label = btn.querySelector(".lbl");
      var old = label ? label.textContent : null;
      btn.classList.add("copied");
      if (label && old) label.textContent = "Copied";
      setTimeout(function () { btn.classList.remove("copied"); if (label && old) label.textContent = old; }, 1400);
    });
  });

  // ---------------------------------------------------------------- new-run form
  var runForm = document.getElementById("new-run");
  if (runForm) {
    var zone = runForm.querySelector(".dropzone");
    var file = runForm.querySelector('input[type="file"]');
    var url = runForm.querySelector('input[name="url"]');
    var nameEl = runForm.querySelector(".dz-name");
    function showFile() {
      var f = file.files && file.files[0];
      zone.classList.toggle("has-file", !!f);
      if (f && nameEl) nameEl.textContent = f.name + " · " + Math.max(1, Math.round(f.size / 1024)) + " KB";
    }
    file.addEventListener("change", showFile);
    ["dragenter", "dragover"].forEach(function (ev) { zone.addEventListener(ev, function () { zone.classList.add("drag"); }); });
    ["dragleave", "drop"].forEach(function (ev) { zone.addEventListener(ev, function () { zone.classList.remove("drag"); }); });
    var clear = runForm.querySelector("[data-clear-file]");
    if (clear) clear.addEventListener("click", function (e) { e.preventDefault(); file.value = ""; showFile(); });
    showFile();
    runForm.addEventListener("submit", function (e) {
      // only the visible source is sent, so a stale file never overrides a typed URL
      var mode = (runForm.querySelector('[data-tabs] [aria-selected="true"]') || {}).dataset;
      mode = mode ? mode.tab : "";
      if (mode === "url") { file.value = ""; } else if (mode === "upload") { url.value = ""; }
      if (!(file.files && file.files.length) && !url.value.trim()) {
        e.preventDefault();
        var hint = runForm.querySelector("[data-source-hint]");
        if (hint) { hint.hidden = false; }
        (mode === "url" ? url : zone).scrollIntoView({ block: "center", behavior: "smooth" });
        if (mode === "url") url.focus();
      }
    });
  }

  // forms that throw work away ask first (registered before data-busy, which skips prevented submits)
  $$("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // buttons that start long work show a spinner and block double submits
  $$("form[data-busy]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      var b = f.querySelector('button[type="submit"]');
      if (b) { b.classList.add("loading"); setTimeout(function () { b.disabled = true; }, 0); }
    });
  });

  // ---------------------------------------------------------------- behaviour selection
  var genForm = document.getElementById("generate-form");
  if (genForm) {
    var bar = genForm.querySelector(".selbar");
    var countEl = genForm.querySelector("[data-sel-count]");
    var listEl = genForm.querySelector("[data-sel-list]");
    function sync() {
      var picked = $$('input[name="pick"]:checked', genForm).map(function (x) { return x.value; });
      genForm.elements.select.value = picked.join(",");
      $$('input[name="pick"]', genForm).forEach(function (x) { x.closest("tr").classList.toggle("selected", x.checked); });
      if (bar) bar.classList.toggle("show", picked.length > 0);
      if (countEl) countEl.textContent = picked.length + (picked.length === 1 ? " behaviour" : " behaviours");
      if (listEl) listEl.textContent = picked.join(", ");
    }
    genForm.addEventListener("change", sync);
    var none = genForm.querySelector("[data-sel-clear]");
    if (none) none.addEventListener("click", function () { $$('input[name="pick"]', genForm).forEach(function (x) { x.checked = false; }); sync(); });
    sync();
  }

  // ---------------------------------------------------------------- client-side table filter
  $$("[data-filter]").forEach(function (input) {
    var table = document.querySelector(input.getAttribute("data-filter"));
    if (!table) return;
    var rows = $$("tbody tr[data-row]", table);
    var empty = table.querySelector("[data-filter-empty]");
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var shown = 0;
      rows.forEach(function (r) {
        var on = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.hidden = !on; if (on) shown++;
      });
      if (empty) empty.hidden = shown !== 0;
    });
  });

  // ---------------------------------------------------------------- scroll-spy for the run page rail
  var railLinks = $$(".rail a[href^='#']");
  if (railLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    railLinks.forEach(function (a) { byId[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        railLinks.forEach(function (a) { a.classList.remove("active"); });
        var a = byId[en.target.id]; if (a) a.classList.add("active");
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    Object.keys(byId).forEach(function (id) { var el = document.getElementById(id); if (el) io.observe(el); });
  }

  // ---------------------------------------------------------------- live job progress
  var job = document.querySelector("[data-job]");
  if (job) {
    var id = job.getAttribute("data-job");
    var list = job.querySelector(".timeline");
    var statusEl = job.querySelector("[data-job-status]");
    var errEl = job.querySelector("[data-job-error]");
    var check = '<svg class="i" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>';
    var cross = '<svg class="i" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>';
    function render(j) {
      var running = j.status === "running";
      list.innerHTML = "";
      (j.log || []).forEach(function (line, i, all) {
        var last = i === all.length - 1;
        var li = document.createElement("li");
        if (last && running) li.className = "current";
        if (last && j.status === "failed") li.className = "failed";
        var ico = document.createElement("span");
        ico.className = "tl-ico";
        ico.innerHTML = last && running ? '<span class="spin"></span>' : last && j.status === "failed" ? cross : check;
        var tx = document.createElement("span");
        tx.className = "tl-text"; tx.textContent = line;
        li.appendChild(ico); li.appendChild(tx); list.appendChild(li);
      });
      if (statusEl) {
        statusEl.className = "badge " + (running ? "warn" : j.status === "done" ? "ok" : "bad");
        statusEl.innerHTML = '<span class="dot ' + (running ? "warn pulse" : j.status === "done" ? "ok" : "bad") + '"></span>';
        statusEl.appendChild(document.createTextNode(j.status));
      }
      if (errEl && j.error) { errEl.hidden = false; errEl.querySelector("[data-msg]").textContent = j.error; }
      var stopForm = job.querySelector("[data-job-stop]");
      if (stopForm && !running) stopForm.hidden = true;
    }
    var live = job.querySelector("[data-job-live]");
    var delay = 1500;
    function stop(msg) {
      if (!live) return;
      if (msg) live.textContent = msg; else live.hidden = true;
    }
    (function poll() {
      fetch("/api/jobs/" + encodeURIComponent(id), { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (r) {
          if (r.status >= 400 && r.status < 500) {   // retrying cannot fix these
            var e = new Error(r.status); e.final = true; throw e;
          }
          if (!r.ok) throw new Error(r.status);
          return r.json();
        })
        .then(function (j) {
          delay = 1500;
          render(j);
          if (j.status === "done" && j.run_id) { location.href = "/runs/" + encodeURIComponent(j.run_id); return; }
          if (j.status === "running") setTimeout(poll, delay);
          else stop();
        })
        .catch(function (e) {
          if (e && e.final) {
            stop(e.message === "401" ? "stopped updating: signed out, reload the page to sign in" :
              e.message === "404" ? "stopped updating: this job no longer exists" : "stopped updating (HTTP " + e.message + "); reload the page");
            return;
          }
          delay = Math.min(delay * 2, 30000);   // server or network trouble: back off
          setTimeout(poll, delay);
        });
    })();
  }
})();
