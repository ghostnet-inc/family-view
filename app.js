/* Family accounts — a read-only page. It fetches one file (its own data.enc.json), opens it in this
   browser with the password, and draws it. Nothing is ever sent anywhere: no form, no write, no other
   address. Text goes in with textContent only. */
(function () {
  "use strict";

  /* Constants are written as expressions on purpose: the page's files may hold no run of 3+ digits. */
  var minIter = 6e5;
  var version = 1;
  var keyBits = 8 * 32;
  var fields = ["ct", "iter", "iv", "salt", "v"];
  var dbName = "family-accounts";
  var storeName = "k";
  var badText = "That password didn't work.";
  var changedText = "The password changed — type the new one.";

  /* A framed copy shows nothing (clickjacking): the body stays hidden and we try to break out. */
  if (window.top !== window.self) {
    try { window.top.location = window.self.location.href; } catch (e) { /* cross-origin: stay hidden */ }
    return;
  }
  document.body.classList.remove("locked");

  var $ = function (id) { return document.getElementById(id); };
  var env = null;
  var data = null;
  var remember = false;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }

  function canonical(pw) {
    return pw.toLowerCase().split(/\s+/).filter(Boolean).join(" ");
  }

  function bytes(b64) {
    var s = atob(b64);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) { out[i] = s.charCodeAt(i); }
    return out;
  }

  function checkEnv(e) {
    if (!e || typeof e !== "object") { return false; }
    var keys = Object.keys(e).sort();
    if (keys.join(",") !== fields.join(",")) { return false; }
    if (e.v !== version) { return false; }
    if (typeof e.iter !== "number" || !Number.isInteger(e.iter) || e.iter < minIter) { return false; }
    return ["ct", "iv", "salt"].every(function (k) { return typeof e[k] === "string"; });
  }

  function aad(e) {
    return new TextEncoder().encode("family-share|v=" + e.v + "|iter=" + e.iter + "|salt=" + e.salt);
  }

  function deriveKey(pw, e) {
    var raw = new TextEncoder().encode(canonical(pw));
    return crypto.subtle.importKey("raw", raw, { name: "pbkdf2" }, false, ["deriveKey"]).then(function (base) {
      return crypto.subtle.deriveKey(
        { name: "pbkdf2", salt: bytes(e.salt), iterations: e.iter, hash: "sha-" + keyBits },
        base, { name: "aes-gcm", length: keyBits }, false, ["decrypt"]);
    });
  }

  function open(key, e) {
    return crypto.subtle.decrypt({ name: "aes-gcm", iv: bytes(e.iv), additionalData: aad(e) }, key, bytes(e.ct))
      .then(function (plain) { return new Response(plain).json(); });
  }

  /* ── Remember: a non-extractable key in IndexedDB, keyed to the salt (a new password = a new salt) ── */
  function db() {
    return new Promise(function (resolve, reject) {
      try {
        var req = indexedDB.open(dbName, 1);
        req.onupgradeneeded = function () { req.result.createObjectStore(storeName); };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { reject(req.error); };
      } catch (err) { reject(err); }
    });
  }

  function store(mode, fn) {
    return db().then(function (d) {
      return new Promise(function (resolve, reject) {
        try {
          var tx = d.transaction(storeName, mode);
          var r = fn(tx.objectStore(storeName));
          tx.oncomplete = function () { d.close(); resolve(r && r.result); };
          tx.onerror = function () { d.close(); reject(tx.error); };
        } catch (err) { d.close(); reject(err); }
      });
    });
  }

  function saved() {
    return store("readonly", function (s) { return s.get("key"); }).catch(function () { return null; });
  }

  function keep(key, salt) {
    return store("readwrite", function (s) { return s.put({ key: key, salt: salt }, "key"); }).catch(function () { return null; });
  }

  function forget() {
    return store("readwrite", function (s) { return s.clear(); }).catch(function () { return null; });
  }

  /* ── drawing: plain words, no badges ── */
  function totalText(t) {
    if (t.kind === "amount") { return t.text; }
    return t.kind === "novalue" ? "No value yet" : "—";
  }

  function rowNode(r) {
    var row = el("div", "row");
    var sym = el("span", "sym", r.symbol);
    if (r.tag) { sym.appendChild(el("span", "tag", " · " + r.tag)); }
    if (r.price !== null) { sym.title = r.price + " each · " + r.price_label; }
    row.appendChild(sym);
    row.appendChild(el("span", "num", r.shares === null ? "" : r.shares));
    row.appendChild(r.value !== null ? el("span", "value", r.value) : el("span", "value hint", r.note || ""));
    return row;
  }

  function cardNode(c) {
    var card = el("article", "card");
    var head = el("div", "card-head");
    var title = el("p", "card-title", c.broker);
    title.appendChild(el("span", "kind", " · " + c.type));
    head.appendChild(title);
    head.appendChild(c.excluded ? el("span", "hint", c.excluded + " — not in totals") : el("span", "card-total", totalText(c.total)));
    card.appendChild(head);
    if (c.banked !== null) {
      var b = el("div", "row cash");
      b.appendChild(el("span", "sym", "Cash"));
      b.appendChild(el("span", "num", ""));
      b.appendChild(el("span", "value" + (c.banked_neg ? " neg" : ""), c.banked));
      card.appendChild(b);
    }
    c.rows.forEach(function (r) { card.appendChild(rowNode(r)); });
    return card;
  }

  function select(i) {
    var tabs = $("tabs").children;
    for (var j = 0; j < tabs.length; j++) { tabs[j].setAttribute("aria-current", j === i ? "page" : "false"); }
  }

  function show(i) {
    var p = data.people[i];
    select(i);
    $("crash").hidden = true;
    $("cards").hidden = false;
    var top = $("top");
    top.hidden = false;
    top.replaceChildren();
    top.appendChild(el("p", "name", p.name));
    top.appendChild(el("span", "big", totalText(p.total)));
    var words = [];
    if (p.prices) { words.push(p.prices); }
    if (p.without_value) { words.push(p.without_value + (p.without_value === 1 ? " account" : " accounts") + " without a value"); }
    if (p.other_currency) { words.push(p.other_currency + " in another currency, not in the total"); }
    if (words.length) { top.appendChild(el("p", "prices", words.join(" · "))); }
    var cards = $("cards");
    cards.replaceChildren();
    if (!p.cards.length) { cards.appendChild(el("p", "empty", "No accounts yet.")); }
    p.cards.forEach(function (c) { cards.appendChild(cardNode(c)); });
  }

  function crashItem(it) {
    if (it.kind === "table") {
      var t = el("table");
      var head = el("tr");
      it.rows[0].forEach(function (h, k) { head.appendChild(el("th", it.numeric[k] ? "n" : null, h)); });
      var thead = el("thead");
      thead.appendChild(head);
      t.appendChild(thead);
      var body = el("tbody");
      it.rows.slice(1).forEach(function (r) {
        var tr = el("tr");
        r.forEach(function (c, k) { tr.appendChild(el("td", it.numeric[k] ? "n" : null, c)); });
        body.appendChild(tr);
      });
      t.appendChild(body);
      return t;
    }
    if (it.kind === "ul") {
      var ul = el("ul");
      it.lines.forEach(function (ln) { ul.appendChild(el("li", null, ln)); });
      return ul;
    }
    if (it.kind === "gap") { return null; }
    var p = el("div");
    it.lines.forEach(function (ln) { p.appendChild(el("p", it.kind === "source" ? "src" : null, ln)); });
    return p;
  }

  function showCrash(i) {
    select(i);
    $("top").hidden = true;
    $("cards").hidden = true;
    var box = $("crash");
    box.hidden = false;
    box.replaceChildren();
    var c = data.crash;
    if (!c) { box.appendChild(el("p", "empty", "Crash page not available.")); return; }
    box.appendChild(el("h2", null, c.title));
    box.appendChild(el("p", "dateline", c.dateline));
    c.sections.forEach(function (s) {
      var sec = el("section");
      sec.appendChild(el("h3", null, s.heading));
      s.items.forEach(function (it) { var n = crashItem(it); if (n) { sec.appendChild(n); } });
      box.appendChild(sec);
    });
    if (c.closing) { box.appendChild(el("p", "closing", c.closing)); }
  }

  function tab(label, onClick) {
    var t = el("button", "tab", label);
    t.type = "button";
    t.title = label;
    t.addEventListener("click", onClick);
    return t;
  }

  function draw(d, fromMemory) {
    data = d;
    var tabs = $("tabs");
    tabs.replaceChildren();
    d.people.forEach(function (p, i) { tabs.appendChild(tab(p.name, function () { show(i); })); });
    var crashAt = d.people.length;
    tabs.appendChild(tab("Crash", function () { showCrash(crashAt); }));
    $("made").textContent = "Updated " + new Date(d.made_at).toLocaleString();
    $("forget").hidden = !fromMemory && !remember;
    $("gate").hidden = true;
    $("view").hidden = false;
    if (d.people.length) { show(0); } else { showCrash(crashAt); }
  }

  function fail() {
    var m = $("msg");
    m.textContent = badText;
    m.hidden = false;
    $("open").disabled = false;
    $("open").textContent = "Open";
  }

  /* A remembered key that no longer opens the page (a new password = a new salt, or a decrypt that
     fails): say the password changed, never "didn't work", and clear the dead key. */
  function changed() {
    return forget().then(function () {
      var m = $("msg");
      m.textContent = changedText;
      m.hidden = false;
    });
  }

  /* The data file is fetched once, at load; a password typed before it arrives waits for it (never a
     false "didn't work"). */
  var ready = fetch("data.enc.json", { cache: "no-store", credentials: "omit" })
    .then(function (r) { if (!r.ok) { throw new Error("no data"); } return r.json(); })
    .then(function (e) { env = e; }, function () { env = null; });

  function tryPassword() {
    var pw = $("pw").value;
    $("msg").hidden = true;
    $("open").disabled = true;
    $("open").textContent = "Opening…";
    ready.then(function () {
      if (!env || !checkEnv(env) || !canonical(pw)) { throw new Error("refused"); }
      return deriveKey(pw, env).then(function (key) {
        return open(key, env).then(function (d) {
          $("pw").value = "";
          var after = remember ? keep(key, env.salt) : Promise.resolve();
          return after.then(function () { draw(d, false); });
        });
      });
    }).catch(fail);
  }

  $("open").addEventListener("click", tryPassword);
  $("pw").addEventListener("keydown", function (e) { if (e.key === "Enter") { tryPassword(); } });
  $("remember").addEventListener("click", function () {
    remember = !remember;
    $("remember").setAttribute("aria-pressed", remember ? "true" : "false");
  });
  $("forget").addEventListener("click", function (e) {
    e.preventDefault();
    forget().then(function () { window.location.reload(); });
  });

  ready.then(function () {
    if (!env || !checkEnv(env)) { return; }
    return saved().then(function (rec) {
      if (!rec || !rec.key) { return; }
      if (rec.salt !== env.salt) { return changed(); }
      return open(rec.key, env).then(function (d) { draw(d, true); }, changed);
    });
  }).catch(function () { return null; });
})();
