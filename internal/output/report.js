(function () {
  var form = document.getElementById("filters");
  if (!form) { return; }
  form.hidden = false;
  var ctl = {
    env: document.getElementById("f-env"),
    kind: document.getElementById("f-kind"),
    sev: document.getElementById("f-sev"),
    status: document.getElementById("f-status"),
    q: document.getElementById("f-q")
  };
  var all = function (sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); };
  var rows = all("tr[data-kind]");
  var roots = all("details.root");
  var acks = all("details.acks");
  var envs = all("section.env");
  var shown = document.getElementById("shown");

  roots.concat(acks).forEach(function (d) { d.dataset.open = d.open ? "1" : "0"; });

  function visibleIn(el) {
    var n = 0;
    var list = el.querySelectorAll("tr[data-kind]");
    for (var i = 0; i < list.length; i++) {
      if (!list[i].hidden) { n++; }
    }
    return n;
  }

  function total(el) { return el.querySelectorAll("tr[data-kind]").length; }

  function apply() {
    var env = ctl.env.value, kind = ctl.kind.value, status = ctl.status.value;
    var sev = parseInt(ctl.sev.value, 10), q = ctl.q.value.trim().toLowerCase();
    var rowActive = kind !== "" || status !== "" || sev > 0 || q !== "";
    var active = rowActive || env !== "";
    var count = 0;
    rows.forEach(function (r) {
      var ok = (env === "" || r.dataset.env === env) &&
        (kind === "" || r.dataset.kind === kind) &&
        (status === "" || r.dataset.status === status) &&
        parseInt(r.dataset.sev, 10) >= sev &&
        (q === "" || r.dataset.q.indexOf(q) !== -1);
      r.hidden = !ok;
      if (ok) { count++; }
    });
    acks.forEach(function (d) {
      var n = visibleIn(d);
      d.hidden = rowActive && n === 0;
      d.open = active ? n > 0 : d.dataset.open === "1";
    });
    roots.forEach(function (d) {
      var n = visibleIn(d);
      d.hidden = (env !== "" && d.dataset.env !== env) || (rowActive && n === 0);
      d.open = active ? n > 0 : d.dataset.open === "1";
    });
    envs.forEach(function (s) {
      s.hidden = (env !== "" && s.dataset.env !== env) ||
        (rowActive && s.querySelectorAll("details.root:not([hidden])").length === 0);
    });
    shown.textContent = count + " of " + rows.length + " Findings shown";
  }

  function reset() {
    ctl.env.value = "";
    ctl.kind.value = "";
    ctl.status.value = "";
    ctl.sev.value = "0";
    ctl.q.value = "";
    apply();
  }

  function openTarget() {
    var el = location.hash.length > 1 ? document.getElementById(location.hash.slice(1)) : null;
    if (!el || !el.classList.contains("root")) { return; }
    if (el.hidden) { reset(); }
    el.open = true;
    el.dataset.open = "1";
    el.scrollIntoView();
  }

  ["env", "kind", "sev", "status"].forEach(function (k) { ctl[k].addEventListener("change", apply); });
  ctl.q.addEventListener("input", apply);
  form.addEventListener("submit", function (e) { e.preventDefault(); });
  all("a.envlink").forEach(function (a) {
    a.addEventListener("click", function () {
      ctl.env.value = a.dataset.env;
      apply();
    });
  });
  all("a.cell").forEach(function (a) {
    a.addEventListener("click", function () { setTimeout(openTarget, 0); });
  });
  window.addEventListener("hashchange", openTarget);
  apply();
  openTarget();
})();
