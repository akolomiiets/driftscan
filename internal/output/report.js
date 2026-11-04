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
  var rows = Array.prototype.slice.call(document.querySelectorAll("tr[data-kind]"));
  var roots = Array.prototype.slice.call(document.querySelectorAll("details.root"));
  var acks = Array.prototype.slice.call(document.querySelectorAll("details.acks"));
  var envs = Array.prototype.slice.call(document.querySelectorAll("section.env"));
  var shown = document.getElementById("shown");

  function visibleIn(el) {
    var n = 0;
    var list = el.querySelectorAll("tr[data-kind]");
    for (var i = 0; i < list.length; i++) {
      if (!list[i].hidden) { n++; }
    }
    return n;
  }

  function apply() {
    var env = ctl.env.value, kind = ctl.kind.value, status = ctl.status.value;
    var sev = parseInt(ctl.sev.value, 10), q = ctl.q.value.trim().toLowerCase();
    var active = env !== "" || kind !== "" || status !== "" || sev > 0 || q !== "";
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
    acks.forEach(function (d) { d.hidden = active && visibleIn(d) === 0; });
    roots.forEach(function (d) { d.hidden = active && visibleIn(d) === 0; });
    envs.forEach(function (s) {
      s.hidden = active && s.querySelectorAll("details.root:not([hidden])").length === 0;
    });
    shown.textContent = count + " of " + rows.length + " Findings shown";
  }

  form.addEventListener("input", apply);
  form.addEventListener("change", apply);
  form.addEventListener("submit", function (e) { e.preventDefault(); });
  apply();
})();
