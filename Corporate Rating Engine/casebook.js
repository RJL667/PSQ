/* casebook.js — past deals as test cases: list, record the real outcome, process, compare, correct.
 * Server: /api/cases*, /api/questionnaire, /api/casebook/learnings. Premium is priced here with the
 * same engine the rater uses (CorpEngine), so rater and casebook can never disagree on the maths.
 */
(function () {
  "use strict";
  const D = window.CORP_DATA;
  const E = window.CorpEngine;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const zar0 = (n) => (n == null || isNaN(n)) ? "—" : "R " + Math.round(n).toLocaleString("en-ZA");
  const pct = (x) => (x == null ? "—" : Math.round(x * 100) + "%");
  const num = (s) => { if (s === "" || s == null) return null; const n = parseFloat(String(s).replace(/[^0-9.\-]/g, "")); return isNaN(n) ? null : n; };
  const banner = (cls, icon, html) => `<div class="banner ${cls}" style="margin-top:12px"><span class="b-icon">${icon}</span><span>${html}</span></div>`;
  const DECISIONS = [["", "— not recorded —"], ["quoted", "Quoted as standard"], ["quoted_subject_to", "Quoted subject to conditions"], ["declined", "Declined"], ["referred", "Referred / more information asked"]];
  const ROLES = [["proposal", "Proposal form"], ["quote", "Issued quote / terms"], ["other", "Other"]];
  const STATUS_TEXT = { ready: "Ready to quote", conditions_not_met: "Conditions not met", information_required: "Information required" };
  const VERDICT_TEXT = { match: "Matches the real quote", mismatch: "Differs from the real quote", partial: "Nothing to compare yet", no_actual: "Real outcome not recorded", not_assessed: "Not enough answers to assess" };

  let schema = null;          // /api/questionnaire
  let current = null;         // /api/cases/<id>
  let showAll = false;

  async function api(path, opts) {
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { data = { ok: false, error: "Bad response (" + res.status + ")" }; }
    if (!res.ok && data && data.ok !== true) throw new Error((data && data.error) || ("HTTP " + res.status));
    return data;
  }
  const json = (method, body) => ({ method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  // ---------------------------------------------------------------- list
  async function loadList() {
    try {
      const cases = await api("api/cases");
      const counts = {};
      cases.forEach((c) => { const v = c.verdict || "unprocessed"; counts[v] = (counts[v] || 0) + 1; });
      $("cb-summary").textContent = cases.length + " case(s)" + (cases.length ? " · " + Object.entries(counts).map(([k, n]) => n + " " + (VERDICT_TEXT[k] || k).toLowerCase()).join(" · ") : "");
      $("cb-list").innerHTML = cases.length ? cases.map((c) =>
        `<div class="cb-item${current && current.case.id === c.id ? " active" : ""}" data-id="${esc(c.id)}">
           <div class="t">${esc(c.client || c.id)}</div>
           <div class="s">${esc(c.insurer || "insurer ?")} · ${esc(c.form_type || "form ?")} · ${c.documents} doc(s)</div>
           <div class="s">${c.verdict ? `<span class="v-${esc(c.verdict)}">${esc(VERDICT_TEXT[c.verdict] || c.verdict)}</span>` : "Not processed"}${c.rater_status ? " · rater: " + esc(STATUS_TEXT[c.rater_status] || c.rater_status) : ""}</div>
         </div>`).join("") : `<div class="field-hint">No cases yet.</div>`;
      document.querySelectorAll(".cb-item").forEach((el) => el.addEventListener("click", () => openCase(el.dataset.id)));
    } catch (err) { $("cb-list").innerHTML = banner("danger", "&#9888;", esc(err.message)); }
  }

  async function loadLearnings(target) {
    try {
      const l = await api("api/casebook/learnings");
      const el = $(target || "cb-learnings");
      if (!el) return;
      el.innerHTML = l.total ? `${l.total} correction(s) recorded.<ul>${l.most_corrected.slice(0, 10).map((r) =>
        `<li>Row ${r.row}: ${esc(r.question || "")} <strong>(${r.corrections})</strong></li>`).join("")}</ul>` : "No corrections recorded yet.";
    } catch (err) { /* non-fatal */ }
  }

  // ---------------------------------------------------------------- new case
  function newCase() {
    current = null;
    $("cb-detail").innerHTML = `<div class="step-header"><h2>New case</h2><p>Name the client and where the form came from. You add documents and the real outcome next.</p></div>
      <div class="cb-form">
        <div><label>Client</label><input id="n-client"/></div>
        <div><label>Insurer whose form / terms these are</label><input id="n-insurer"/></div>
        <div><label>Form type</label><input id="n-form" placeholder="e.g. our fillable form, Bryte proposal, broker scan"/></div>
        <div><label>Broker</label><input id="n-broker"/></div>
      </div>
      <div class="btn-row"><span></span><button class="btn btn-primary" id="n-create">Create case</button></div>`;
    $("n-create").addEventListener("click", async () => {
      try {
        const c = await api("api/cases", json("POST", { client: $("n-client").value, insurer: $("n-insurer").value, form_type: $("n-form").value, broker: $("n-broker").value }));
        toast("Case created", "success");
        await loadList();
        openCase(c.id);
      } catch (err) { toast(err.message, "error"); }
    });
  }

  // ---------------------------------------------------------------- case detail
  async function openCase(id) {
    try { current = await api("api/cases/" + encodeURIComponent(id)); }
    catch (err) { toast(err.message, "error"); return; }
    document.querySelectorAll(".cb-item").forEach((el) => el.classList.toggle("active", el.dataset.id === id));
    render();
  }

  const opt = (list, val) => list.map(([v, t]) => `<option value="${esc(v)}"${String(val == null ? "" : val) === v ? " selected" : ""}>${esc(t)}</option>`).join("");

  function render() {
    const c = current.case, a = c.actual || {}, ri = c.rating_inputs || {}, ctx = c.context || {};
    const bands = [["", "— not recorded —"]].concat(D.MATURITY_BANDS.filter((m) => m.label !== "N/A").map((m) => [m.label, m.label]));
    const mdrs = D.MDR_OPTIONS.map((m) => [m.label, m.label]);
    const conds = (schema && schema.conditions) || [];
    const actualConds = new Set(a.conditions || []);
    $("cb-detail").innerHTML = `
      <div class="step-header"><h2>${esc(c.client || c.id)}</h2><p>Case <code>${esc(c.id)}</code> · created ${esc((c.created_at || "").slice(0, 10))} · ${esc(c.source || "")}</p></div>

      <div class="section-title">Case and real outcome</div>
      <div class="cb-form">
        <div><label>Client</label><input id="m-client" value="${esc(c.client)}"/></div>
        <div><label>Insurer</label><input id="m-insurer" value="${esc(c.insurer)}"/></div>
        <div><label>Form type</label><input id="m-form" value="${esc(c.form_type)}"/></div>
        <div><label>Quoted on</label><input id="m-date" type="date" value="${esc(c.quoted_on)}"/></div>
        <div><label>Decision actually made</label><select id="a-decision">${opt(DECISIONS, a.decision)}</select></div>
        <div><label>Maturity band actually applied</label><select id="a-band">${opt(bands, a.maturity_band)}</select></div>
        <div><label>Annual premium actually quoted (incl. VAT)</label><input id="a-premium" value="${a.premium != null ? esc(a.premium) : ""}"/></div>
        <div><label>Cover actually quoted</label><input id="a-cover" value="${a.cover != null ? esc(a.cover) : ""}"/></div>
        <div class="full"><label>Conditions actually imposed</label>${conds.length ? conds.map((x) =>
          `<label style="display:flex;gap:6px;align-items:flex-start;color:inherit;font-size:13px"><input type="checkbox" class="a-cond" value="${esc(x.id)}"${actualConds.has(x.id) ? " checked" : ""} style="width:auto"/>${esc(x.condition)}</label>`).join("") : "<span class='field-hint'>Loading conditions…</span>"}</div>
        <div class="full"><label>Notes on the real quote</label><textarea id="a-notes" rows="2">${esc(a.notes)}</textarea></div>
      </div>
      <div class="section-title">Pricing inputs (to reprice with the rater)</div>
      <div class="cb-form">
        <div class="full"><label>Sub-industry</label><input id="r-ind" list="ind-list" value="${esc(ri.subIndustry)}"/><datalist id="ind-list">${D.INDUSTRIES.map((i) => `<option value="${esc(i.sub)}"></option>`).join("")}</datalist></div>
        <div><label>Annual turnover</label><input id="r-turnover" value="${ri.turnover != null ? esc(ri.turnover) : ""}"/></div>
        <div><label>Cover</label><input id="r-cover" value="${ri.cover != null ? esc(ri.cover) : ""}"/></div>
        <div><label>Excess</label><input id="r-excess" value="${ri.excess != null ? esc(ri.excess) : ""}"/></div>
        <div><label>Funds Protect amount (blank = standard)</label><input id="r-fp" value="${ri.fpAdjustableAmount != null ? esc(ri.fpAdjustableAmount) : ""}"/></div>
        <div class="full"><label>MDR</label><select id="r-mdr">${opt(mdrs, ri.mdr || "No MDR")}</select></div>
        <div><label><input type="checkbox" id="c-soe" style="width:auto"${ctx.soe ? " checked" : ""}/> State-owned entity</label></div>
        <div><label><input type="checkbox" id="c-public" style="width:auto"${ctx.public_sector ? " checked" : ""}/> Public sector</label></div>
      </div>
      <div class="btn-row"><span></span><button class="btn" id="btn-save-meta">Save case details</button></div>

      <div class="section-title">Documents</div>
      <table class="benefits-table cb-docs"><thead><tr><th>File</th><th style="width:200px">Role</th><th style="width:80px">Size</th></tr></thead><tbody>
        ${current.documents.length ? current.documents.map((d) => `<tr><td><a href="api/cases/${encodeURIComponent(c.id)}/documents/${encodeURIComponent(d.name)}" target="_blank">${esc(d.name)}</a></td>
          <td><select class="doc-role" data-name="${esc(d.name)}">${opt(ROLES, d.role)}</select></td><td>${Math.round(d.bytes / 1024)} KB</td></tr>`).join("")
          : `<tr><td colspan="3" class="field-hint">No documents yet.</td></tr>`}
      </tbody></table>
      <div class="btn-row" style="gap:8px">
        <select id="up-role">${opt(ROLES, "proposal")}</select>
        <input type="file" id="up-file" multiple accept=".pdf,.docx,.xlsx,.xlsm,.txt,.md,.csv,.png,.jpg,.jpeg,.tif,.tiff,.bmp,.webp"/>
        <button class="btn" id="btn-upload">Upload</button>
        <button class="btn btn-primary" id="btn-process">Process case →</button>
      </div>

      <div id="cb-result"></div>
      <div id="cb-review"></div>`;

    $("btn-save-meta").addEventListener("click", saveMeta);
    $("btn-upload").addEventListener("click", upload);
    $("btn-process").addEventListener("click", processCase);
    document.querySelectorAll(".doc-role").forEach((s) => s.addEventListener("change", async () => {
      try { await api(`api/cases/${encodeURIComponent(c.id)}/documents/${encodeURIComponent(s.dataset.name)}`, json("PATCH", { role: s.value })); toast("Role saved", "success"); }
      catch (err) { toast(err.message, "error"); }
    }));
    renderResult();
    renderReview();
  }

  function metaPatch() {
    return {
      client: $("m-client").value, insurer: $("m-insurer").value, form_type: $("m-form").value, quoted_on: $("m-date").value,
      actual: {
        decision: $("a-decision").value || null, maturity_band: $("a-band").value || null,
        premium: $("a-premium").value, cover: $("a-cover").value, notes: $("a-notes").value,
        conditions: Array.from(document.querySelectorAll(".a-cond:checked")).map((x) => x.value),
      },
      rating_inputs: {
        subIndustry: $("r-ind").value, turnover: $("r-turnover").value, cover: $("r-cover").value,
        excess: $("r-excess").value, fpAdjustableAmount: $("r-fp").value, mdr: $("r-mdr").value,
      },
      context: { soe: $("c-soe").checked, public_sector: $("c-public").checked },
    };
  }

  async function saveMeta(silent) {
    try {
      await api("api/cases/" + encodeURIComponent(current.case.id), json("PATCH", metaPatch()));
      if (silent !== true) toast("Case saved", "success");
      return true;
    } catch (err) { toast(err.message, "error"); return false; }
  }

  async function upload() {
    const files = $("up-file").files;
    if (!files || !files.length) { toast("Choose a file first", "error"); return; }
    const fd = new FormData();
    Array.from(files).forEach((f) => fd.append("file", f));
    fd.append("role", $("up-role").value);
    try {
      await saveMeta(true);
      await api(`api/cases/${encodeURIComponent(current.case.id)}/documents`, { method: "POST", body: fd });
      toast("Uploaded", "success");
      await openCase(current.case.id); loadList();
    } catch (err) { toast(err.message, "error"); }
  }

  async function processCase() {
    $("cb-result").innerHTML = banner("info", "⏳", "Reading the documents and scoring the answers…");
    try {
      if (!(await saveMeta(true))) return;
      await api(`api/cases/${encodeURIComponent(current.case.id)}/process`, { method: "POST" });
      await openCase(current.case.id); loadList();
      toast("Processed", "success");
    } catch (err) { $("cb-result").innerHTML = banner("danger", "&#9888;", esc(err.message)); }
  }

  // ---------------------------------------------------------------- pricing
  function priceWith(maturity) {
    const ri = current.case.rating_inputs || {};
    if (!ri.subIndustry || !ri.turnover || !ri.cover) return null;
    const benefits = D.BENEFITS.map((b) => ({ name: b.name, included: b.name !== "PCI Fines and Penalties" && b.name !== "Computer Crime", sublimitRatio: 1 }));
    const r = E.computePremium({
      turnover: ri.turnover, cover: ri.cover, subIndustry: ri.subIndustry, vat: D.CONSTANTS.DEFAULT_VAT,
      maturityOverride: maturity.label || "N/A", posture: maturity.posture != null ? maturity.posture : null,
      benefits, excess: ri.excess != null ? ri.excess : 1000000,
      fpAdjustableAmount: ri.fpAdjustableAmount || 0, mdr: ri.mdr || "No MDR", discretionary: 0,
    });
    return r && r.ok ? r : null;
  }
  const bandLabel = (band) => { const m = D.MATURITY_BANDS.find((x) => String(x.label).toLowerCase() === String(band || "").toLowerCase()); return m ? m.label : null; };

  function premiumRows(a, actual) {
    const rows = [];
    const label = bandLabel(a && a.maturity && a.maturity.band);
    const rater = a && a.ok ? priceWith(label ? { label } : { posture: a.posture }) : null;
    const atActual = actual.maturity_band ? priceWith({ label: bandLabel(actual.maturity_band) || actual.maturity_band }) : null;
    const diff = (p) => (p && actual.premium) ? ` <span class="${Math.abs(p / actual.premium - 1) <= 0.05 ? "v-match" : "v-mismatch"}">(${p >= actual.premium ? "+" : ""}${Math.round((p / actual.premium - 1) * 100)}% vs real)</span>` : "";
    if (rater) rows.push(`<tr><td>Rater premium at its own maturity band</td><td>${zar0(rater.finalPremium)}${diff(rater.finalPremium)}</td></tr>`);
    if (atActual) rows.push(`<tr><td>Rater premium at the band actually applied</td><td>${zar0(atActual.finalPremium)}${diff(atActual.finalPremium)}</td></tr>`);
    if (actual.premium) rows.push(`<tr><td>Premium actually quoted</td><td>${zar0(actual.premium)}</td></tr>`);
    if (!rater && !atActual) rows.push(`<tr><td colspan="2" class="field-hint">Add sub-industry, turnover and cover under pricing inputs to reprice this case.</td></tr>`);
    return rows.join("");
  }

  // ---------------------------------------------------------------- result
  function renderResult() {
    const res = current.result;
    if (!res) { $("cb-result").innerHTML = banner("info", "&#9432;", "Not processed yet. Upload the documents, record the real outcome, then process."); return; }
    const a = res.assessment || null, cmp = res.comparison || {}, actual = current.case.actual || {};
    const readings = (res.readings || []).map((r) => {
      const how = r.kind === "fillable_form" ? `Fillable form · ${r.answers} answer(s) · version match ${pct(r.version_match)}${(r.conflicts || []).length ? " · " + r.conflicts.length + " conflicting tick(s)" : ""}`
        : r.kind === "text" ? `Text extracted · ${(r.chars || 0).toLocaleString()} chars${r.needs_ocr ? " · needs OCR" : ""}${r.needs_mapping ? " · <strong>answers must be entered below</strong>" : ""}`
        : "Could not read: " + esc(r.error || "");
      return `<tr><td>${esc(r.doc)}</td><td>${esc(r.role)}</td><td>${how}</td></tr>`;
    }).join("");
    const checks = (cmp.checks || []).map((k) => {
      const show = (v) => Array.isArray(v) ? (v.length ? v.map(esc).join(", ") : "none") : esc(STATUS_TEXT[v] || v);
      let extra = "";
      if (k.check === "conditions" && !k.match) extra = `<div class="field-hint">Only rater: ${show(k.only_rater)} · only real quote: ${show(k.only_actual)}</div>`;
      if (k.check === "decision" && !k.match) extra = `<div class="field-hint">Rater outcome is consistent with: ${show(k.consistent_with)}</div>`;
      return `<tr><td>${esc(k.check.replace("_", " "))}</td><td>${show(k.rater)}</td><td>${show(k.actual)}${extra}</td><td class="${k.match ? "v-match" : "v-mismatch"}">${k.match ? "✓" : "✕"}</td></tr>`;
    }).join("");
    const src = res.answer_sources || {};
    $("cb-result").innerHTML = `
      <div class="section-title" style="margin-top:22px">What the rater read · processed ${esc((res.processed_at || "").replace("T", " ").slice(0, 16))}</div>
      <table class="benefits-table cb-docs"><thead><tr><th>Document</th><th style="width:90px">Role</th><th>Result</th></tr></thead><tbody>${readings || "<tr><td colspan='3'>—</td></tr>"}</tbody></table>
      <div class="extract-meta" style="margin-top:8px">${Object.entries(src).map(([k, n]) => `<span class="meta-chip">${n} answer(s) from ${esc(k)}</span>`).join("")}</div>
      ${a && a.ok ? `
        <div class="section-title">Rater outcome</div>
        <div class="score-hero">
          <div class="kv"><div class="kv-label">Status</div><div class="kv-value">${esc(STATUS_TEXT[a.status] || a.status)}</div></div>
          <div class="kv"><div class="kv-label">Maturity band</div><div class="kv-value">${esc(a.maturity && a.maturity.band)}</div><div class="kv-sub">×${esc(a.maturity && a.maturity.multiplier)} · posture ${esc(a.posture)}</div></div>
          <div class="kv"><div class="kv-label">Completeness</div><div class="kv-value">${pct(a.completeness && a.completeness.pct)}</div><div class="kv-sub">${a.completeness ? a.completeness.answered + "/" + a.completeness.applicable : ""} applicable questions</div></div>
        </div>` : banner("warn", "&#9888;", a && a.error ? esc(a.error) : "No answers yet, so the rater could not score this case. Enter the answers below.")}
      <div class="section-title">Rater against the real quote · <span class="v-${esc(cmp.verdict)}">${esc(VERDICT_TEXT[cmp.verdict] || cmp.verdict || "")}</span></div>
      ${checks ? `<table class="benefits-table cb-checks"><thead><tr><th style="width:120px">Check</th><th>Rater</th><th>Real quote</th><th style="width:40px"></th></tr></thead><tbody>${checks}</tbody></table>` : ""}
      <table class="benefits-table cb-checks" style="margin-top:8px"><tbody>${premiumRows(a, actual)}</tbody></table>`;
  }

  // ---------------------------------------------------------------- review / corrections
  function renderReview() {
    const res = current.result;
    if (!res || !schema) { $("cb-review").innerHTML = ""; return; }
    const a = res.assessment || {}, review = current.review || {};
    const answers = Object.assign({}, a.answers || {});
    const sources = res.sources || {};
    const unanswered = new Set((a.unanswered || []).map((u) => String(u.row)));
    const qs = schema.questions.filter((q) => q.scored && (showAll || unanswered.has(String(q.row)) || String(q.row) in answers || !a.ok));
    const confirmed = new Set(review.confirmed || []);
    const confirmable = (schema.conditions || []).filter((c) => c.confirm);
    const row = (q) => {
      const r = String(q.row), val = answers[r];
      const v = Array.isArray(val) ? val.join("; ") : (val == null ? "" : String(val));
      const choices = q.choices || [];
      const input = choices.length && !Array.isArray(val)
        ? `<select class="rv" data-row="${r}"><option value=""></option>${choices.map((ch) => `<option${String(ch) === v ? " selected" : ""}>${esc(ch)}</option>`).join("")}</select>`
        : `<input class="rv" data-row="${r}" value="${esc(v)}"/>`;
      return `<div class="cb-q" data-orig="${esc(v)}"><div>R${r}</div><div>${esc(q.text)}${q.section ? `<div class="src">${esc(q.section)}</div>` : ""}</div><div>${input}</div><div class="src">${esc(sources[r] || (unanswered.has(r) ? "missing" : ""))}</div></div>`;
    };
    $("cb-review").innerHTML = `
      <div class="section-title" style="margin-top:22px">Answers · correct anything read wrongly
        <label style="float:right;text-transform:none;letter-spacing:0;font-weight:400"><input type="checkbox" id="rv-all" style="width:auto"${showAll ? " checked" : ""}/> show every question</label></div>
      <div class="field-hint">Shown: ${showAll ? "all scored questions" : "answered and missing applicable questions"}. Each change is kept as a labelled example for mapping ${esc(current.case.insurer || "this insurer")}'s form.</div>
      <div id="rv-rows">${qs.map(row).join("")}</div>
      ${confirmable.length ? `<div class="section-title">Confirmed by broker or underwriter</div>${confirmable.map((c) =>
        `<label style="display:flex;gap:6px;font-size:13px"><input type="checkbox" class="rv-conf" value="${esc(c.id)}" style="width:auto"${confirmed.has(c.id) ? " checked" : ""}/>${esc(c.condition)}</label>`).join("")}` : ""}
      <div class="cb-form" style="margin-top:10px"><div class="full"><label>Review notes</label><textarea id="rv-notes" rows="2">${esc(review.notes)}</textarea></div></div>
      <div class="btn-row"><span id="rv-count" class="field-hint"></span><button class="btn btn-primary" id="btn-review">Save corrections and re-process</button></div>`;
    $("rv-all").addEventListener("change", (e) => { showAll = e.target.checked; renderReview(); });
    document.querySelectorAll(".rv").forEach((el) => el.addEventListener("change", () => {
      const box = el.closest(".cb-q");
      box.classList.toggle("changed", el.value !== box.dataset.orig);
      $("rv-count").textContent = document.querySelectorAll(".cb-q.changed").length + " change(s)";
    }));
    $("btn-review").addEventListener("click", saveReview);
  }

  async function saveReview() {
    const review = current.review || {};
    const out = Object.assign({}, review.answers || {});
    document.querySelectorAll(".cb-q.changed .rv").forEach((el) => { out[el.dataset.row] = el.value; });
    const body = {
      answers: out,
      confirmed: Array.from(document.querySelectorAll(".rv-conf:checked")).map((x) => x.value),
      context: { soe: $("c-soe").checked, public_sector: $("c-public").checked },
      notes: $("rv-notes").value,
    };
    try {
      await saveMeta(true);
      const r = await api(`api/cases/${encodeURIComponent(current.case.id)}/review`, json("PUT", body));
      toast(`Saved · ${r.learnings_added} correction(s) recorded`, "success");
      await openCase(current.case.id); loadList();
    } catch (err) { toast(err.message, "error"); }
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg; t.className = "toast show " + (kind || "");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.className = "toast"), 3000);
  }

  // ---------------------------------------------------------------- boot
  $("btn-new").addEventListener("click", newCase);
  $("btn-refresh").addEventListener("click", loadList);
  api("api/questionnaire").then((s) => { schema = s; if (current) render(); }).catch(() => {});
  loadList();
  loadLearnings();
})();
