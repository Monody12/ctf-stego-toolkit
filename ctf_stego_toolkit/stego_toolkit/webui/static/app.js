/* CTF Stego WebUI — 原生 JS, 零依赖 */
"use strict";

/* ---------------- 通用 ---------------- */
async function api(url, options) {
  const resp = await fetch(url, options);
  let payload = {};
  try { payload = await resp.json(); } catch (e) { /* 非 JSON */ }
  if (!resp.ok) {
    const msg = payload.error || payload.errors || ("HTTP " + resp.status);
    throw new Error(typeof msg === "string" ? msg : msg.join("; "));
  }
  return payload;
}

let toastTimer = null;
function toast(message, cls) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = "toast show " + (cls || "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = "toast"; }, 3500);
}

function copyText(text) {
  const done = () => toast("已复制: " + (text.length > 60 ? text.slice(0, 60) + "…" : text), "ok");
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  } else { fallbackCopy(text, done); }
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } finally { ta.remove(); }
}

document.addEventListener("DOMContentLoaded", () => {
  // 复制
  document.addEventListener("click", (ev) => {
    const el = ev.target.closest("[data-copy]");
    if (el) { ev.preventDefault(); copyText(el.dataset.copy); }
  });
  // 灯箱
  const lightbox = document.getElementById("lightbox");
  document.addEventListener("click", (ev) => {
    const img = ev.target.closest("[data-lightbox]");
    if (img) {
      lightbox.querySelector("img").src = img.currentSrc || img.src;
      lightbox.classList.add("open");
    } else if (ev.target.closest(".lightbox")) {
      lightbox.classList.remove("open");
    }
  });
});

/* ---------------- 看板 ---------------- */
function initIndex() {
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const report = document.getElementById("import-report");
  if (!dropzone) return;

  dropzone.addEventListener("click", () => fileInput.click());
  dropzone.addEventListener("dragover", (ev) => { ev.preventDefault(); dropzone.classList.add("drag"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
  dropzone.addEventListener("drop", (ev) => {
    ev.preventDefault(); dropzone.classList.remove("drag");
    handleUpload(ev.dataTransfer.files);
  });
  fileInput.addEventListener("change", () => handleUpload(fileInput.files));

  document.getElementById("btn-import-dir").addEventListener("click", async () => {
    const path = document.getElementById("dir-path").value.trim();
    if (!path) { toast("请填入目录路径", "err"); return; }
    try {
      const result = await api("/api/import_dir", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      showReport(result);
      if (result.created && result.created.length) setTimeout(() => location.reload(), 800);
    } catch (err) { toast("导入失败: " + err.message, "err"); }
  });

  function handleUpload(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    toast("正在上传 " + files.length + " 个文件…");
    fetch("/api/upload", { method: "POST", body: form })
      .then(async (resp) => {
        const result = await resp.json().catch(() => ({}));
        showReport(result);
        if (result.created && result.created.length) setTimeout(() => location.reload(), 800);
      })
      .catch((err) => toast("上传失败: " + err.message, "err"));
  }

  function showReport(result) {
    const lines = [];
    (result.created || []).forEach((c) =>
      lines.push(`<div class="ok">✓ 建题 #${c.id} ${c.title}（${c.files} 文件，已加入分析队列）</div>`));
    (result.skipped || []).forEach((s) => lines.push(`<div class="skip">→ ${s}</div>`));
    (result.errors || []).forEach((e) => lines.push(`<div class="err">✗ ${e}</div>`));
    if (!lines.length) lines.push('<div class="skip">没有变化</div>');
    report.innerHTML = lines.join("");
    report.classList.remove("hidden");
  }

  // 行内操作
  document.getElementById("qtable").addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button");
    if (!btn) return;
    const row = btn.closest("tr");
    const id = row && row.dataset.id;
    if (!id) return;
    if (btn.classList.contains("act-reanalyze")) {
      try {
        await api(`/api/questions/${id}/analyze`, { method: "POST" });
        toast(`#${id} 已重新加入分析队列`, "ok");
        pollOnce();
      } catch (err) { toast(err.message, "err"); }
    } else if (btn.classList.contains("act-delete")) {
      if (!confirm(`确定删除题目 #${id}？其文件与分析结果将一并删除。`)) return;
      try {
        await api(`/api/questions/${id}`, { method: "DELETE" });
        row.remove();
        toast(`#${id} 已删除`, "ok");
      } catch (err) { toast(err.message, "err"); }
    }
  });

  // 过滤
  document.getElementById("filters").addEventListener("click", (ev) => {
    const chip = ev.target.closest(".chip");
    if (!chip) return;
    document.querySelectorAll("#filters .chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    applyFilter(chip.dataset.filter);
  });

  function rowMatches(filter, row) {
    if (filter === "all") return true;
    if (filter === "solved") return row.dataset.solved === "1";
    if (filter === "unsolved") {
      if (row.dataset.solved === "1") return false;
      if (row.dataset.match === "false") return true;
      return row.dataset.match === "none" && row.dataset.status === "done"
        && !row.querySelector(".cell-flag .flag-text");
    }
    return row.dataset.status === filter;
  }

  function applyFilter(filter) {
    document.querySelectorAll("#qtable tbody tr[data-id]").forEach((row) => {
      row.style.display = rowMatches(filter, row) ? "" : "none";
    });
  }

  // 轮询: 更新状态单元格, 结构性变化靠 /api/status 的字段全部覆盖, 无需刷新页面
  function patchRow(id, data) {
    const row = document.querySelector(`tr[data-id="${id}"]`);
    if (!row) return;
    const prev = row.dataset.status;
    row.dataset.status = data.status;
    row.dataset.match = data.expected_match === null ? "none"
      : (data.expected_match ? "true" : "false");
    const badge = row.querySelector(".badge");
    badge.className = "badge b-" + data.status;
    badge.textContent = { pending: "待分析", running: "分析中", done: "完成", error: "出错" }[data.status];
    row.querySelector(".cell-score").textContent = data.suspicion_score;
    row.querySelector(".cell-flag").innerHTML = data.top_flag
      ? `<span class="conf c-${data.top_conf}">${({ high: "高", medium: "中", low: "低" })[data.top_conf]}</span>`
        + `<code class="flag-text" data-copy="${data.top_flag}">${data.top_flag}</code>`
        + (data.flag_count > 1 ? `<span class="tag">+${data.flag_count - 1}</span>` : "")
      : '<span class="dim">—</span>';
    const match = row.querySelector(".cell-match");
    match.innerHTML = data.expected_match === null ? '<span class="dim">无答案</span>'
      : data.expected_match ? '<span class="match hit">✓ 命中</span>'
      : '<span class="match miss">✗ 未中</span>';
    row.querySelector(".cell-elapsed").textContent = data.elapsed ? data.elapsed.toFixed(1) + "s" : "—";
    if (prev !== data.status && (data.status === "done" || data.status === "error")) {
      const filter = document.querySelector("#filters .chip.active");
      if (filter && !rowMatches(filter.dataset.filter, row)) row.style.display = "none";
    }
  }

  async function pollOnce() {
    try {
      const data = await api("/api/status");
      const counts = data.counts;
      document.getElementById("st-total").textContent = counts.total;
      document.getElementById("st-pending").textContent = counts.pending;
      document.getElementById("st-running").textContent = counts.running;
      document.getElementById("st-done").textContent = counts.done;
      document.getElementById("st-error").textContent = counts.error;
      document.getElementById("st-hit").textContent = counts.hit;
      document.getElementById("st-solved").textContent = counts.solved;
      document.getElementById("nav-stats").textContent =
        `待析 ${counts.pending} · 运行 ${counts.running} · 命中 ${counts.hit}/${counts.total}`;
      Object.entries(data.questions).forEach(([id, q]) => patchRow(id, q));
    } catch (e) { /* 服务重启中, 忽略本轮 */ }
  }

  pollOnce();
  setInterval(pollOnce, 2000);
}

/* ---------------- 详情页 ---------------- */
function initDetail() {
  const confirmed = document.getElementById("in-confirmed");
  if (!confirmed) return;
  const qid = window.location.pathname.split("/").pop();
  const notes = document.getElementById("in-notes");
  const expected = document.getElementById("in-expected");
  const solved = document.getElementById("in-solved");

  async function save(fields) {
    try {
      await api(`/api/questions/${qid}/annotate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(fields),
      });
      toast("已保存", "ok");
    } catch (err) { toast("保存失败: " + err.message, "err"); }
  }
  [confirmed, expected, notes].forEach((el) => {
    el.addEventListener("change", () => save({ [el.id === "in-confirmed" ? "confirmed_flag" : el.id === "in-expected" ? "expected_flag" : "notes"]: el.value }));
    el.addEventListener("blur", () => save({ [el.id === "in-confirmed" ? "confirmed_flag" : el.id === "in-expected" ? "expected_flag" : "notes"]: el.value }));
  });
  solved.addEventListener("change", () => save({ solved: solved.checked }));

  // 文本产物: 展开时再加载内容(截断到 200KB)
  document.querySelectorAll(".text-artifact").forEach((details) => {
    details.addEventListener("toggle", async () => {
      const pre = details.querySelector("pre");
      if (!details.open || pre.dataset.loaded) return;
      try {
        const resp = await fetch(pre.dataset.mediaSrc);
        let text = await resp.text();
        if (text.length > 200 * 1024) text = text.slice(0, 200 * 1024) + "\n…（内容过长已截断）";
        pre.textContent = text || "（空）";
      } catch (e) { pre.textContent = "加载失败: " + e.message; }
      pre.dataset.loaded = "1";
    });
  });
}

/* ---------------- 前缀页 ---------------- */
function initPrefixes() {
  const newPrefix = document.getElementById("new-prefix");
  if (!newPrefix) return;

  document.getElementById("btn-add-prefix").addEventListener("click", async () => {
    const name = newPrefix.value.trim();
    if (!name) { toast("请填入前缀名", "err"); return; }
    try {
      await api("/api/prefixes", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "add", name }),
      });
      location.reload();
    } catch (err) { toast(err.message, "err"); }
  });

  document.querySelectorAll(".act-remove").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api("/api/prefixes", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "remove", name: btn.dataset.name }),
        });
        location.reload();
      } catch (err) { toast(err.message, "err"); }
    });
  });

  document.getElementById("btn-reset-prefixes").addEventListener("click", async () => {
    if (!confirm("清空全部自定义前缀，恢复为内置列表？")) return;
    try {
      await api("/api/prefixes", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "reset" }),
      });
      location.reload();
    } catch (err) { toast(err.message, "err"); }
  });

  document.getElementById("chk-replace").addEventListener("change", async (ev) => {
    try {
      await api("/api/prefixes", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "set_replace", replace_default: ev.target.checked }),
      });
      location.reload();
    } catch (err) { toast(err.message, "err"); }
  });
}

/* ---------------- expected 页 ---------------- */
function initExpected() {
  const fileInput = document.getElementById("expected-file");
  if (!fileInput) return;

  document.getElementById("btn-upload-expected").addEventListener("click", () => {
    const file = fileInput.files[0];
    if (!file) { toast("请选择 expected 文件", "err"); return; }
    const form = new FormData();
    form.append("file", file);
    fetch("/api/expected/upload", { method: "POST", body: form })
      .then(async (resp) => {
        const result = await resp.json();
        toast(`解析 ${result.entries} 条答案，自动关联 ${result.linked} 道题`, "ok");
        setTimeout(() => location.reload(), 800);
      })
      .catch((err) => toast("上传失败: " + err.message, "err"));
  });

  document.getElementById("btn-apply-expected").addEventListener("click", async () => {
    try {
      const result = await api("/api/expected/apply", { method: "POST" });
      toast(`已关联 ${result.linked} 道题`, "ok");
      setTimeout(() => location.reload(), 800);
    } catch (err) { toast(err.message, "err"); }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initIndex();
  initDetail();
  initPrefixes();
  initExpected();
});
