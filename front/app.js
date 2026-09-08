const unlock = document.querySelector("#unlock");
const workspace = document.querySelector("#workspace");
const notice = document.querySelector("#notice");
const liveLog = document.querySelector("#live-log");
let adminPassword = sessionStorage.getItem("sbeans-password") || "";
let records = [];
let codeLibrary = [];
let codeLibraryPage = 1;
let expandedCodeLibraryId = "";
let hasDefaultAccountPassword = false;
const selectedCodeLibraryIds = new Set();
const codeLibraryMedia = window.matchMedia("(max-width: 760px)");
let codeLibraryPageSize = codeLibraryMedia.matches ? 20 : 40;
let activeController = null;
const proxyField = document.querySelector("#proxies");
const PROXY_STORAGE_KEY = "sbeans-proxies";

function saveProxyPool() {
  try { localStorage.setItem(PROXY_STORAGE_KEY, proxyField.value); } catch { /* ignore */ }
}

try {
  const savedProxies = localStorage.getItem(PROXY_STORAGE_KEY);
  if (savedProxies !== null) proxyField.value = savedProxies;
} catch { /* Local storage can be unavailable in restrictive browser modes. */ }

proxyField.addEventListener("input", saveProxyPool);
proxyField.addEventListener("change", saveProxyPool);
window.addEventListener("pagehide", saveProxyPool);

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", "X-Admin-Password": adminPassword, ...(options.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `请求失败 (${response.status})`);
  return body;
}

function setNotice(element, message, success = false) {
  element.textContent = message;
  element.classList.toggle("notice-success", success);
}

function showView(viewId) {
  document.querySelectorAll(".view").forEach((view) => { view.hidden = view.id !== viewId; });
  document.querySelectorAll(".tab").forEach((tab) => { tab.classList.toggle("active", tab.dataset.view === viewId); });
}

function formatSingaporeDate(value) {
  const raw = String(value || "").trim();
  if (!raw) return "未知";
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return `${raw} 00:00`;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw.replace("T", " ").slice(0, 16);
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Singapore",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date).map(({ type, value: part }) => [type, part]));
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}`;
}

function automaticRecordTimeValue(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/.exec(String(value || "").trim());
  if (!match) return null;
  const [, year, month, day, hour, minute] = match.map(Number);
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) return null;
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, 0, 0);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day
      || date.getUTCHours() !== hour || date.getUTCMinutes() !== minute) return null;
  return date.getTime();
}

function sortRecordsForDisplay(items) {
  return (Array.isArray(items) ? items : [])
    .map((record, index) => ({ record, index, time: automaticRecordTimeValue(record?.time) }))
    .sort((left, right) => {
      if (left.time === null && right.time === null) return left.index - right.index;
      if (left.time === null) return -1;
      if (right.time === null) return 1;
      return left.time - right.time || left.index - right.index;
    })
    .map(({ record }) => record);
}

function firstCodeDate(codes) {
  return (Array.isArray(codes) ? codes : []).find((item) => item && item.endDate)?.endDate || "";
}

function createDateRow(value, noticeTarget = notice) {
  const row = document.createElement("div"); row.className = "date-row";
  const label = document.createElement("span"); label.className = "date-label"; label.textContent = "下次时间";
  row.append(label);
  if (value) row.append(createCopyButton(formatSingaporeDate(value), "复制下次时间", noticeTarget));
  else {
    const unknown = document.createElement("span"); unknown.className = "date-value"; unknown.textContent = "未知";
    row.append(unknown);
  }
  return row;
}

function createCodeGrid(codes, extraClass = "", noticeTarget = notice) {
  const codeList = document.createElement("div"); codeList.className = `code-list code-grid ${extraClass}`.trim();
  (Array.isArray(codes) ? codes : []).forEach((item, index) => {
    const codeAvailable = Boolean(item && item.code) && item.ok !== false;
    const entry = document.createElement("div"); entry.className = `code-entry${codeAvailable ? "" : " code-entry-error"}`;
    const plan = document.createElement("span"); plan.className = "code-plan"; plan.textContent = String(index + 1);
    entry.append(plan);
    if (codeAvailable) entry.append(createCopyButton(item.code, `复制第 ${index + 1} 组优惠码`, noticeTarget));
    else {
      const error = document.createElement("span"); error.className = "code-error"; error.textContent = item.error || "采集失败"; entry.append(error);
    }
    codeList.append(entry);
  });
  return codeList;
}

function renderRecords() {
  const picker = document.querySelector("#record-picker");
  const list = document.querySelector("#records-list");
  if (!records.length) {
    picker.innerHTML = '<p class="empty">暂无账号记录</p>';
    list.innerHTML = '<p class="empty">暂无账号记录</p>';
    return;
  }
  picker.replaceChildren(...records.map((record) => {
    const label = document.createElement("label"); label.className = "picker-row";
    const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.value = record.id; checkbox.name = "saved-record";
    const email = document.createElement("span"); email.textContent = record.email;
    const time = document.createElement("time"); time.textContent = record.time;
    label.append(checkbox, email, time); return label;
  }));
  list.replaceChildren(...records.map((record) => {
    const row = document.createElement("div"); row.className = "record-row";
    const email = document.createElement("strong"); email.textContent = record.email;
    const time = document.createElement("span"); time.className = "record-time"; time.textContent = record.time;
    const remove = document.createElement("button"); remove.type = "button"; remove.className = "danger small-button"; remove.textContent = "删除"; remove.dataset.recordId = record.id;
    row.append(email, time, remove); return row;
  }));
}

async function loadRecords() {
  records = sortRecordsForDisplay((await request("/api/records")).records);
  renderRecords();
}

function renderCodeLibrary() {
  const list = document.querySelector("#code-library-list");
  const toolbar = document.querySelector("#code-library-toolbar");
  if (!codeLibrary.length) {
    toolbar.hidden = true;
    list.innerHTML = '<p class="empty">暂无已归档的四组优惠码</p>';
    return;
  }
  toolbar.hidden = false;
  const pageCount = Math.max(1, Math.ceil(codeLibrary.length / codeLibraryPageSize));
  codeLibraryPage = Math.min(Math.max(codeLibraryPage, 1), pageCount);
  const start = (codeLibraryPage - 1) * codeLibraryPageSize;
  const pageEntries = codeLibrary.slice(start, start + codeLibraryPageSize);
  const rows = [];

  for (let index = 0; index < pageEntries.length; index += codeLibraryMedia.matches ? 1 : 2) {
    const group = pageEntries.slice(index, index + (codeLibraryMedia.matches ? 1 : 2));
    const row = document.createElement("div"); row.className = "library-row";
    group.forEach((entry, side) => {
      const card = document.createElement("div"); card.className = "library-summary-card";
      card.classList.toggle("expanded", entry.id === expandedCodeLibraryId);

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.className = "library-entry-checkbox";
      checkbox.checked = selectedCodeLibraryIds.has(entry.id);
      checkbox.setAttribute("aria-label", `选择 ${entry.email || "未知账号"} 的优惠码记录`);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) selectedCodeLibraryIds.add(entry.id);
        else selectedCodeLibraryIds.delete(entry.id);
        updateCodeLibraryControls(pageEntries, pageCount);
      });

      const toggle = document.createElement("button"); toggle.type = "button"; toggle.className = "library-summary-toggle";
      toggle.setAttribute("aria-expanded", String(entry.id === expandedCodeLibraryId));
      const summaryText = document.createElement("span"); summaryText.className = "library-summary-text";
      const email = document.createElement("strong"); email.textContent = entry.email || "未知账号";
      const captured = document.createElement("span"); captured.className = "library-captured";
      captured.textContent = `采集时间：${formatSingaporeDate(entry.captured_at)}`;
      const icon = document.createElement("span"); icon.className = "library-toggle-icon";
      icon.textContent = entry.id === expandedCodeLibraryId ? "−" : "+";
      icon.setAttribute("aria-hidden", "true");
      summaryText.append(email, captured); toggle.append(summaryText, icon);
      toggle.addEventListener("click", () => {
        expandedCodeLibraryId = expandedCodeLibraryId === entry.id ? "" : entry.id;
        renderCodeLibrary();
      });
      card.append(checkbox, toggle); row.append(card);

      if (entry.id === expandedCodeLibraryId) row.dataset.expandedSide = side === 0 ? "left" : "right";
    });

    const expandedEntry = group.find((entry) => entry.id === expandedCodeLibraryId);
    if (expandedEntry) {
      const detail = document.createElement("div");
      detail.className = `library-detail origin-${row.dataset.expandedSide}`;
      const meta = document.createElement("p"); meta.className = "library-meta";
      meta.textContent = "四组优惠码可分别复制";
      const libraryNotice = document.querySelector("#code-library-notice");
      detail.append(
        createDateRow(expandedEntry.next_date, libraryNotice),
        meta,
        createCodeGrid(expandedEntry.codes, "library-code-list", libraryNotice),
      );
      row.append(detail);
    }
    rows.push(row);
  }

  list.replaceChildren(...rows);
  updateCodeLibraryControls(pageEntries, pageCount);
}

function updateCodeLibraryControls(pageEntries, pageCount) {
  const selectAll = document.querySelector("#code-library-select-all");
  const selectedOnPage = pageEntries.filter((entry) => selectedCodeLibraryIds.has(entry.id)).length;
  selectAll.checked = pageEntries.length > 0 && selectedOnPage === pageEntries.length;
  selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < pageEntries.length;
  document.querySelector("#code-library-selection-count").textContent = `已选 ${selectedCodeLibraryIds.size} 条`;
  document.querySelector("#delete-code-library").disabled = selectedCodeLibraryIds.size === 0;
  document.querySelector("#code-library-page-status").textContent = `第 ${codeLibraryPage} / ${pageCount} 页 · 本页 ${pageEntries.length} 条`;
  document.querySelector("#code-library-previous").disabled = codeLibraryPage <= 1;
  document.querySelector("#code-library-next").disabled = codeLibraryPage >= pageCount;
}

async function loadCodeLibrary() {
  codeLibrary = (await request("/api/code-library")).entries || [];
  const availableIds = new Set(codeLibrary.map((entry) => entry.id));
  [...selectedCodeLibraryIds].forEach((entryId) => {
    if (!availableIds.has(entryId)) selectedCodeLibraryIds.delete(entryId);
  });
  if (!availableIds.has(expandedCodeLibraryId)) expandedCodeLibraryId = "";
  renderCodeLibrary();
}

function renderDefaultAccountPasswordState() {
  const state = document.querySelector("#default-account-password-state");
  state.textContent = hasDefaultAccountPassword ? "已设置，输入新密码可直接替换" : "尚未设置，账号记录仍需单独填写密码";
  state.classList.toggle("configured", hasDefaultAccountPassword);
  document.querySelector("#record-password").placeholder = hasDefaultAccountPassword
    ? "留空使用面板默认密码"
    : "未设置默认密码，当前必须填写";
}

async function loadSettings() {
  const settings = await request("/api/settings");
  hasDefaultAccountPassword = Boolean(settings.has_default_account_password);
  renderDefaultAccountPasswordState();
}

async function openWorkspace() {
  await request("/api/session", { method: "POST" });
  await Promise.all([loadRecords(), loadCodeLibrary(), loadSettings()]);
  unlock.hidden = true;
  workspace.hidden = false;
  document.querySelector("#health").textContent = "后端正常";
}

function appendLog(item) {
  if (liveLog.querySelector(".empty")) liveLog.replaceChildren();
  const row = document.createElement("p");
  const time = document.createElement("time");
  time.textContent = formatSingaporeDate(item.time || new Date().toISOString());
  const message = document.createElement("span"); message.textContent = item.message;
  row.append(time, message); liveLog.append(row); liveLog.scrollTop = liveLog.scrollHeight;
}

function renderResults(results) {
  const list = document.querySelector("#result-list");
  list.replaceChildren(...results.map((result) => {
    const account = document.createElement("article"); account.className = "account-result";
    const head = document.createElement("div"); head.className = "account-result-head";
    const email = document.createElement("strong"); email.textContent = result.email;
    const state = document.createElement("span");
    state.className = result.success ? "success" : (result.login_success ? "partial" : "failed");
    state.textContent = result.success ? "成功" : (result.login_success ? "部分完成" : "失败");
    head.append(email, state);
    const message = document.createElement("p"); message.className = "account-result-message";
    message.textContent = result.message + (result.screenshot ? `（截图: ${result.screenshot}）` : "");
    account.append(head, message);

    const codes = Array.isArray(result.codes) ? result.codes : [];
    if (codes.length) {
      account.append(createDateRow(firstCodeDate(codes)), createCodeGrid(codes));
    }
    return account;
  }));
  document.querySelector("#results").hidden = false;
}

function createCopyButton(value, label, noticeTarget = notice) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-value";
  button.title = label;
  button.setAttribute("aria-label", label);
  const text = document.createElement("span"); text.className = "copy-text"; text.textContent = value || "";
  const icon = document.createElement("span"); icon.className = "copy-icon"; icon.textContent = "⧉"; icon.setAttribute("aria-hidden", "true");
  button.append(text, icon);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value || "");
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = value || ""; textarea.style.cssText = "position:fixed;opacity:0";
      document.body.appendChild(textarea); textarea.select(); document.execCommand("copy"); textarea.remove();
    }
    setNotice(noticeTarget, `${label}已复制`, true);
  });
  return button;
}

async function readEventStream(response) {
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `请求失败 (${response.status})`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const events = buffer.split("\n\n");
    buffer = events.pop() || "";
    for (const rawEvent of events) {
      const data = rawEvent.split("\n").filter((line) => line.startsWith("data: ")).map((line) => line.slice(6)).join("\n");
      if (!data) continue;
      const item = JSON.parse(data);
      if (item.type === "log") appendLog(item);
      if (item.type === "result") {
        renderResults(item.results);
        loadRecords().catch(() => {});
        loadCodeLibrary().catch(() => {});
      }
      if (item.type === "error") throw new Error(item.message);
    }
    if (done) break;
  }
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => showView(tab.dataset.view)));

document.querySelector("#unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  adminPassword = document.querySelector("#admin-password").value;
  try { await openWorkspace(); sessionStorage.setItem("sbeans-password", adminPassword); }
  catch (error) { document.querySelector("#unlock p").textContent = error.message; }
});

document.querySelector("#logout").addEventListener("click", () => {
  sessionStorage.removeItem("sbeans-password"); adminPassword = ""; location.reload();
});

document.querySelector("#clear-log").addEventListener("click", () => { liveLog.innerHTML = '<p class="empty">等待任务开始</p>'; });

document.querySelector("#stop").addEventListener("click", async () => {
  if (!activeController) return;
  appendLog({ message: "任务已手动停止，正在关闭浏览器任务" });
  try {
    const result = await request("/api/login-stop", { method: "POST" });
    appendLog({ message: `后端已收到停止请求，取消 ${result.stopped || 0} 个任务` });
  } catch (error) {
    appendLog({ message: `后端停止请求失败：${error.message}` });
  }
  activeController.abort();
});

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = document.querySelector("#submit");
  const recordIds = [...document.querySelectorAll('input[name="saved-record"]:checked')].map((input) => input.value);
  if (!recordIds.length) { setNotice(notice, "请选择至少一个已保存账号"); return; }
  activeController = new AbortController();
  button.disabled = true; button.textContent = "执行中";
  document.querySelector("#stop").hidden = false;
  setNotice(notice, "");
  liveLog.replaceChildren(); document.querySelector("#results").hidden = true;
  try {
    const response = await fetch("/api/login-stream", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Password": adminPassword },
      signal: activeController.signal,
      body: JSON.stringify({
        record_ids: recordIds,
        proxies: proxyField.value,
        debug: document.querySelector("#debug").checked,
        retry_waf: document.querySelector("#retry-waf").checked,
      }),
    });
    await readEventStream(response);
  } catch (error) {
    if (activeController?.signal.aborted) {
      setNotice(notice, "任务已停止", true);
    } else {
      setNotice(notice, error.message);
      appendLog({ message: `任务中断：${error.message}` });
    }
  } finally {
    activeController = null;
    document.querySelector("#stop").hidden = true;
    button.disabled = false;
    button.textContent = "开始登录";
  }
});

document.querySelector("#record-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = document.querySelector("#records-notice");
  try {
    await request("/api/records", { method: "POST", body: JSON.stringify({
      email: document.querySelector("#record-email").value,
      password: document.querySelector("#record-password").value,
      time: document.querySelector("#record-time").value,
    }) });
    event.target.reset(); await loadRecords(); setNotice(target, "账号记录已添加", true);
  } catch (error) { setNotice(target, error.message); }
});

document.querySelector("#records-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-record-id]");
  if (!button) return;
  const target = document.querySelector("#records-notice");
  try { await request(`/api/records/${button.dataset.recordId}`, { method: "DELETE" }); await loadRecords(); setNotice(target, "账号记录已删除", true); }
  catch (error) { setNotice(target, error.message); }
});

document.querySelector("#code-library-select-all").addEventListener("change", (event) => {
  const start = (codeLibraryPage - 1) * codeLibraryPageSize;
  const pageEntries = codeLibrary.slice(start, start + codeLibraryPageSize);
  pageEntries.forEach((entry) => {
    if (event.target.checked) selectedCodeLibraryIds.add(entry.id);
    else selectedCodeLibraryIds.delete(entry.id);
  });
  renderCodeLibrary();
});

document.querySelector("#code-library-previous").addEventListener("click", () => {
  if (codeLibraryPage <= 1) return;
  codeLibraryPage -= 1; expandedCodeLibraryId = ""; renderCodeLibrary();
});

document.querySelector("#code-library-next").addEventListener("click", () => {
  const pageCount = Math.max(1, Math.ceil(codeLibrary.length / codeLibraryPageSize));
  if (codeLibraryPage >= pageCount) return;
  codeLibraryPage += 1; expandedCodeLibraryId = ""; renderCodeLibrary();
});

document.querySelector("#delete-code-library").addEventListener("click", async () => {
  const entryIds = [...selectedCodeLibraryIds];
  if (!entryIds.length || !window.confirm(`确定删除已选的 ${entryIds.length} 条优惠码记录吗？`)) return;
  const button = document.querySelector("#delete-code-library");
  const target = document.querySelector("#code-library-notice");
  button.disabled = true;
  try {
    const result = await request("/api/code-library", {
      method: "DELETE",
      body: JSON.stringify({ entry_ids: entryIds }),
    });
    selectedCodeLibraryIds.clear(); expandedCodeLibraryId = "";
    await loadCodeLibrary();
    setNotice(target, `已删除 ${result.deleted} 条优惠码记录`, true);
  } catch (error) {
    setNotice(target, error.message);
    renderCodeLibrary();
  }
});

codeLibraryMedia.addEventListener("change", (event) => {
  const firstVisibleIndex = (codeLibraryPage - 1) * codeLibraryPageSize;
  codeLibraryPageSize = event.matches ? 20 : 40;
  codeLibraryPage = Math.floor(firstVisibleIndex / codeLibraryPageSize) + 1;
  renderCodeLibrary();
});

document.querySelector("#default-account-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = document.querySelector("#default-account-password-notice");
  try {
    const result = await request("/api/settings/default-account-password", {
      method: "POST",
      body: JSON.stringify({ password: document.querySelector("#default-account-password").value }),
    });
    hasDefaultAccountPassword = Boolean(result.has_default_account_password);
    event.target.reset(); renderDefaultAccountPasswordState();
    setNotice(target, "默认账号密码已保存", true);
  } catch (error) { setNotice(target, error.message); }
});

document.querySelector("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentPassword = document.querySelector("#current-password").value;
  const newPassword = document.querySelector("#new-password").value;
  const confirmPassword = document.querySelector("#confirm-password").value;
  const target = document.querySelector("#password-notice");
  if (newPassword !== confirmPassword) { setNotice(target, "两次输入的新密码不一致"); return; }
  try {
    await request("/api/password", { method: "POST", body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) });
    adminPassword = newPassword; sessionStorage.setItem("sbeans-password", newPassword); event.target.reset(); setNotice(target, "面板密码已修改", true);
  } catch (error) { setNotice(target, error.message); }
});

if (adminPassword) openWorkspace().catch(() => sessionStorage.removeItem("sbeans-password"));
