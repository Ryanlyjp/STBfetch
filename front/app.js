const unlock = document.querySelector("#unlock");
const workspace = document.querySelector("#workspace");
const notice = document.querySelector("#notice");
const liveLog = document.querySelector("#live-log");
let adminPassword = sessionStorage.getItem("sbeans-password") || "";
let records = [];
let codeLibrary = [];
let activeController = null;
const proxyField = document.querySelector("#proxies");

try {
  const savedProxies = localStorage.getItem("sbeans-proxies");
  if (savedProxies !== null) proxyField.value = savedProxies;
} catch {
  // Local storage can be unavailable in restrictive browser modes.
}

proxyField.addEventListener("input", () => {
  try { localStorage.setItem("sbeans-proxies", proxyField.value); } catch { /* ignore */ }
});

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
  records = (await request("/api/records")).records;
  renderRecords();
}

function renderCodeLibrary() {
  const list = document.querySelector("#code-library-list");
  if (!codeLibrary.length) {
    list.innerHTML = '<p class="empty">暂无已归档的四组优惠码</p>';
    return;
  }
  list.replaceChildren(...codeLibrary.map((entry) => {
    const details = document.createElement("details"); details.className = "library-entry";
    const summary = document.createElement("summary"); summary.className = "library-summary";
    const email = document.createElement("strong"); email.textContent = entry.email || "未知账号";
    const nextDate = document.createElement("span"); nextDate.className = "library-next-date";
    nextDate.textContent = `下次日期：${entry.next_date || "未知"}`;
    summary.append(email, nextDate);
    const meta = document.createElement("p"); meta.className = "library-meta";
    meta.textContent = `采集时间：${entry.captured_at || "未知"}`;
    const codeList = document.createElement("div"); codeList.className = "code-list library-code-list";
    (Array.isArray(entry.codes) ? entry.codes : []).forEach((item) => {
      const row = document.createElement("div"); row.className = "code-entry";
      const plan = document.createElement("span"); plan.className = "code-plan"; plan.textContent = `计划 ${item.planId || "未知"}`;
      row.append(plan, createCopyButton(item.code, "复制码"), createCopyButton(item.endDate, "复制日期"));
      codeList.append(row);
    });
    details.append(summary, meta, codeList);
    return details;
  }));
}

async function loadCodeLibrary() {
  codeLibrary = (await request("/api/code-library")).entries;
  renderCodeLibrary();
}

async function openWorkspace() {
  await request("/api/session", { method: "POST" });
  await Promise.all([loadRecords(), loadCodeLibrary()]);
  unlock.hidden = true;
  workspace.hidden = false;
  document.querySelector("#health").textContent = "后端正常";
}

function appendLog(item) {
  if (liveLog.querySelector(".empty")) liveLog.replaceChildren();
  const row = document.createElement("p");
  const time = document.createElement("time");
  time.textContent = item.time ? new Date(item.time).toLocaleTimeString() : new Date().toLocaleTimeString();
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
      const codeList = document.createElement("div"); codeList.className = "code-list";
      codes.forEach((item) => {
        const entry = document.createElement("div"); entry.className = `code-entry${item.ok ? "" : " code-entry-error"}`;
        const plan = document.createElement("span"); plan.className = "code-plan"; plan.textContent = `计划 ${item.planId || "未知"}`;
        entry.append(plan);
        if (item.ok) {
          entry.append(createCopyButton(item.code, "复制码"), createCopyButton(item.endDate, "复制日期"));
        } else {
          const error = document.createElement("span"); error.className = "code-error"; error.textContent = item.error || "采集失败"; entry.append(error);
        }
        codeList.append(entry);
      });
      account.append(codeList);
    }
    return account;
  }));
  document.querySelector("#results").hidden = false;
}

function createCopyButton(value, label) {
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
    setNotice(notice, `${label}已复制`, true);
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
  const accounts = document.querySelector("#accounts").value;
  if (!accounts.trim() && !recordIds.length) { setNotice(notice, "请输入或选择至少一个账号"); return; }
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
      body: JSON.stringify({ accounts, record_ids: recordIds, proxies: proxyField.value, debug: document.querySelector("#debug").checked }),
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
