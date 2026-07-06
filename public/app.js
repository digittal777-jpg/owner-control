const OWNER_TOKEN_STORAGE_KEY = "ownerControlToken";

function readPersistedOwnerToken() {
  try {
    const legacyToken = localStorage.getItem(OWNER_TOKEN_STORAGE_KEY) || "";
    if (legacyToken) {
      sessionStorage.setItem(OWNER_TOKEN_STORAGE_KEY, legacyToken);
      localStorage.removeItem(OWNER_TOKEN_STORAGE_KEY);
      return legacyToken;
    }
    return sessionStorage.getItem(OWNER_TOKEN_STORAGE_KEY) || "";
  } catch (_error) {
    return "";
  }
}

function persistOwnerToken(token) {
  try {
    if (token) {
      sessionStorage.setItem(OWNER_TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(OWNER_TOKEN_STORAGE_KEY);
    }
    localStorage.removeItem(OWNER_TOKEN_STORAGE_KEY);
  } catch (_error) {
    // Si el navegador bloquea storage, seguimos en memoria.
  }
}

const state = {
  token: readPersistedOwnerToken(),
  clients: [],
  ownerRuntime: null,
  selectedSlug: "",
  detail: null,
  loading: false,
};

const refs = {
  tokenForm: document.getElementById("token-form"),
  ownerToken: document.getElementById("owner-token"),
  refreshClients: document.getElementById("refresh-clients"),
  createClientForm: document.getElementById("create-client-form"),
  secretBox: document.getElementById("secret-box"),
  secretOutput: document.getElementById("secret-output"),
  statusLine: document.getElementById("status-line"),
  ownerRuntimeConfigForm: document.getElementById("owner-runtime-config-form"),
  ownerRuntimeConfigSummary: document.getElementById("owner-runtime-config-summary"),
  ownerRuntimeVariablesWrap: document.getElementById("owner-runtime-variables-wrap"),
  clientList: document.getElementById("client-list"),
  detailTitle: document.getElementById("detail-title"),
  detailStatus: document.getElementById("detail-status"),
  summaryGrid: document.getElementById("summary-grid"),
  subscriptionForm: document.getElementById("subscription-form"),
  paymentForm: document.getElementById("payment-form"),
  clientConfigForm: document.getElementById("client-config-form"),
  clientConfigSyncSummary: document.getElementById("client-config-sync-summary"),
  clientModulesWrap: document.getElementById("client-modules-wrap"),
  clientAdminSectionsWrap: document.getElementById("client-admin-sections-wrap"),
  clientRuntimeConfigForm: document.getElementById("client-runtime-config-form"),
  clientRuntimeConfigSummary: document.getElementById("client-runtime-config-summary"),
  clientRuntimeVariablesWrap: document.getElementById("client-runtime-variables-wrap"),
  rotateKey: document.getElementById("rotate-key"),
  paymentsList: document.getElementById("payments-list"),
  healthList: document.getElementById("health-list"),
  validationList: document.getElementById("validation-list"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function sanitizeClassToken(value, fallback = "") {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (/^[a-z0-9_-]+$/.test(normalized)) {
    return normalized;
  }

  const safeFallback = String(fallback ?? "").trim().toLowerCase();
  return /^[a-z0-9_-]+$/.test(safeFallback) ? safeFallback : "";
}

function normalizeHostname(hostname) {
  return String(hostname || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
}

function isLoopbackHost(hostname) {
  const host = normalizeHostname(hostname);
  return host === "localhost"
    || host.endsWith(".localhost")
    || host === "::1"
    || host === "0.0.0.0"
    || host.startsWith("127.");
}

function getSuggestedControlApiUrl() {
  const fallback = "https://owner-control.tudominio.com";
  try {
    const parsed = new URL(String(location.origin || "").trim());
    if (parsed.protocol === "https:" || isLoopbackHost(parsed.hostname)) {
      return parsed.origin;
    }
  } catch (_error) {
    return fallback;
  }
  return fallback;
}

function formatMoney(value, currency = "MXN") {
  return new Intl.NumberFormat("es-MX", {
    style: "currency",
    currency,
    maximumFractionDigits: 2,
  }).format(Number(value || 0));
}

function formatDate(value) {
  return value ? String(value).slice(0, 10) : "sin fecha";
}

function formatHealthStatus(value) {
  const status = String(value || "unknown").toLowerCase();
  if (status === "ok") return "Sano";
  if (status === "risk") return "Riesgo";
  if (status === "critical") return "Critico";
  return "Sin reporte";
}

function formatConfigSyncStatus(value) {
  const status = String(value || "unknown").toLowerCase();
  if (status === "applied") return "Aplicada";
  if (status === "pending") return "Pendiente";
  if (status === "stale") return "Desfasada";
  if (status === "failed") return "Fallida";
  return "Sin reporte";
}

function setStatus(message, kind = "info") {
  refs.statusLine.textContent = message;
  refs.statusLine.dataset.kind = sanitizeClassToken(kind, "info");
}

function getToken() {
  return state.token || refs.ownerToken.value.trim();
}

async function ownerFetch(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-Owner-Control-Token": getToken(),
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (_error) {
    body = { message: text };
  }
  if (!response.ok) {
    throw new Error(body?.message || `HTTP ${response.status}`);
  }
  return body;
}

function readForm(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function setDetailFormsEnabled(enabled) {
  [refs.subscriptionForm, refs.paymentForm, refs.clientConfigForm, refs.clientRuntimeConfigForm].forEach((form) => {
    form.querySelectorAll("input, select, textarea, button").forEach((element) => {
      element.disabled = !enabled;
    });
  });
  refs.rotateKey.disabled = !enabled;
}

function setOwnerRuntimeFormEnabled(enabled) {
  refs.ownerRuntimeConfigForm.querySelectorAll("input, select, textarea, button").forEach((element) => {
    element.disabled = !enabled;
  });
}

function resetAuthenticatedOwnerState() {
  state.clients = [];
  state.selectedSlug = "";
  state.detail = null;
  state.ownerRuntime = null;
  renderClients();
  renderDetail();
  renderOwnerRuntimeConfig();
  setDetailFormsEnabled(false);
  setOwnerRuntimeFormEnabled(false);
}

function renderClients() {
  refs.clientList.innerHTML = state.clients.length
    ? state.clients.map((client) => `
        <button class="client-row ${client.slug === state.selectedSlug ? "active" : ""}" data-slug="${escapeHtml(client.slug)}" type="button">
          <span>
            <strong>${escapeHtml(client.businessName)}</strong>
            <small>${escapeHtml(client.slug)} · ${escapeHtml(client.baseUrl || "sin url")}</small>
          </span>
          <span class="status-pill ${sanitizeClassToken(client.subscription?.status, "trial")}">${escapeHtml(client.subscription?.status || "trial")}</span>
          <span class="health-dot ${sanitizeClassToken(client.healthStatus, "unknown")}">${escapeHtml(formatHealthStatus(client.healthStatus))}</span>
          <span class="status-pill config-sync ${sanitizeClassToken(client.config?.sync?.status, "unknown")}">${escapeHtml(formatConfigSyncStatus(client.config?.sync?.status))}</span>
        </button>
      `).join("")
    : `<div class="empty-state">Sin clientes registrados.</div>`;
}

function renderSecret(client, apiKey) {
  const controlApiUrl = getSuggestedControlApiUrl();
  refs.secretBox.hidden = false;
  refs.secretOutput.textContent = [
    `CONTROL_API_URL=${controlApiUrl}`,
    `CONTROL_CLIENT_SLUG=${client.slug}`,
    `CONTROL_CLIENT_SECRET=${apiKey}`,
    "",
    "# Si owner-control fuerza HTTPS o firmas cliente, las pruebas API del POS",
    "# tambien requieren X-Client-Timestamp, X-Client-Nonce y X-Client-Signature.",
  ].join("\n");
}

function renderSummary(detail) {
  const client = detail?.client;
  if (!client) {
    refs.summaryGrid.innerHTML = `<div class="empty-state">Sin detalle cargado.</div>`;
    return;
  }
  const subscription = client.subscription || {};
  const config = client.config || {};
  const configSync = config.sync || {};
  const runtimeConfig = client.runtimeConfig || {};
  const runtimeSync = runtimeConfig.sync || {};
  refs.summaryGrid.innerHTML = `
    <article class="summary-card">
      <span>Mensualidad</span>
      <strong>${formatMoney(subscription.monthlyAmount, subscription.currencyCode || "MXN")}</strong>
      <p>${escapeHtml(subscription.planCode || "sin plan")}</p>
    </article>
    <article class="summary-card">
      <span>Corte</span>
      <strong>${escapeHtml(formatDate(subscription.currentPeriodEnd))}</strong>
      <p>Gracia ${escapeHtml(formatDate(subscription.gracePeriodUntil))}</p>
    </article>
    <article class="summary-card">
      <span>Ultimo pago</span>
      <strong>${escapeHtml(formatDate(subscription.lastPaymentAt))}</strong>
      <p>${escapeHtml(subscription.status || "trial")}</p>
    </article>
    <article class="summary-card">
      <span>Salud</span>
      <strong>${escapeHtml(formatHealthStatus(client.healthStatus))}</strong>
      <p>${escapeHtml(formatDate(client.latestHealthAt))}</p>
    </article>
    <article class="summary-card">
      <span>Config POS</span>
      <strong>${escapeHtml(formatConfigSyncStatus(configSync.status))}</strong>
      <p>${configSync.inSync ? "POS al dia" : "Esperando POS"} - ${escapeHtml(formatDate(configSync.syncedAt || config.updatedAt))}</p>
    </article>
    <article class="summary-card">
      <span>Variables POS</span>
      <strong>${escapeHtml(formatConfigSyncStatus(runtimeSync.status))}</strong>
      <p>${runtimeSync.inSync ? "Runtime al dia" : "Esperando POS"} - ${escapeHtml(formatDate(runtimeSync.syncedAt || runtimeConfig.updatedAt))}</p>
    </article>
    <article class="summary-card">
      <span>Validacion</span>
      <strong>${client.latestValidationAt ? "Reportada" : "Sin validar"}</strong>
      <p>${escapeHtml(formatDate(client.latestValidationAt))}</p>
    </article>
  `;
}

function fillForms(detail) {
  const client = detail?.client;
  const subscription = client?.subscription || {};
  refs.subscriptionForm.elements.status.value = subscription.status || "trial";
  refs.subscriptionForm.elements.planCode.value = subscription.planCode || "beta";
  refs.subscriptionForm.elements.monthlyAmount.value = String(subscription.monthlyAmount || 0);
  refs.subscriptionForm.elements.currentPeriodStart.value = subscription.currentPeriodStart || "";
  refs.subscriptionForm.elements.currentPeriodEnd.value = subscription.currentPeriodEnd || "";
  refs.subscriptionForm.elements.gracePeriodUntil.value = subscription.gracePeriodUntil || "";
  if (!refs.paymentForm.elements.amount.value) {
    refs.paymentForm.elements.amount.value = String(subscription.monthlyAmount || "");
  }
}

function renderToggleGroup(container, definitions, selectedValues, inputName) {
  const selected = new Set(Array.isArray(selectedValues) ? selectedValues : []);
  container.innerHTML = Array.isArray(definitions) && definitions.length
    ? definitions.map((item) => `
        <label class="owner-toggle">
          <input type="checkbox" name="${escapeHtml(inputName)}" value="${escapeHtml(item.code)}" ${selected.has(item.code) ? "checked" : ""} />
          <span class="toggle-copy">
            <strong>${escapeHtml(item.label || item.code)}</strong>
            <small>${escapeHtml(item.description || item.code)}</small>
          </span>
        </label>
      `).join("")
    : `<div class="empty-state">Sin opciones configurables.</div>`;
}

function renderClientConfig(detail) {
  const client = detail?.client;
  const config = client?.config || {};
  const sync = config.sync || {};
  renderClientConfigSyncSummary(detail);
  renderToggleGroup(
    refs.clientModulesWrap,
    detail?.availableModules || [],
    config.enabledModules || [],
    "enabledModules",
  );
  renderToggleGroup(
    refs.clientAdminSectionsWrap,
    detail?.adminSections || [],
    config.adminCapabilities || [],
    "adminCapabilities",
  );
}

function renderClientConfigSyncSummary(detail) {
  const client = detail?.client;
  const config = client?.config || {};
  const sync = config.sync || {};
  if (refs.clientConfigSyncSummary) {
    refs.clientConfigSyncSummary.className = `config-sync-summary ${sanitizeClassToken(sync.status, "unknown")}`;
    refs.clientConfigSyncSummary.innerHTML = client
      ? `
          <strong>${escapeHtml(formatConfigSyncStatus(sync.status))}</strong>
          <span>${sync.inSync ? "El POS ya aplico esta configuracion." : "Esperando que el POS la aplique."}</span>
          <small>Cambio ${escapeHtml(formatDate(config.updatedAt))} - POS ${escapeHtml(formatDate(sync.syncedAt))}</small>
          ${sync.message ? `<small>${escapeHtml(sync.message)}</small>` : ""}
        `
      : `<div class="empty-state">Selecciona un cliente para ver ejecucion POS.</div>`;
  }
}

function renderClientRuntimeConfig(detail) {
  const client = detail?.client;
  const runtimeConfig = client?.runtimeConfig || {};
  const sync = runtimeConfig.sync || {};
  renderClientRuntimeConfigSyncSummary(detail);
  const variables = Array.isArray(runtimeConfig.variables)
    ? runtimeConfig.variables
    : detail?.runtimeVariables || [];
  const groups = variables.reduce((result, variable) => {
    const groupName = variable.group || "General";
    result[groupName] = result[groupName] || [];
    result[groupName].push(variable);
    return result;
  }, {});
  refs.clientRuntimeVariablesWrap.innerHTML = Object.keys(groups).length
    ? Object.entries(groups).map(([groupName, items]) => `
        <section class="runtime-group">
          <h4>${escapeHtml(groupName)}</h4>
          <div class="runtime-grid">
            ${items.map((variable) => renderRuntimeVariableField(variable)).join("")}
          </div>
        </section>
      `).join("")
    : `<div class="empty-state">Sin variables runtime configurables.</div>`;
}

function renderClientRuntimeConfigSyncSummary(detail) {
  const client = detail?.client;
  const runtimeConfig = client?.runtimeConfig || {};
  const sync = runtimeConfig.sync || {};
  if (refs.clientRuntimeConfigSummary) {
    refs.clientRuntimeConfigSummary.className = `config-sync-summary ${sanitizeClassToken(sync.status, "unknown")}`;
    refs.clientRuntimeConfigSummary.innerHTML = client
      ? `
          <strong>${escapeHtml(formatConfigSyncStatus(sync.status))}</strong>
          <span>${sync.inSync ? "El POS ya aplico estas variables." : "Esperando que el POS sincronice variables."}</span>
          <small>Cambio ${escapeHtml(formatDate(runtimeConfig.updatedAt))} - POS ${escapeHtml(formatDate(sync.syncedAt))}</small>
          ${sync.message ? `<small>${escapeHtml(sync.message)}</small>` : ""}
        `
      : `<div class="empty-state">Selecciona un cliente para editar variables.</div>`;
  }
}

function renderOwnerRuntimeConfig() {
  const runtimeConfig = state.ownerRuntime?.runtimeConfig || {};
  const variables = Array.isArray(runtimeConfig.variables)
    ? runtimeConfig.variables
    : state.ownerRuntime?.runtimeVariables || [];
  const groups = variables.reduce((result, variable) => {
    const groupName = variable.group || "General";
    result[groupName] = result[groupName] || [];
    result[groupName].push(variable);
    return result;
  }, {});

  const summaryKind = runtimeConfig.restartRequired ? "pending" : "applied";
  refs.ownerRuntimeConfigSummary.className = `config-sync-summary ${sanitizeClassToken(summaryKind, "unknown")}`;
  refs.ownerRuntimeConfigSummary.innerHTML = getToken()
    ? `
        <strong>${runtimeConfig.restartRequired ? "Reinicio pendiente" : "Sin reinicio pendiente"}</strong>
        <span>${escapeHtml(runtimeConfig.message || "Sin cambios runtime pendientes en owner-control.")}</span>
        <small>Cambio ${escapeHtml(formatDate(runtimeConfig.updatedAt))} - pendientes ${Array.isArray(runtimeConfig.pendingKeys) ? runtimeConfig.pendingKeys.length : 0}</small>
      `
    : `<div class="empty-state">Conecta el token owner para editar el runtime de owner-control.</div>`;

  refs.ownerRuntimeVariablesWrap.innerHTML = Object.keys(groups).length
    ? Object.entries(groups).map(([groupName, items]) => `
        <section class="runtime-group">
          <h4>${escapeHtml(groupName)}</h4>
          <div class="runtime-grid">
            ${items.map((variable) => renderRuntimeVariableField(variable)).join("")}
          </div>
        </section>
      `).join("")
    : `<div class="empty-state">Sin variables runtime configurables.</div>`;
}

function renderRuntimeVariableField(variable) {
  const isSecret = Boolean(variable.secret);
  const options = Array.isArray(variable.options) ? variable.options : [];
  const hasStoredValue = Boolean(variable.hasStoredValue);
  const value = variable.value || "";
  const managedHint = variable.managedHint || (
    variable.managedByClientSync === false
      ? "emparejamiento local"
      : "sincroniza al POS"
  );
  const control = variable.type === "select"
    ? `<select name="${escapeHtml(variable.key)}" data-runtime-key="${escapeHtml(variable.key)}" data-runtime-secret="${isSecret ? "true" : "false"}">
        ${options.map((option) => `<option value="${escapeHtml(option)}" ${String(option) === String(value) ? "selected" : ""}>${escapeHtml(option || "sin valor")}</option>`).join("")}
      </select>`
    : `<input
        name="${escapeHtml(variable.key)}"
        data-runtime-key="${escapeHtml(variable.key)}"
        data-runtime-secret="${isSecret ? "true" : "false"}"
        type="${isSecret ? "password" : "text"}"
        value="${isSecret ? "" : escapeHtml(value)}"
        placeholder="${escapeHtml(isSecret && hasStoredValue ? "********" : variable.placeholder || "")}"
        autocomplete="off"
        spellcheck="false"
      />`;
  return `
    <label class="runtime-field">
      <span>${escapeHtml(variable.label || variable.key)}</span>
      ${control}
      <small>${escapeHtml(variable.key)} - ${escapeHtml(managedHint)}${hasStoredValue ? " - guardada" : ""}</small>
      <small>${escapeHtml(isSecret && hasStoredValue ? "Deja vacio para conservar el secreto actual." : variable.description || "")}</small>
      <span class="runtime-clear-row">
        <input type="checkbox" data-runtime-clear="${escapeHtml(variable.key)}" />
        <small>Limpiar variable</small>
      </span>
    </label>
  `;
}

function getCheckedValues(form, name) {
  return [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((input) => input.value);
}

function getRuntimeConfigPayload(form = refs.clientRuntimeConfigForm) {
  const values = {};
  const clearKeys = [];
  form
    .querySelectorAll("[data-runtime-key]")
    .forEach((field) => {
      const key = field.dataset.runtimeKey || "";
      const isSecret = field.dataset.runtimeSecret === "true";
      const value = String(field.value || "").trim();
      const clearInput = [...form.querySelectorAll("[data-runtime-clear]")]
        .find((input) => input.dataset.runtimeClear === key);
      if (clearInput?.checked) {
        clearKeys.push(key);
        return;
      }
      if (isSecret && !value) {
        return;
      }
      values[key] = value;
    });
  return { values, clearKeys };
}

function getIssueText(item) {
  return String(item?.message || item?.title || item?.code || "");
}

function renderIssueList(items, emptyLabel) {
  const list = Array.isArray(items) ? items.filter((item) => getIssueText(item)) : [];
  if (!list.length) {
    return `<p class="health-issue-empty">${escapeHtml(emptyLabel)}</p>`;
  }
  return `
    <ul class="health-issue-list">
      ${list.map((item) => `
        <li class="${sanitizeClassToken(item.severity, "risk")}">
          <span>${escapeHtml(item.code || item.severity || "estado")}</span>
          <strong>${escapeHtml(getIssueText(item))}</strong>
        </li>
      `).join("")}
    </ul>
  `;
}

function getBackupHealthSummary(report) {
  const backups = report?.metrics?.backups;
  if (!backups || typeof backups !== "object") {
    return "";
  }
  const state = backups.enabled ? "Backups activos" : "Backups apagados";
  const lastRun = backups.enabled && backups.lastRun?.status
    ? ` - ultimo ${backups.lastRun.status}`
    : "";
  const restart = backups.restartRequired ? " - reinicio pendiente" : "";
  return `${state}${lastRun}${restart}`;
}

function getHealthSignature(report) {
  return JSON.stringify({
    status: report?.status || "unknown",
    reasons: (report?.reasons || []).map((item) => getIssueText(item)),
    actions: (report?.actions || []).map((item) => getIssueText(item)),
  });
}

function renderPayments(payments) {
  refs.paymentsList.innerHTML = payments?.length
    ? payments.map((payment) => `
        <article class="record">
          <strong>${formatMoney(payment.amount)}</strong>
          <p>${escapeHtml(payment.paymentMethod || "Pago")} · ${escapeHtml(formatDate(payment.periodStart))} a ${escapeHtml(formatDate(payment.periodEnd))}</p>
          <small>${escapeHtml(payment.notes || payment.paidAt || "")}</small>
        </article>
      `).join("")
    : `<div class="empty-state">Sin pagos.</div>`;
}

function renderHealthLegacyUnused(reports) {
  refs.healthList.innerHTML = reports?.length
    ? reports.map((report) => `
        <article class="record">
          <strong>${escapeHtml(report.status || "unknown")}</strong>
          <p>${escapeHtml(formatDate(report.receivedAt))} · causas ${(report.reasons || []).length} · acciones ${(report.actions || []).length}</p>
          <small>${escapeHtml((report.actions || [])[0]?.title || (report.reasons || [])[0]?.title || "Sin accion principal")}</small>
        </article>
      `).join("")
    : `<div class="empty-state">Sin reportes de salud.</div>`;
}

function renderHealth(reports) {
  if (!reports?.length) {
    refs.healthList.innerHTML = `<div class="empty-state">Sin reportes de salud.</div>`;
    return;
  }

  const compacted = [];
  reports.forEach((report) => {
    const signature = getHealthSignature(report);
    const latest = compacted[compacted.length - 1];
    if (latest && latest.signature === signature) {
      latest.count += 1;
      latest.firstReceivedAt = report.receivedAt || latest.firstReceivedAt;
      return;
    }
    compacted.push({
      report,
      signature,
      count: 1,
      firstReceivedAt: report.receivedAt,
    });
  });

  const latest = compacted[0];
  const latestAction = getIssueText((latest.report.actions || [])[0])
    || getIssueText((latest.report.reasons || [])[0])
    || "Sin accion principal";
  const backupSummary = getBackupHealthSummary(latest.report);
  refs.healthList.innerHTML = `
    <article class="record health-latest ${sanitizeClassToken(latest.report.status, "unknown")}">
      <strong>${escapeHtml(latest.report.status || "unknown")}</strong>
      <p>${escapeHtml(formatDate(latest.report.receivedAt))} - causas ${(latest.report.reasons || []).length} - acciones ${(latest.report.actions || []).length}</p>
      ${backupSummary ? `<p class="health-backup-state">${escapeHtml(backupSummary)}</p>` : ""}
      <small>${escapeHtml(latestAction)}</small>
      <div class="health-issue-columns">
        <section>
          <span>Causas</span>
          ${renderIssueList(latest.report.reasons, "Sin causas activas.")}
        </section>
        <section>
          <span>Acciones</span>
          ${renderIssueList(latest.report.actions, "Sin acciones pendientes.")}
        </section>
      </div>
      ${latest.count > 1 ? `<span class="record-count">${latest.count} reportes iguales compactados</span>` : ""}
    </article>
    <div class="record-history">
      ${compacted.slice(1, 8).map((entry) => `
        <article class="record compact-record">
          <strong>${escapeHtml(entry.report.status || "unknown")}</strong>
          <p>${escapeHtml(formatDate(entry.report.receivedAt))}${entry.count > 1 ? ` - x${entry.count}` : ""}</p>
          <small>${escapeHtml(getIssueText((entry.report.actions || [])[0]) || getIssueText((entry.report.reasons || [])[0]) || "Sin accion principal")}</small>
        </article>
      `).join("") || `<div class="empty-state">Sin historial diferente reciente.</div>`}
    </div>
  `;
}

function renderValidations(reports) {
  refs.validationList.innerHTML = reports?.length
    ? reports.map((report) => `
        <article class="record">
          <strong>${escapeHtml(report.status || "unknown")}</strong>
          <p>${escapeHtml(report.url || "sin url")} · ${escapeHtml(formatDate(report.receivedAt))}</p>
          <small>${(report.checks || []).filter((check) => check.ok === false).length} fallas de ${(report.checks || []).length} checks</small>
        </article>
      `).join("")
    : `<div class="empty-state">Sin validaciones.</div>`;
}

function renderDetail() {
  const detail = state.detail;
  const client = detail?.client;
  if (!client) {
    refs.detailTitle.textContent = "Selecciona un cliente";
    refs.detailStatus.textContent = "Sin cliente";
    refs.detailStatus.className = "status-pill";
    refs.summaryGrid.innerHTML = `<div class="empty-state">Elige un negocio para ver pagos, salud y validaciones.</div>`;
    renderClientConfig(null);
    renderClientRuntimeConfig(null);
    renderPayments([]);
    renderHealth([]);
    renderValidations([]);
    setDetailFormsEnabled(false);
    return;
  }

  refs.detailTitle.textContent = client.businessName;
  refs.detailStatus.textContent = client.subscription?.status || "trial";
  refs.detailStatus.className = `status-pill ${sanitizeClassToken(client.subscription?.status, "trial")}`;
  setDetailFormsEnabled(true);
  renderSummary(detail);
  fillForms(detail);
  renderClientConfig(detail);
  renderClientRuntimeConfig(detail);
  renderPayments(detail.payments || []);
  renderHealth(detail.healthReports || []);
  renderValidations(detail.validationReports || []);
}

async function loadClients() {
  if (!getToken()) {
    resetAuthenticatedOwnerState();
    setStatus("Captura OWNER_CONTROL_TOKEN.", "warning");
    return;
  }
  state.loading = true;
  setStatus("Cargando clientes...");
  try {
    const response = await ownerFetch("/api/owner/clients");
    state.clients = response.clients || [];
    if (!state.selectedSlug && state.clients[0]) {
      state.selectedSlug = state.clients[0].slug;
    }
    renderClients();
    await loadOwnerRuntimeConfig();
    if (state.selectedSlug) {
      await loadDetail(state.selectedSlug);
    }
    setStatus(`${state.clients.length} cliente(s) cargados.`, "ok");
  } catch (error) {
    if (/token owner central|401/i.test(String(error.message || ""))) {
      resetAuthenticatedOwnerState();
    }
    setStatus(error.message || "No pude cargar clientes.", "error");
  } finally {
    state.loading = false;
  }
}

async function loadOwnerRuntimeConfig() {
  if (!getToken()) {
    state.ownerRuntime = null;
    renderOwnerRuntimeConfig();
    setOwnerRuntimeFormEnabled(false);
    return;
  }
  const response = await ownerFetch("/api/owner/runtime-config");
  state.ownerRuntime = response;
  renderOwnerRuntimeConfig();
  setOwnerRuntimeFormEnabled(true);
}

async function loadDetail(slug) {
  state.selectedSlug = slug;
  renderClients();
  const response = await ownerFetch(`/api/owner/clients/${encodeURIComponent(slug)}`);
  state.detail = response;
  renderDetail();
}

async function refreshSelectedDetailQuietly() {
  if (!state.selectedSlug || !getToken() || document.hidden) {
    return;
  }
  const activeElement = document.activeElement;
  const isEditingField = Boolean(
    activeElement
    && ["INPUT", "SELECT", "TEXTAREA"].includes(activeElement.tagName)
    && activeElement.closest(".stack-form"),
  );
  try {
    const response = await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}`);
    state.detail = response;
    state.clients = state.clients.map((client) => (
      client.slug === response.client?.slug ? response.client : client
    ));
    renderClients();
    if (isEditingField) {
      renderSummary(response);
      renderClientConfigSyncSummary(response);
      renderClientRuntimeConfigSyncSummary(response);
      return;
    }
    renderDetail();
  } catch (_error) {
    // El panel puede quedar abierto mientras el servicio reinicia; no molestamos al owner.
  }
}

refs.tokenForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.token = refs.ownerToken.value.trim();
  persistOwnerToken(state.token);
  await loadClients();
});

refs.refreshClients.addEventListener("click", () => {
  void loadClients();
});

refs.createClientForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const response = await ownerFetch("/api/owner/clients", {
      method: "POST",
      body: JSON.stringify(readForm(refs.createClientForm)),
    });
    renderSecret(response.client, response.apiKey);
    refs.createClientForm.reset();
    refs.createClientForm.elements.planCode.value = "beta";
    refs.createClientForm.elements.monthlyAmount.value = "0";
    state.selectedSlug = response.client.slug;
    await loadClients();
    setStatus("Cliente creado.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude crear el cliente.", "error");
  }
});

refs.clientList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-slug]");
  if (!button) {
    return;
  }
  try {
    await loadDetail(button.dataset.slug);
    setStatus("Detalle actualizado.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude abrir el cliente.", "error");
  }
});

refs.subscriptionForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedSlug) {
    return;
  }
  try {
    await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}/subscription`, {
      method: "PATCH",
      body: JSON.stringify(readForm(refs.subscriptionForm)),
    });
    await loadDetail(state.selectedSlug);
    await loadClients();
    setStatus("Suscripcion guardada.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude guardar suscripcion.", "error");
  }
});

refs.paymentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedSlug) {
    return;
  }
  try {
    await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}/payments`, {
      method: "POST",
      body: JSON.stringify(readForm(refs.paymentForm)),
    });
    refs.paymentForm.elements.notes.value = "";
    await loadDetail(state.selectedSlug);
    await loadClients();
    setStatus("Pago registrado.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude registrar el pago.", "error");
  }
});

refs.clientConfigForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedSlug) {
    return;
  }
  try {
    await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}/config`, {
      method: "PATCH",
      body: JSON.stringify({
        enabledModules: getCheckedValues(refs.clientConfigForm, "enabledModules"),
        adminCapabilities: getCheckedValues(refs.clientConfigForm, "adminCapabilities"),
      }),
    });
    await loadDetail(state.selectedSlug);
    await loadClients();
    setStatus("Configuracion POS guardada.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude guardar configuracion POS.", "error");
  }
});

refs.clientRuntimeConfigForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedSlug) {
    return;
  }
  try {
    const payload = getRuntimeConfigPayload();
    await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}/runtime-config`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    await loadDetail(state.selectedSlug);
    await loadClients();
    setStatus("Variables POS guardadas en owner-control.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude guardar variables POS.", "error");
  }
});

refs.ownerRuntimeConfigForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = getRuntimeConfigPayload(refs.ownerRuntimeConfigForm);
    const response = await ownerFetch("/api/owner/runtime-config", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    state.ownerRuntime = response;
    renderOwnerRuntimeConfig();
    setStatus(
      response.runtimeConfig?.restartRequired
        ? "Variables owner-control guardadas. Reinicio pendiente para aplicar HTTPS y seguridad."
        : "Variables owner-control guardadas.",
      "ok",
    );
  } catch (error) {
    setStatus(error.message || "No pude guardar variables owner-control.", "error");
  }
});

refs.rotateKey.addEventListener("click", async () => {
  if (!state.selectedSlug) {
    return;
  }
  if (!window.confirm("Rotar la API key invalida la clave anterior. Continuar?")) {
    return;
  }
  try {
    const response = await ownerFetch(`/api/owner/clients/${encodeURIComponent(state.selectedSlug)}/rotate-key`, {
      method: "POST",
    });
    renderSecret(response.client, response.apiKey);
    await loadDetail(state.selectedSlug);
    await loadClients();
    setStatus("API key rotada.", "ok");
  } catch (error) {
    setStatus(error.message || "No pude rotar API key.", "error");
  }
});

refs.ownerToken.value = state.token;
setDetailFormsEnabled(false);
setOwnerRuntimeFormEnabled(false);
renderOwnerRuntimeConfig();
void loadClients();
setInterval(() => {
  void refreshSelectedDetailQuietly();
}, 3000);
