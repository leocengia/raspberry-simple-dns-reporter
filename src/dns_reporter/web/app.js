const numberFormat = new Intl.NumberFormat();
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});
const queryDateFormat = new Intl.DateTimeFormat("en-GB", {
  timeZone: "Europe/Rome",
  year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit",
  timeZoneName: "short",
});

const elements = {
  sourceState: document.querySelector("#source-state"),
  devicesControl: document.querySelector("#devices-control"),
  deviceList: document.querySelector("#device-list"),
  groupControl: document.querySelector("#group-control"),
  groupSelect: document.querySelector("#group-select"),
  groupHint: document.querySelector("#group-hint"),
  rollingControl: document.querySelector("#rolling-control"),
  dateControl: document.querySelector("#date-control"),
  reportDate: document.querySelector("#report-date"),
  generateButton: document.querySelector("#generate-button"),
  error: document.querySelector("#error-banner"),
  loading: document.querySelector("#loading"),
  report: document.querySelector("#report"),
  detail: document.querySelector("#detail-panel"),
  queryPanel: document.querySelector("#query-panel"),
  queryRows: document.querySelector("#query-rows"),
  queryCount: document.querySelector("#query-count"),
  queryEmpty: document.querySelector("#query-empty"),
  loadMore: document.querySelector("#load-more-queries"),
};

let currentReport = null;
let availableGroups = [];
let currentService = null;
let queryState = null;
let exportInProgress = false;

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setSourceState(kind, message) {
  elements.sourceState.classList.remove("ok", "degraded");
  if (kind) elements.sourceState.classList.add(kind);
  elements.sourceState.lastChild.textContent = ` ${message}`;
}

function sleep(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function todayInRome() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Rome", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(new Date());
  const value = Object.fromEntries(parts.map((part) => [part.type, part.value]));
  return `${value.year}-${value.month}-${value.day}`;
}

async function initialize() {
  try {
    const health = await requestJson("/api/health");
    const healthy = health.status === "ok";
    setSourceState(healthy ? "ok" : "degraded", healthy ? "Sources ready" : "Source degraded");

    let inventory;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        inventory = await requestJson("/api/devices");
        break;
      } catch (error) {
        if (error.status !== 503 || attempt === 2) throw error;
        setSourceState("degraded", "Source busy · retrying");
        await sleep(500 * (2 ** attempt));
      }
    }
    const { devices, groups } = inventory;
    if (!devices.length) throw new Error("No devices found in the recent Pi-hole history.");
    renderDeviceOptions(devices);
    renderGroupOptions(groups || []);
    setSourceState("ok", "Sources ready");
    updateControls();
  } catch (error) {
    showError(error.message);
    setSourceState("degraded", "Sources unavailable");
  }
}

async function generateReport() {
  hideError();
  elements.loading.hidden = false;
  elements.generateButton.disabled = true;
  elements.detail.hidden = true;
  try {
    const periodMode = document.querySelector('input[name="period-mode"]:checked').value;
    const mode = document.querySelector('input[name="scope"]:checked').value;
    const request = periodMode === "calendar"
      ? { report_date: elements.reportDate.value }
      : { hours: Number(document.querySelector("#hours-select").value) };
    if (mode === "group") {
      request.group_id = elements.groupSelect.value;
    } else {
      request.device_ids = [...document.querySelectorAll('.device-option input:checked')]
        .map((input) => input.value);
    }
    currentReport = await requestJson("/api/report", {
      method: "POST",
      body: JSON.stringify(request),
    });
    renderReport(currentReport);
    elements.queryPanel.hidden = true;
  } catch (error) {
    showError(error.message);
  } finally {
    elements.loading.hidden = true;
    updateControls();
  }
}

function renderReport(report) {
  elements.report.hidden = false;
  document.querySelector("#scope-type").textContent = report.scope.type === "group"
    ? "Pi-hole group"
    : report.scope.device_count === 1 ? "Selected device" : "Selected devices";
  document.querySelector("#device-name").textContent = report.scope.display_name;
  const onlyDevice = report.scope.device_count === 1 ? report.scope.devices[0] : null;
  const meta = onlyDevice
    ? [onlyDevice.address, onlyDevice.vendor, onlyDevice.device_type].filter(Boolean).join(" · ")
    : `${numberFormat.format(report.scope.device_count)} devices included`;
  document.querySelector("#device-meta").textContent = meta;
  document.querySelector("#generated-at").textContent = `Generated ${dateFormat.format(new Date(report.generated_at))}`;
  document.querySelector("#total-queries").textContent = numberFormat.format(report.overview.total_queries);
  document.querySelector("#blocked-percentage").textContent = `${report.overview.blocked_percentage}%`;
  document.querySelector("#blocked-queries").textContent = `${numberFormat.format(report.overview.blocked_queries)} queries`;
  document.querySelector("#unique-domains").textContent = numberFormat.format(report.overview.unique_domains);
  document.querySelector("#identified-services").textContent = numberFormat.format(report.overview.identified_services);
  document.querySelector("#new-domains").textContent = numberFormat.format(report.overview.new_domains);
  document.querySelector("#signal-count").textContent = numberFormat.format(report.changes.signals.length);
  document.querySelector("#summary").textContent = report.summary;
  document.querySelector("#caveat").textContent = report.caveat;
  document.querySelector("#timeline-range").textContent = report.range_kind === "calendar_day"
    ? `${report.report_date}${report.complete_day ? "" : " · so far"}`
    : report.hours === 168 ? "Last 7 days" : `Last ${report.hours}h`;
  renderSignals(report.changes);
  renderTimeline(document.querySelector("#activity-chart"), report.timeline, "DNS queries");
  renderServices(report.services);
  elements.report.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderSignals(changes) {
  document.querySelector("#baseline-label").textContent = changes.baseline_days
    ? `Previous ${changes.baseline_days} days`
    : "No baseline";
  const list = document.querySelector("#signals-list");
  document.querySelector("#export-all-md").hidden = !changes.signals.length;
  document.querySelector("#export-all-csv").hidden = !changes.signals.length;
  document.querySelector("#export-all-jsonl").hidden = !changes.signals.length;
  list.replaceChildren();
  if (!changes.signals.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No changes crossed the conservative review thresholds.";
    list.append(empty);
    return;
  }
  for (const signal of changes.signals) {
    const item = document.createElement("article");
    item.className = `signal-item ${signal.severity}`;
    const title = document.createElement("strong");
    title.textContent = signal.title;
    const detail = document.createElement("p");
    detail.textContent = signal.detail;
    const metrics = document.createElement("p");
    metrics.className = "signal-metrics";
    metrics.textContent = `${numberFormat.format(signal.query_count)} queries · ${numberFormat.format(signal.unique_domains)} unique domains · ${numberFormat.format(signal.device_count)} devices`;
    const interval = document.createElement("p");
    interval.className = "signal-interval";
    interval.textContent = formatInterval(signal.interval);
    item.append(title, detail, metrics, interval);
    const values = signal.domains
      ? signal.domains.map((domain) => {
          const firstSeen = domain.first_seen
            ? ` · first in window ${dateFormat.format(new Date(domain.first_seen))}`
            : "";
          return `${domain.domain} · ${numberFormat.format(domain.queries)}${firstSeen}`;
        })
      : signal.services || [];
    if (values.length) {
      const tags = document.createElement("div");
      tags.className = "signal-domains";
      for (const value of values) {
        const tag = document.createElement("code");
        tag.textContent = value;
        tags.append(tag);
      }
      item.append(tags);
    }
    const actions = document.createElement("div");
    actions.className = "query-actions";
    actions.append(
      actionButton("View queries", () => openQueryLog("signal", { signal_id: signal.signal_id }, signal.title)),
      actionButton("Export LLM .md", () => exportQueries("md", "signal", { signal_id: signal.signal_id })),
      actionButton("Export CSV", () => exportQueries("csv", "signal", { signal_id: signal.signal_id })),
      actionButton("Export JSONL", () => exportQueries("jsonl", "signal", { signal_id: signal.signal_id })),
    );
    item.append(actions);
    list.append(item);
  }
}

function actionButton(label, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function formatInterval(interval) {
  const start = queryDateFormat.format(new Date(interval.start_epoch * 1000));
  const end = queryDateFormat.format(new Date((interval.end_epoch - 1) * 1000));
  return `${start} – ${end}`;
}

function renderTimeline(container, points, label) {
  const oldLabels = container.nextElementSibling;
  if (oldLabels?.classList.contains("timeline-labels")) oldLabels.remove();
  container.replaceChildren();
  const chart = document.createElement("div");
  chart.className = container.className;
  chart.removeAttribute("id");
  const maximum = Math.max(...points.map((point) => point.queries), 1);
  for (const point of points) {
    const column = document.createElement("div");
    column.className = "timeline-column";
    column.title = `${point.label}: ${numberFormat.format(point.queries)} queries`;
    const bar = document.createElement("div");
    bar.className = "timeline-bar";
    bar.style.height = `${Math.max(1, (point.queries / maximum) * 100)}%`;
    column.append(bar);
    chart.append(column);
  }
  container.setAttribute("aria-label", `${label} over time`);
  container.append(...chart.children);
  const labels = document.createElement("div");
  labels.className = "timeline-labels";
  const indices = [0, Math.floor((points.length - 1) / 2), points.length - 1];
  for (const index of indices) {
    const span = document.createElement("span");
    span.textContent = points[index]?.label || "";
    labels.append(span);
  }
  container.after(labels);
}

function renderServices(services) {
  const list = document.querySelector("#services-list");
  list.replaceChildren();
  for (const service of services.slice(0, 10)) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "service-row";
    const main = document.createElement("div");
    main.className = "service-main";
    const name = document.createElement("strong");
    name.textContent = service.service;
    const value = document.createElement("span");
    value.textContent = `${numberFormat.format(service.queries)} · ${service.share}%`;
    main.append(name, value);
    const track = document.createElement("div");
    track.className = "service-track";
    const fill = document.createElement("span");
    fill.style.width = `${Math.max(1, service.share)}%`;
    track.append(fill);
    row.append(main, track);
    row.addEventListener("click", () => showService(service, row));
    list.append(row);
  }
}

function showService(service, selectedRow) {
  currentService = service;
  document.querySelectorAll(".service-row").forEach((row) => row.classList.remove("active"));
  selectedRow.classList.add("active");
  document.querySelector("#detail-title").textContent = service.service;
  document.querySelector("#detail-category").textContent = `${service.company} · ${service.category}`;
  const infrastructureNote = document.querySelector("#infrastructure-note");
  infrastructureNote.hidden = !service.infrastructure_provider;
  if (service.infrastructure_provider) {
    infrastructureNote.textContent = service.confidence === "infrastructure/ambiguous"
      ? `${service.infrastructure_provider} is shared infrastructure; DNS alone may not identify the originating app.`
      : `Classified as ${service.service_name}; delivered through ${service.infrastructure_provider} infrastructure.`;
  }
  const metrics = document.querySelector("#detail-metrics");
  metrics.replaceChildren();
  for (const value of [
    `${numberFormat.format(service.queries)} queries`,
    `${numberFormat.format(service.unique_domains)} unique domains`,
    `${service.share}% of total`,
    `${numberFormat.format(service.blocked)} blocked`,
    `${service.confidence} confidence`,
  ]) {
    const item = document.createElement("span");
    item.textContent = value;
    metrics.append(item);
  }
  renderTimeline(document.querySelector("#service-chart"), service.timeline, `${service.service} queries`);
  const comparison = document.querySelector("#device-comparison");
  const comparisonList = document.querySelector("#device-comparison-list");
  comparisonList.replaceChildren();
  comparison.hidden = currentReport.scope.device_count < 2;
  if (!comparison.hidden) {
    for (const device of [...service.device_breakdown].sort((a, b) => b.queries - a.queries)) {
      const row = document.createElement("div");
      row.className = "comparison-row";
      const name = document.createElement("strong");
      name.textContent = device.display_name;
      const count = document.createElement("span");
      count.textContent = `${numberFormat.format(device.queries)} queries`;
      row.append(name, count);
      comparisonList.append(row);
    }
  }
  const domains = document.querySelector("#domain-list");
  document.querySelector("#domain-list-title").textContent = service.domains_truncated
    ? `Top ${service.domains.length} of ${numberFormat.format(service.unique_domains)} domains`
    : `All ${numberFormat.format(service.unique_domains)} domains`;
  domains.replaceChildren();
  for (const domain of service.domains) {
    const row = document.createElement("div");
    row.className = "domain-row";
    const name = document.createElement("code");
    name.textContent = domain.domain;
    const count = document.createElement("span");
    count.textContent = numberFormat.format(domain.queries);
    row.append(name, count);
    domains.append(row);
  }
  elements.detail.hidden = false;
  elements.detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function openQueryLog(scope, selector, title) {
  queryState = { scope, selector, title, offset: 0 };
  document.querySelector("#query-title").textContent = title;
  const deviceSelect = document.querySelector("#query-device-filter");
  deviceSelect.replaceChildren(new Option("All devices", ""));
  for (const device of currentReport.scope.devices) {
    deviceSelect.append(new Option(device.display_name, device.id));
  }
  document.querySelector("#query-domain-filter").value = "";
  document.querySelector("#query-sort").value = "desc";
  elements.queryRows.replaceChildren();
  elements.queryPanel.hidden = false;
  await loadQueryPage(true);
  elements.queryPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function loadQueryPage(reset = false) {
  if (!queryState || elements.loadMore.disabled) return;
  if (reset) {
    queryState.offset = 0;
    elements.queryRows.replaceChildren();
  }
  elements.loadMore.disabled = true;
  elements.queryCount.textContent = "Loading DNS evidence…";
  try {
    const payload = await requestJson("/api/queries", {
      method: "POST",
      body: JSON.stringify({
        snapshot_token: currentReport.snapshot_token,
        scope: queryState.scope,
        selector: queryState.selector,
        offset: queryState.offset,
        limit: 50,
        sort: document.querySelector("#query-sort").value,
        domain_filter: document.querySelector("#query-domain-filter").value,
        device_id: document.querySelector("#query-device-filter").value,
      }),
    });
    renderQueryRows(payload.rows);
    queryState.offset += payload.rows.length;
    elements.queryCount.textContent = `${numberFormat.format(payload.total)} matching DNS queries · showing ${numberFormat.format(queryState.offset)}`;
    elements.queryEmpty.hidden = payload.total !== 0;
    elements.loadMore.hidden = !payload.has_more;
  } catch (error) {
    showError(error.message);
    elements.queryCount.textContent = "Unable to load query evidence.";
  } finally {
    elements.loadMore.disabled = false;
  }
}

function renderQueryRows(rows) {
  for (const event of rows) {
    const row = document.createElement("tr");
    const time = document.createElement("td");
    time.dataset.label = "Time";
    time.textContent = queryDateFormat.format(new Date(event.timestamp_epoch * 1000));
    const device = document.createElement("td");
    device.dataset.label = "Device";
    device.textContent = event.device_name;
    device.title = `${event.client_key} · ${event.device_identity_confidence} identity confidence`;
    const domain = document.createElement("td");
    domain.dataset.label = "Domain";
    const domainCode = document.createElement("code");
    domainCode.textContent = event.domain;
    domain.append(domainCode);
    const service = document.createElement("td");
    service.dataset.label = "Service / infrastructure";
    service.textContent = event.infrastructure_provider
      ? `${event.service_name} · ${event.infrastructure_provider}`
      : event.service_name;
    const status = document.createElement("td");
    status.dataset.label = "Status";
    const badge = document.createElement("span");
    badge.className = `status-badge ${event.blocked ? "blocked" : "allowed"}`;
    badge.textContent = event.blocked ? `Blocked (${event.status_raw})` : `Allowed (${event.status_raw})`;
    status.append(badge);
    row.append(time, device, domain, service, status);
    elements.queryRows.append(row);
  }
}

async function exportQueries(
  format, scope = queryState?.scope, selector = queryState?.selector, useFilters = false,
) {
  if (!currentReport || !scope || !selector || exportInProgress) return;
  exportInProgress = true;
  hideError();
  try {
    const response = await fetch("/api/exports/queries", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        snapshot_token: currentReport.snapshot_token,
        format, scope, selector,
        domain_filter: useFilters ? document.querySelector("#query-domain-filter").value : "",
        device_id: useFilters ? document.querySelector("#query-device-filter").value : "",
      }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Export failed (${response.status})`);
    }
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const filename = disposition.match(/filename="([^"]+)"/)?.[1] || `homeshield-queries.${format}`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    showError(error.message);
  } finally {
    exportInProgress = false;
  }
}

function showError(message) {
  elements.error.textContent = message;
  elements.error.hidden = false;
}

function hideError() { elements.error.hidden = true; }

function safeFilename(extension) {
  const name = currentReport.scope.display_name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "report";
  const date = currentReport.report_date || currentReport.generated_at.slice(0, 10);
  return `dns-report-${name}-${date}.${extension}`;
}

function downloadBlob(content, type, extension) {
  if (!currentReport) return;
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = safeFilename(extension);
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function downloadCsv() {
  if (!currentReport) return;
  const rows = [[
    "service", "company", "category", "confidence", "queries",
    "blocked", "share_percent", "domain", "domain_queries",
  ]];
  for (const service of currentReport.services) {
    const domains = service.domains.length ? service.domains : [{ domain: "", queries: "" }];
    for (const domain of domains) {
      rows.push([
        service.service, service.company, service.category, service.confidence,
        service.queries, service.blocked, service.share, domain.domain, domain.queries,
      ]);
    }
  }
  downloadBlob(rows.map((row) => row.map(csvCell).join(",")).join("\r\n"), "text/csv;charset=utf-8", "csv");
}

function renderDeviceOptions(devices) {
  elements.deviceList.replaceChildren();
  devices.forEach((device, index) => {
    const label = document.createElement("label");
    label.className = "device-option";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = device.id;
    input.checked = index === 0;
    input.addEventListener("change", updateControls);
    const name = document.createElement("span");
    name.textContent = device.vendor
      ? `${device.display_name} · ${device.vendor}`
      : device.display_name;
    label.append(input, name);
    elements.deviceList.append(label);
  });
}

function renderGroupOptions(groups) {
  availableGroups = groups;
  elements.groupSelect.replaceChildren();
  for (const group of groups) {
    const option = document.createElement("option");
    option.value = group.id;
    option.textContent = `${group.display_name} (${group.device_count})`;
    option.disabled = group.device_count === 0;
    elements.groupSelect.append(option);
  }
  const firstUsable = groups.find((group) => group.device_count > 0);
  if (firstUsable) elements.groupSelect.value = firstUsable.id;
  elements.groupSelect.disabled = !firstUsable;
}

function updateControls() {
  const mode = document.querySelector('input[name="scope"]:checked').value;
  const periodMode = document.querySelector('input[name="period-mode"]:checked').value;
  const group = availableGroups.find((item) => item.id === elements.groupSelect.value);
  const selectedDevices = document.querySelectorAll('.device-option input:checked').length;
  const validPeriod = periodMode === "rolling" || Boolean(elements.reportDate.value);
  elements.devicesControl.hidden = mode !== "devices";
  elements.groupControl.hidden = mode !== "group";
  elements.rollingControl.hidden = periodMode !== "rolling";
  elements.dateControl.hidden = periodMode !== "calendar";
  elements.groupHint.textContent = group
    ? `${group.device_count} recent device${group.device_count === 1 ? "" : "s"} matched`
    : "No usable Pi-hole groups found";
  const validScope = mode === "devices" ? selectedDevices > 0 : Boolean(group);
  elements.generateButton.disabled = !validScope || !validPeriod;
}

elements.generateButton.addEventListener("click", generateReport);
document.querySelector("#close-detail").addEventListener("click", () => { elements.detail.hidden = true; });
document.querySelector("#close-query-panel").addEventListener("click", () => { elements.queryPanel.hidden = true; });
document.querySelector("#view-service-queries").addEventListener("click", () => {
  if (currentService) openQueryLog("service", { service_id: currentService.service_id }, currentService.service_name);
});
document.querySelector("#export-service-csv").addEventListener("click", () => {
  if (currentService) exportQueries("csv", "service", { service_id: currentService.service_id });
});
document.querySelector("#export-service-md").addEventListener("click", () => {
  if (currentService) exportQueries("md", "service", { service_id: currentService.service_id });
});
document.querySelector("#export-service-jsonl").addEventListener("click", () => {
  if (currentService) exportQueries("jsonl", "service", { service_id: currentService.service_id });
});
document.querySelector("#export-all-md").addEventListener("click", () => exportQueries("md", "all_signals", {}));
document.querySelector("#export-all-csv").addEventListener("click", () => exportQueries("csv", "all_signals", {}));
document.querySelector("#export-all-jsonl").addEventListener("click", () => exportQueries("jsonl", "all_signals", {}));
document.querySelector("#apply-query-filters").addEventListener("click", () => loadQueryPage(true));
elements.loadMore.addEventListener("click", () => loadQueryPage(false));
document.querySelector("#export-query-md").addEventListener("click", () => exportQueries("md", undefined, undefined, true));
document.querySelector("#export-query-csv").addEventListener("click", () => exportQueries("csv", undefined, undefined, true));
document.querySelector("#export-query-jsonl").addEventListener("click", () => exportQueries("jsonl", undefined, undefined, true));
document.querySelector("#download-json").addEventListener("click", () => {
  if (currentReport) downloadBlob(JSON.stringify(currentReport, null, 2), "application/json", "json");
});
document.querySelector("#download-llm").addEventListener("click", () => exportQueries("md", "report", {}));
document.querySelector("#download-csv").addEventListener("click", downloadCsv);
document.querySelector("#print-report").addEventListener("click", () => window.print());
document.querySelectorAll('input[name="scope"]').forEach((input) => input.addEventListener("change", updateControls));
document.querySelectorAll('input[name="period-mode"]').forEach((input) => input.addEventListener("change", updateControls));
elements.reportDate.addEventListener("change", updateControls);
elements.groupSelect.addEventListener("change", updateControls);
document.querySelector("#select-all").addEventListener("click", () => {
  document.querySelectorAll('.device-option input').forEach((input) => { input.checked = true; });
  updateControls();
});
document.querySelector("#clear-selection").addEventListener("click", () => {
  document.querySelectorAll('.device-option input').forEach((input) => { input.checked = false; });
  updateControls();
});
elements.reportDate.max = todayInRome();
elements.reportDate.value = elements.reportDate.max;
initialize();
