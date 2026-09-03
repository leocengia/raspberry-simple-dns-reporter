const numberFormat = new Intl.NumberFormat();
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const elements = {
  sourceState: document.querySelector("#source-state"),
  devicesControl: document.querySelector("#devices-control"),
  deviceList: document.querySelector("#device-list"),
  groupControl: document.querySelector("#group-control"),
  groupSelect: document.querySelector("#group-select"),
  groupHint: document.querySelector("#group-hint"),
  generateButton: document.querySelector("#generate-button"),
  error: document.querySelector("#error-banner"),
  loading: document.querySelector("#loading"),
  report: document.querySelector("#report"),
  detail: document.querySelector("#detail-panel"),
};

let currentReport = null;
let availableGroups = [];

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

async function initialize() {
  try {
    const health = await requestJson("/api/health");
    const healthy = health.status === "ok";
    elements.sourceState.classList.add(healthy ? "ok" : "degraded");
    elements.sourceState.lastChild.textContent = healthy ? " Sources ready" : " Source degraded";

    const { devices, groups } = await requestJson("/api/devices");
    if (!devices.length) throw new Error("No devices found in the recent Pi-hole history.");
    renderDeviceOptions(devices);
    renderGroupOptions(groups || []);
    updateControls();
  } catch (error) {
    showError(error.message);
    elements.sourceState.classList.add("degraded");
    elements.sourceState.lastChild.textContent = " Sources unavailable";
  }
}

async function generateReport() {
  hideError();
  elements.loading.hidden = false;
  elements.generateButton.disabled = true;
  elements.detail.hidden = true;
  try {
    const hours = Number(document.querySelector("#hours-select").value);
    const mode = document.querySelector('input[name="scope"]:checked').value;
    const request = { hours };
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
  } catch (error) {
    showError(error.message);
  } finally {
    elements.loading.hidden = true;
    elements.generateButton.disabled = false;
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
  document.querySelector("#timeline-range").textContent = report.hours === 168
    ? "Last 7 days"
    : `Last ${report.hours}h`;
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
    item.append(title, detail);
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
    list.append(item);
  }
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
  document.querySelectorAll(".service-row").forEach((row) => row.classList.remove("active"));
  selectedRow.classList.add("active");
  document.querySelector("#detail-title").textContent = service.service;
  document.querySelector("#detail-category").textContent = `${service.company} · ${service.category}`;
  const metrics = document.querySelector("#detail-metrics");
  metrics.replaceChildren();
  for (const value of [
    `${numberFormat.format(service.queries)} queries`,
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
  const date = currentReport.generated_at.slice(0, 10);
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
  const group = availableGroups.find((item) => item.id === elements.groupSelect.value);
  const selectedDevices = document.querySelectorAll('.device-option input:checked').length;
  elements.devicesControl.hidden = mode !== "devices";
  elements.groupControl.hidden = mode !== "group";
  elements.groupHint.textContent = group
    ? `${group.device_count} recent device${group.device_count === 1 ? "" : "s"} matched`
    : "No usable Pi-hole groups found";
  elements.generateButton.disabled = mode === "devices" ? selectedDevices === 0 : !group;
}

elements.generateButton.addEventListener("click", generateReport);
document.querySelector("#close-detail").addEventListener("click", () => { elements.detail.hidden = true; });
document.querySelector("#download-json").addEventListener("click", () => {
  if (currentReport) downloadBlob(JSON.stringify(currentReport, null, 2), "application/json", "json");
});
document.querySelector("#download-csv").addEventListener("click", downloadCsv);
document.querySelector("#print-report").addEventListener("click", () => window.print());
document.querySelectorAll('input[name="scope"]').forEach((input) => input.addEventListener("change", updateControls));
elements.groupSelect.addEventListener("change", updateControls);
document.querySelector("#select-all").addEventListener("click", () => {
  document.querySelectorAll('.device-option input').forEach((input) => { input.checked = true; });
  updateControls();
});
document.querySelector("#clear-selection").addEventListener("click", () => {
  document.querySelectorAll('.device-option input').forEach((input) => { input.checked = false; });
  updateControls();
});
initialize();
