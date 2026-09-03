const numberFormat = new Intl.NumberFormat();
const dateFormat = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

const elements = {
  sourceState: document.querySelector("#source-state"),
  deviceSelect: document.querySelector("#device-select"),
  generateButton: document.querySelector("#generate-button"),
  error: document.querySelector("#error-banner"),
  loading: document.querySelector("#loading"),
  report: document.querySelector("#report"),
  detail: document.querySelector("#detail-panel"),
};

let currentReport = null;

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

    const { devices } = await requestJson("/api/devices");
    elements.deviceSelect.replaceChildren();
    if (!devices.length) throw new Error("No devices found in the recent Pi-hole history.");
    for (const device of devices) {
      const option = document.createElement("option");
      option.value = device.id;
      const extra = device.vendor ? ` · ${device.vendor}` : "";
      option.textContent = `${device.display_name}${extra}`;
      elements.deviceSelect.append(option);
    }
    elements.deviceSelect.disabled = false;
    elements.generateButton.disabled = false;
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
    const hours = Number(document.querySelector('input[name="hours"]:checked').value);
    currentReport = await requestJson("/api/report", {
      method: "POST",
      body: JSON.stringify({ device_id: elements.deviceSelect.value, hours }),
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
  document.querySelector("#device-name").textContent = report.device.display_name;
  const meta = [report.device.address, report.device.vendor, report.device.device_type]
    .filter(Boolean)
    .join(" · ");
  document.querySelector("#device-meta").textContent = meta;
  document.querySelector("#generated-at").textContent = `Generated ${dateFormat.format(new Date(report.generated_at))}`;
  document.querySelector("#total-queries").textContent = numberFormat.format(report.overview.total_queries);
  document.querySelector("#blocked-percentage").textContent = `${report.overview.blocked_percentage}%`;
  document.querySelector("#blocked-queries").textContent = `${numberFormat.format(report.overview.blocked_queries)} queries`;
  document.querySelector("#unique-domains").textContent = numberFormat.format(report.overview.unique_domains);
  document.querySelector("#identified-services").textContent = numberFormat.format(report.overview.identified_services);
  document.querySelector("#summary").textContent = report.summary;
  document.querySelector("#caveat").textContent = report.caveat;
  document.querySelector("#timeline-range").textContent = `Last ${report.hours}h`;
  renderTimeline(document.querySelector("#activity-chart"), report.timeline, "DNS queries");
  renderServices(report.services);
  elements.report.scrollIntoView({ behavior: "smooth", block: "start" });
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

elements.generateButton.addEventListener("click", generateReport);
document.querySelector("#close-detail").addEventListener("click", () => { elements.detail.hidden = true; });
initialize();
