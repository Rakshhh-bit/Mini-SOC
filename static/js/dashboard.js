
const API_BASE = "";

let resourceChart = null;
let performanceChart = null;
let severityChart = null;

const chartColors = {
    cpu: "#3978d4",
    memory: "#8b65c7",
    disk: "#299b76"
};

async function fetchAPI(endpoint, options = {}) {
    const response = await fetch(API_BASE + endpoint, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {})
        }
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.message || "API request failed");
    }

    return data;
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    })[character]);
}

function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? escapeHTML(value)
        : date.toLocaleString();
}

function parseTelemetry(record) {
    try {
        return typeof record.data === "string"
            ? JSON.parse(record.data)
            : record.data || {};
    } catch {
        return {};
    }
}

function getSystemMetrics(record) {
    const data = parseTelemetry(record);
    const system = data.system || {};
    const cpu = data.cpu || {};
    const memory = data.memory || {};
    const disk = data.disk || {};

    return {
        hostname: system.hostname || record.hostname || "Unknown",
        os: [system.system || system.os || "", system.release || ""]
            .filter(Boolean).join(" ") || "Unknown",
        cpu: Number(cpu.cpu_usage_percent ?? cpu.usage_percent),
        memory: Number(memory.memory_usage_percent ?? memory.usage_percent),
        disk: Number(disk.disk_usage_percent ?? disk.usage_percent),
        time: record.received_at
    };
}

function formatPercent(value) {
    return Number.isFinite(value) ? `${value.toFixed(1)}%` : "—";
}

function severityBadge(severity) {
    const value = String(severity || "LOW").toUpperCase();
    const allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    const safe = allowed.includes(value) ? value : "LOW";

    return `<span class="severity ${safe}">${safe}</span>`;
}

function updateEndpoints(records) {
    const table = document.getElementById("endpoint-table");
    const latest = new Map();

    records.forEach(record => {
        const metrics = getSystemMetrics(record);

        if (!latest.has(metrics.hostname)) {
            latest.set(metrics.hostname, { record, metrics });
        }
    });

    const endpoints = [...latest.values()];

    document.getElementById("endpoint-count").textContent =
        endpoints.length;

    if (!endpoints.length) {
        table.innerHTML =
            '<tr><td colspan="6" class="empty-state">No endpoint telemetry received.</td></tr>';
        return;
    }

    table.innerHTML = endpoints.map(({ record, metrics }) => `
        <tr>
            <td>${escapeHTML(metrics.hostname)}</td>
            <td>${escapeHTML(metrics.os)}</td>
            <td>${formatPercent(metrics.cpu)}</td>
            <td>${formatPercent(metrics.memory)}</td>
            <td>${formatPercent(metrics.disk)}</td>
            <td>${formatDate(record.received_at)}</td>
        </tr>
    `).join("");
}

function getLatestEndpoint(records) {
    if (!records.length) return null;
    return getSystemMetrics(records[0]);
}

function getChartHistory(records) {
    return [...records]
        .reverse()
        .map(record => ({
            metrics: getSystemMetrics(record),
            label: new Date(record.received_at).toLocaleTimeString()
        }))
        .filter(item =>
            Number.isFinite(item.metrics.cpu) ||
            Number.isFinite(item.metrics.memory) ||
            Number.isFinite(item.metrics.disk)
        );
}

function createResourceChart(records) {
    const history = getChartHistory(records);

    const labels = history.map(item => item.label);

    const datasets = [
        {
            label: "CPU",
            data: history.map(item => Number.isFinite(item.metrics.cpu) ? item.metrics.cpu : null),
            borderColor: chartColors.cpu,
            backgroundColor: "rgba(57,120,212,0.08)",
            fill: true,
            tension: 0.35
        },
        {
            label: "Memory",
            data: history.map(item => Number.isFinite(item.metrics.memory) ? item.metrics.memory : null),
            borderColor: chartColors.memory,
            backgroundColor: "rgba(139,101,199,0.06)",
            fill: false,
            tension: 0.35
        },
        {
            label: "Disk",
            data: history.map(item => Number.isFinite(item.metrics.disk) ? item.metrics.disk : null),
            borderColor: chartColors.disk,
            backgroundColor: "rgba(41,155,118,0.06)",
            fill: false,
            tension: 0.35
        }
    ].map(dataset => ({
        ...dataset,
        borderWidth: 2,
        pointRadius: 2,
        pointHoverRadius: 5,
        spanGaps: true
    }));

    if (resourceChart) {
        resourceChart.data.labels = labels;
        resourceChart.data.datasets = datasets;
        resourceChart.update("none");
        return;
    }

    resourceChart = new Chart(
        document.getElementById("resource-chart"),
        {
            type: "line",
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { usePointStyle: true, boxWidth: 7, padding: 20 }
                    }
                },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: { callback: value => value + "%" },
                        grid: { color: "#edf0f4" }
                    },
                    x: { grid: { display: false } }
                }
            }
        }
    );
}

function createPerformanceChart(records) {
    const latest = getLatestEndpoint(records);

    const labels = ["CPU", "Memory", "Disk"];
    const values = latest
        ? [latest.cpu, latest.memory, latest.disk].map(value =>
            Number.isFinite(value) ? value : 0
        )
        : [0, 0, 0];

    if (performanceChart) {
        performanceChart.data.datasets[0].data = values;
        performanceChart.update("none");
        return;
    }

    performanceChart = new Chart(
        document.getElementById("performance-chart"),
        {
            type: "bar",
            data: {
                labels,
                datasets: [{
                    label: "Usage %",
                    data: values,
                    backgroundColor: [
                        chartColors.cpu,
                        chartColors.memory,
                        chartColors.disk
                    ],
                    borderRadius: 5,
                    maxBarThickness: 48
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        ticks: { callback: value => value + "%" },
                        grid: { color: "#edf0f4" }
                    },
                    x: { grid: { display: false } }
                }
            }
        }
    );
}

function createSeverityChart(alerts) {
    const levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

    const counts = levels.map(level =>
        alerts.filter(alert =>
            String(alert.severity || "").toUpperCase() === level
        ).length
    );

    if (severityChart) {
        severityChart.data.datasets[0].data = counts;
        severityChart.update("none");
        return;
    }

    severityChart = new Chart(
        document.getElementById("severity-chart"),
        {
            type: "doughnut",
            data: {
                labels: levels,
                datasets: [{
                    data: counts,
                    backgroundColor: ["#c94747", "#d77a42", "#d2a64d", "#3c986d"],
                    borderWidth: 0,
                    hoverOffset: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { usePointStyle: true, boxWidth: 7, padding: 15 }
                    }
                }
            }
        }
    );
}

function updateNetwork(alerts) {
    const networkAlerts = alerts.filter(alert =>
        String(alert.alert_id || "").startsWith("NET-")
    );

    const listeners = networkAlerts.filter(alert =>
        String(alert.alert_id || "").startsWith("NET-002")
    );

    const tools = networkAlerts.filter(alert =>
        String(alert.alert_id || "").startsWith("NET-001")
    );

    document.getElementById("network-alert-count").textContent =
        networkAlerts.length;

    document.getElementById("listening-alert-count").textContent =
        listeners.length;

    document.getElementById("tool-alert-count").textContent =
        tools.length;

    const table = document.getElementById("network-table");

    if (!networkAlerts.length) {
        table.innerHTML =
            '<tr><td colspan="5" class="empty-state">No network security alerts received.</td></tr>';
        return;
    }

    table.innerHTML = networkAlerts.map(alert => `
        <tr>
            <td>${escapeHTML(alert.hostname)}</td>
            <td><span class="mitre">${escapeHTML(alert.alert_id)}</span></td>
            <td title="${escapeHTML(alert.description)}">${escapeHTML(alert.title)}</td>
            <td>${severityBadge(alert.severity)}</td>
            <td>${formatDate(alert.detected_at || alert.received_at)}</td>
        </tr>
    `).join("");
}

function updateAlerts(alerts) {
    const table = document.getElementById("alert-table");

    document.getElementById("alert-count").textContent = alerts.length;

    if (!alerts.length) {
        table.innerHTML =
            '<tr><td colspan="8" class="empty-state">No security alerts recorded.</td></tr>';
        return;
    }

    table.innerHTML = alerts.map(alert => {
        const technique = alert.mitre_technique_id
            ? `${alert.mitre_technique_id} - ${alert.mitre_technique_name || ""}`
            : "Not mapped";

        return `
            <tr>
                <td>${escapeHTML(alert.hostname)}</td>
                <td><span class="mitre">${escapeHTML(alert.alert_id)}</span></td>
                <td title="${escapeHTML(alert.description)}">${escapeHTML(alert.title)}</td>
                <td>${severityBadge(alert.severity)}</td>
                <td>${escapeHTML(alert.mitre_tactic || "—")}</td>
                <td>${escapeHTML(technique)}</td>
                <td>${escapeHTML(alert.mitre_mapping_confidence || "—")}</td>
                <td>${formatDate(alert.detected_at || alert.received_at)}</td>
            </tr>
        `;
    }).join("");
}

function updateIncidents(records) {
    const container = document.getElementById("activity-list");

    document.getElementById("incident-count").textContent =
        records.length;

    if (!records.length) {
        container.innerHTML =
            '<div class="empty-state">No incidents available.</div>';
        return;
    }

    container.innerHTML = records.map(incident => {
        const id = escapeHTML(incident.incident_id);
        const status = String(incident.status || "OPEN").toUpperCase();

        return `
            <article class="incident-card">
                <div class="incident-top">
                    <div>
                        <div class="incident-title">${escapeHTML(incident.title)}</div>
                        <div class="incident-meta">
                            <span>Incident: ${id}</span>
                            <span>Endpoint: ${escapeHTML(incident.hostname)}</span>
                            <span>Rule: ${escapeHTML(incident.rule_id)}</span>
                            <span>Assigned: ${escapeHTML(incident.assigned_to || "SOC Analyst")}</span>
                        </div>
                    </div>
                    ${severityBadge(incident.severity)}
                </div>

                <p class="incident-description">${escapeHTML(incident.description)}</p>

                <div class="incident-meta">
                    <span>Created: ${formatDate(incident.created_at)}</span>
                    <span>Current status: ${escapeHTML(status)}</span>
                </div>

                <div class="incident-controls">
                    <select id="status-${id}" aria-label="Incident status">
                        ${["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"].map(option =>
                            `<option value="${option}" ${status === option ? "selected" : ""}>${option.replace("_", " ")}</option>`
                        ).join("")}
                    </select>
                    <button type="button" data-incident-id="${id}" class="save-status">
                        Save status
                    </button>
                </div>
            </article>
        `;
    }).join("");
}

async function saveIncidentStatus(incidentId, button) {
    const select = document.getElementById(`status-${incidentId}`);
    if (!select) return;

    button.disabled = true;
    button.textContent = "Saving...";

    try {
        await fetchAPI(
            `/dashboard/api/incidents/${encodeURIComponent(incidentId)}/status`,
            {
                method: "PATCH",
                body: JSON.stringify({ status: select.value })
            }
        );

        button.textContent = "Saved";
        await loadDashboard();

    } catch (error) {
        alert("Could not update incident: " + error.message);
        button.textContent = "Save status";

    } finally {
        button.disabled = false;
    }
}

document.getElementById("activity-list").addEventListener("click", event => {
    const button = event.target.closest(".save-status");

    if (button) {
        saveIncidentStatus(button.dataset.incidentId, button);
    }
});

async function loadDashboard() {
    const refreshButton = document.getElementById("refresh-button");
    refreshButton.disabled = true;

    try {
        const [telemetryData, alertData, incidentData] =
            await Promise.all([
                fetchAPI("/dashboard/api/telemetry"),
                fetchAPI("/dashboard/api/alerts"),
                fetchAPI("/dashboard/api/incidents")
            ]);

        const telemetry = telemetryData.telemetry || [];
        const alerts = alertData.alerts || [];
        const incidents = incidentData.incidents || [];

        document.getElementById("telemetry-count").textContent =
            telemetryData.count ?? telemetry.length;

        updateEndpoints(telemetry);
        createResourceChart(telemetry);
        createPerformanceChart(telemetry);
        createSeverityChart(alerts);
        updateNetwork(alerts);
        updateAlerts(alerts);
        updateIncidents(incidents);

        document.getElementById("last-updated").textContent =
            new Date().toLocaleTimeString();

    } catch (error) {
        console.error("Dashboard error:", error);

        document.getElementById("last-updated").textContent =
            "Connection error";

    } finally {
        refreshButton.disabled = false;
    }
}

loadDashboard();
setInterval(loadDashboard, 10000);
