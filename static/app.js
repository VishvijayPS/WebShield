let latestResult = null;
let activeTab = "dns";
const $ = (id) => document.getElementById(id);
const chartCtx = $("severityChart");
const chart = new Chart(chartCtx, {
  type: "doughnut",
  data: {
    labels: ["High", "Medium", "Low", "Info"],
    datasets: [
      {
        data: [0, 0, 0, 0],
        backgroundColor: ["#ff6f7d", "#ffbf69", "#6b8cff", "#39d8d0"],
        borderColor: "#101725",
        borderWidth: 4,
        hoverOffset: 5,
      },
    ],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor: "#080c14", padding: 10 },
    },
    cutout: "70%",
  },
});

function showStatus(text, type = "") {
  const el = $("status");
  el.textContent = text;
  el.className = "status " + type;
}
function pretty(value) {
  return JSON.stringify(value, null, 2);
}
function renderTab(tab) {
  activeTab = tab;
  document
    .querySelectorAll(".tab")
    .forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  if (!latestResult) {
    $("technicalData").textContent = "No scan data yet.";
    return;
  }
  const map = {
    dns: latestResult.dns,
    http: latestResult.http.headers,
    tls: latestResult.tls,
    ports: latestResult.port_scan,
  };
  $("technicalData").textContent = pretty(map[tab] ?? {});
}
document
  .querySelectorAll(".tab")
  .forEach((b) => b.addEventListener("click", () => renderTab(b.dataset.tab)));

function renderFindings(items) {
  const root = $("findingsList");
  root.replaceChildren();
  if (!items || !items.length) {
    root.className = "empty-state";
    root.textContent = "No findings were returned.";
    return;
  }
  root.className = "";
  items.forEach((f) => {
    const card = document.createElement("article");
    card.className = "finding";
    const top = document.createElement("div");
    top.className = "finding-top";
    const title = document.createElement("h3");
    title.textContent = f.title;
    const sev = document.createElement("span");
    sev.className = "severity " + f.severity;
    sev.textContent = f.severity;
    top.append(title, sev);
    const evidence = document.createElement("p");
    evidence.textContent = "Evidence: " + (f.evidence || "Not provided");
    const rec = document.createElement("p");
    rec.textContent =
      "Recommendation: " + (f.recommendation || "Review manually.");
    card.append(top, evidence, rec);
    root.append(card);
  });
}
function updateMetrics(d) {
  $("ipMetric").textContent = d.ip_addresses.length;
  $("httpMetric").textContent = d.http.status_code;
  $("httpSub").textContent = d.http.https ? "HTTPS response" : "HTTP response";
  $("findingMetric").textContent = d.findings.length;
  $("portMetric").textContent =
    d.port_scan.status === "Completed" ? d.port_scan.ports.length : "—";
  $("targetTag").textContent = d.target.toUpperCase();
  const c = d.severity_counts || {};
  chart.data.datasets[0].data = [
    c.High || 0,
    c.Medium || 0,
    c.Low || 0,
    c.Info || 0,
  ];
  chart.update();
  $("reportActions").hidden = false;
  $("jsonLink").href = "/api/report/" + d.scan_id + ".json";
  $("pdfLink").href = "/api/report/" + d.scan_id + ".pdf";
}
function addHistoryRow(item) {
  const tr = document.createElement("tr");
  ["#" + item.id, item.target, item.created_at].forEach((value) => {
    const td = document.createElement("td");
    td.textContent = value;
    tr.append(td);
  });
  const td = document.createElement("td");
  const pdf = document.createElement("a");
  pdf.href = "/api/report/" + item.id + ".pdf";
  pdf.textContent = "PDF";
  const json = document.createElement("a");
  json.href = "/api/report/" + item.id + ".json";
  json.textContent = "JSON";
  td.append(pdf, document.createTextNode(" · "), json);
  tr.append(td);
  return tr;
}
async function refreshHistory() {
  try {
    const response = await fetch("/api/history");
    const rows = await response.json();
    const tbody = $("historyRows");
    tbody.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4;
      td.className = "empty-table";
      td.textContent = "No scans saved yet.";
      tr.append(td);
      tbody.append(tr);
      return;
    }
    rows.forEach((r) => tbody.append(addHistoryRow(r)));
  } catch (e) {
    showStatus("Could not refresh scan history.");
  }
}
$("refreshHistory").addEventListener("click", refreshHistory);
$("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = $("target").value.trim();
  if (!target) return;
  $("scanButton").disabled = true;
  showStatus(
    "Collecting DNS, HTTP and TLS information. This may take a few seconds…",
  );
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, port_scan: $("portScan").checked }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    latestResult = data;
    updateMetrics(data);
    renderFindings(data.findings);
    renderTab(activeTab);
    await refreshHistory();
    showStatus(
      "Scan completed and saved. Report downloads are ready below Technical Intelligence.",
      "success",
    );
  } catch (e) {
    showStatus(
      e.message || "Scan failed. Check the domain and try again.",
      "error",
    );
  } finally {
    $("scanButton").disabled = false;
  }
});
