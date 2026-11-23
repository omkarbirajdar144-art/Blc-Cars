(() => {
  const form = document.getElementById("scanForm");
  const target = document.getElementById("target");
  const button = document.getElementById("scanBtn");
  const radar = document.getElementById("radar");
  const radarState = document.getElementById("radarState");
  const radarTarget = document.getElementById("radarTarget");
  const terminal = document.getElementById("terminal");
  const progressFill = document.getElementById("progressFill");
  const progressValue = document.getElementById("progressValue");
  const progressMessage = document.getElementById("progressMessage");
  const progressTitle = document.getElementById("progressTitle");
  const terminalStatus = document.getElementById("terminalStatus");
  const historyList = document.getElementById("historyList");
  const pdfButton = document.getElementById("pdfButton");
  let lastEventCount = 0;

  function log(message, type = "event") {
    const line = document.createElement("div");
    line.className = "term-line " + type;
    line.textContent = message;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
  }
  function progress(value, message) {
    const safe = Math.max(0, Math.min(100, Number(value) || 0));
    progressFill.style.width = safe + "%";
    progressValue.textContent = safe + "%";
    progressCount.textContent = safe + " / 100";
    if (message) progressMessage.textContent = message;
  }
  const progressCount = document.getElementById("progressCount");

  async function loadHistory() {
    try {
      const response = await fetch("/api/history");
      const items = await response.json();
      historyList.replaceChildren();
      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "history-empty";
        empty.textContent = "No saved scans yet. Your completed scans will appear here.";
        historyList.appendChild(empty);
        return;
      }
      items.forEach(item => {
        const row = document.createElement("div");
        row.className = "history-item";
        const targetCell = document.createElement("span");
        targetCell.className = "history-target";
        targetCell.textContent = item.target;
        const date = document.createElement("span");
        date.className = "history-date";
        date.textContent = new Date(item.scanned_at).toLocaleString();
        const score = document.createElement("b");
        score.className = "history-score";
        score.textContent = item.score + "/100";
        const link = document.createElement("a");
        link.href = "/report/" + encodeURIComponent(item.id);
        link.textContent = "PDF ↗";
        row.append(targetCell, date, score, link);
        historyList.appendChild(row);
      });
    } catch (_) {
      historyList.textContent = "History is temporarily unavailable.";
    }
  }

  function showResult(result) {
    document.getElementById("emptyResult").hidden = true;
    document.getElementById("resultContent").hidden = false;
    document.getElementById("resultHost").textContent = result.hostname || "Not available";
    document.getElementById("resultTarget").textContent = result.target || "";
    document.getElementById("resultIp").textContent = result.ip || "N/A";
    document.getElementById("resultTime").textContent = result.response_time === "N/A" ? "N/A" : result.response_time + " ms";
    document.getElementById("httpTag").textContent = "HTTP " + (result.http_status ?? "N/A");
    document.getElementById("httpsTag").textContent = "HTTPS " + (result.https ? "ENABLED" : "NOT DETECTED");
    document.getElementById("statusTag").textContent = result.status || "Unknown";
    document.getElementById("scoreMessage").textContent = result.security_status || "No assessment";
    const score = Math.max(0, Math.min(100, Number(result.score) || 0));
    const ring = document.getElementById("gaugeRing");
    ring.style.background = "conic-gradient(var(--cyan) " + score + "%, #1c2d43 0)";
    const number = document.getElementById("scoreNumber");
    number.textContent = "0";
    const start = performance.now();
    const animate = now => {
      const pct = Math.min(1, (now - start) / 850);
      number.textContent = String(Math.round(score * pct));
      if (pct < 1) requestAnimationFrame(animate);
    };
    requestAnimationFrame(animate);

    const headers = document.getElementById("headerChecks");
    headers.replaceChildren();
    Object.entries(result.security_headers || {}).forEach(([name, present]) => {
      const row = document.createElement("div");
      row.className = "check-row";
      const mark = document.createElement("span");
      mark.className = "check-mark" + (present ? "" : " missing");
      mark.textContent = present ? "✓" : "!";
      const label = document.createElement("span");
      label.className = "check-name";
      const strong = document.createElement("b");
      strong.textContent = name;
      const small = document.createElement("small");
      small.textContent = present ? "Header detected in HTTP response" : "Header not detected in HTTP response";
      label.append(strong, small);
      const state = document.createElement("span");
      state.className = "check-state" + (present ? "" : " missing");
      state.textContent = present ? "PRESENT" : "MISSING";
      row.append(mark, label, state);
      headers.appendChild(row);
    });
    const ports = document.getElementById("portChecks");
    ports.replaceChildren();
    (result.ports || []).forEach(item => {
      const row = document.createElement("div");
      row.className = "port-row";
      const dot = document.createElement("i");
      dot.className = "port-dot" + (item.includes("OPEN") ? " open" : "");
      const label = document.createElement("span");
      label.textContent = item;
      const state = document.createElement("b");
      state.textContent = item.includes("OPEN") ? "OPEN" : item.includes("CLOSED") ? "CLOSED" : "INFO";
      row.append(dot, label, state);
      ports.appendChild(row);
    });
    pdfButton.href = "/report/" + encodeURIComponent(result.scan_id);
    pdfButton.classList.remove("disabled");
    pdfButton.setAttribute("aria-disabled", "false");
    document.getElementById("results").scrollIntoView({behavior: "smooth", block: "start"});
  }

  async function poll(jobId) {
    while (true) {
      const response = await fetch("/api/scan/" + encodeURIComponent(jobId));
      const job = await response.json();
      if (!response.ok) throw new Error(job.error || "Could not read scan status");
      progress(job.progress, job.events?.[job.events.length - 1] || "Working...");
      const events = job.events || [];
      while (lastEventCount < events.length) {
        log(events[lastEventCount]);
        lastEventCount += 1;
      }
      if (job.status === "complete") return job.result;
      if (job.status === "error") throw new Error(job.error || "Scan failed");
      await new Promise(resolve => setTimeout(resolve, 450));
    }
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const value = target.value.trim();
    if (!value) return;
    button.disabled = true;
    button.textContent = "SCANNING…";
    lastEventCount = 0;
    terminal.replaceChildren();
    log("CyberGuard 3.0 initialized", "muted");
    log("Target: " + value, "muted");
    radar.classList.add("scanning");
    radarState.textContent = "SCANNING";
    radarTarget.textContent = value;
    terminalStatus.textContent = "RUNNING";
    progressTitle.textContent = "Assessment in progress";
    progress(2, "Preparing scanner");
    pdfButton.classList.add("disabled");
    pdfButton.href = "#";
    pdfButton.setAttribute("aria-disabled", "true");
    try {
      const startResponse = await fetch("/api/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({target: value})
      });
      const startData = await startResponse.json();
      if (!startResponse.ok) throw new Error(startData.error || "Could not start scan");
      const result = await poll(startData.job_id);
      showResult(result);
      log("Assessment complete. Report stored.", "event");
      progressTitle.textContent = "Assessment complete";
      progress(100, "All available checks completed");
      terminalStatus.textContent = "COMPLETE";
      radarState.textContent = "COMPLETE";
      await loadHistory();
    } catch (error) {
      log(error.message, "error");
      progressTitle.textContent = "Assessment stopped";
      progress(100, error.message);
      terminalStatus.textContent = "ERROR";
      radarState.textContent = "ERROR";
    } finally {
      radar.classList.remove("scanning");
      button.disabled = false;
      button.innerHTML = 'INITIATE SCAN <span>↗</span>';
    }
  });


  const urlCheckForm = document.getElementById("urlCheckForm");
  urlCheckForm.addEventListener("submit", async event => {
    event.preventDefault();
    const url = document.getElementById("urlToCheck").value.trim();
    const checkButton = document.getElementById("urlCheckBtn");
    const output = document.getElementById("urlCheckResult");
    checkButton.disabled = true;
    checkButton.textContent = "CHECKING…";
    output.hidden = false;
    output.replaceChildren();
    const loading = document.createElement("p");
    loading.textContent = "Analyzing URL structure…";
    output.appendChild(loading);
    try {
      const response = await fetch("/api/url-check", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({url})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "URL check failed");
      const heading = document.createElement("div");
      heading.className = "url-verdict";
      const score = document.createElement("b");
      score.textContent = data.risk_score + "/100";
      const verdict = document.createElement("strong");
      verdict.textContent = data.verdict;
      heading.append(score, verdict);
      const host = document.createElement("p");
      host.textContent = "Hostname: " + data.hostname;
      const list = document.createElement("div");
      list.className = "url-check-list";
      data.checks.forEach(item => {
        const row = document.createElement("div");
        row.className = "url-check-row";
        const name = document.createElement("b");
        name.textContent = item.name;
        const state = document.createElement("span");
        state.textContent = item.status;
        state.className = "url-state " + item.status.toLowerCase();
        const detail = document.createElement("small");
        detail.textContent = item.detail;
        row.append(name, state, detail);
        list.appendChild(row);
      });
      const note = document.createElement("p");
      note.className = "url-disclaimer";
      note.textContent = data.disclaimer;
      output.replaceChildren(heading, host, list, note);
    } catch (error) {
      output.textContent = error.message;
    } finally {
      checkButton.disabled = false;
      checkButton.innerHTML = 'CHECK LINK <span>↗</span>';
    }
  });

  document.getElementById("refreshHistory").addEventListener("click", loadHistory);
  loadHistory();
})();
