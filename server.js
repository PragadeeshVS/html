/**
 * Mini SOC Backend — Node.js + Express (FIXED VERSION)
 * Snort multi-line parser + real-time tail + firewall control
 */

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const { exec } = require("child_process");
const crypto = require("crypto");

const app = express();
const PORT = 5000;
const SNORT_LOG = "/var/log/snort/alert";
const LOG_POLL_INTERVAL = 2000;

app.use(cors());
app.use(express.json());

// ── In-memory state ─────────────────────────────────────
let alerts = [];
let blockedIPs = new Set();

let stats = {
  total: 0,
  brute_force: 0,
  dos: 0,
  port_scan: 0,
  icmp: 0,
  sql_inject: 0,
};

// ── MULTI-LINE SNORT PARSER (FIXED) ─────────────────────
function parseSnortBlock(block) {
  const header = block.match(/\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]/);
  if (!header) return null;

  const sid = header[1];
  const ruleName = header[2];

  const ipLine = block.match(
    /(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+([\d.]+)(?::\d+)?\s+->\s+([\d.]+)/
  );
  if (!ipLine) return null;

  const srcIp = ipLine[2];
  const dstIp = ipLine[3];

  const priorityMatch = block.match(/Priority:\s*(\d)/);
  const priority = priorityMatch ? parseInt(priorityMatch[1]) : 2;

  const severity =
    priority === 1 ? "High" :
    priority === 2 ? "Medium" : "Low";

  let attackType = "unknown";
  const rn = ruleName.toLowerCase();

  if (rn.includes("ssh") || rn.includes("login")) attackType = "brute_force";
  else if (rn.includes("flood") || rn.includes("dos") || rn.includes("syn")) attackType = "dos";
  else if (rn.includes("scan") || rn.includes("nmap")) attackType = "port_scan";
  else if (rn.includes("icmp") || rn.includes("ping")) attackType = "icmp";
  else if (rn.includes("sql")) attackType = "sql_inject";

  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    srcIp,
    dstIp,
    attackType,
    severity,
    ruleName,
    sid,
    raw: block,
  };
}

// ── LOAD EXISTING ALERTS ─────────────────────────────────
function loadExistingAlerts() {
  if (!fs.existsSync(SNORT_LOG)) return;

  const content = fs.readFileSync(SNORT_LOG, "utf-8");

  const blocks = content.split(/\[\*\*\]/).slice(1).map(b => "[**]" + b);

  for (const block of blocks) {
    const alert = parseSnortBlock(block);
    if (alert) {
      alerts.push(alert);
      stats.total++;
      if (stats[alert.attackType] !== undefined) {
        stats[alert.attackType]++;
      }
    }
  }

  console.log(`[IDS] Loaded ${alerts.length} alerts`);
}

// ── REAL-TIME LOG TAIL (FIXED) ───────────────────────────
function tailSnortLog() {
  if (!fs.existsSync(SNORT_LOG)) {
    console.warn(`[IDS] Log not found at ${SNORT_LOG}`);
    return;
  }

  let lastSize = fs.statSync(SNORT_LOG).size;

  setInterval(() => {
    const newSize = fs.statSync(SNORT_LOG).size;
    if (newSize <= lastSize) return;

    const stream = fs.createReadStream(SNORT_LOG, {
      start: lastSize,
      end: newSize,
      encoding: "utf-8",
    });

    let buffer = "";

    stream.on("data", chunk => buffer += chunk);

    stream.on("end", () => {
      const blocks = buffer.split(/\[\*\*\]/).slice(1).map(b => "[**]" + b);

      for (const block of blocks) {
        const alert = parseSnortBlock(block);
        if (alert) {
          alerts.unshift(alert);
          stats.total++;

          if (stats[alert.attackType] !== undefined) {
            stats[alert.attackType]++;
          }

          if (alerts.length > 500) alerts.pop();
        }
      }

      lastSize = newSize;
    });

  }, LOG_POLL_INTERVAL);

  console.log(`[IDS] Tailing Snort log: ${SNORT_LOG}`);
}

// ── FIREWALL HELPERS ─────────────────────────────────────
function validateIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every(n => parseInt(n) <= 255);
}

function runIPTables(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve(stdout);
    });
  });
}

// ── API ROUTES ───────────────────────────────────────────
app.get("/alerts", (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json({
    success: true,
    count: alerts.length,
    alerts: alerts.slice(0, limit),
  });
});

app.post("/block/:ip", async (req, res) => {
  const { ip } = req.params;

  if (!validateIP(ip)) {
    return res.status(400).json({ success: false, error: "Invalid IP" });
  }

  if (blockedIPs.has(ip)) {
    return res.json({ success: true, message: "Already blocked" });
  }

  try {
    await runIPTables(`sudo iptables -A INPUT -s ${ip} -j DROP`);
    blockedIPs.add(ip);
    res.json({ success: true, message: `Blocked ${ip}` });
  } catch {
    blockedIPs.add(ip);
    res.json({ success: true, message: `Blocked ${ip} (simulated)` });
  }
});

app.post("/unblock/:ip", async (req, res) => {
  const { ip } = req.params;

  if (!blockedIPs.has(ip)) {
    return res.json({ success: true, message: "Not blocked" });
  }

  try {
    await runIPTables(`sudo iptables -D INPUT -s ${ip} -j DROP`);
    blockedIPs.delete(ip);
    res.json({ success: true, message: `Unblocked ${ip}` });
  } catch {
    blockedIPs.delete(ip);
    res.json({ success: true, message: `Unblocked ${ip} (simulated)` });
  }
});

app.get("/blocked", (req, res) => {
  res.json({
    success: true,
    blockedIPs: [...blockedIPs],
  });
});

app.get("/stats", (req, res) => {
  res.json({
    success: true,
    stats: {
      ...stats,
      blockedIPs: blockedIPs.size,
    },
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "operational",
    logExists: fs.existsSync(SNORT_LOG),
    alertCount: alerts.length,
  });
});

// ── START SERVER ─────────────────────────────────────────
async function start() {
  console.log("🚀 MINI SOC Backend Started");

  loadExistingAlerts();
  tailSnortLog();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`API running at http://0.0.0.0:${PORT}`);
  });
}

start();
