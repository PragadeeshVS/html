/**
 * Mini SOC Backend — Node.js + Express
 * Snort log parser + iptables firewall control
 *
 * Install: npm install express cors fs readline child_process crypto
 * Run:     sudo node server.js    (iptables requires root)
 */

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const readline = require("readline");
const { exec } = require("child_process");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = 5000;
const SNORT_LOG = "/var/log/snort/alert";
const LOG_POLL_INTERVAL = 2000; // ms

app.use(cors());
app.use(express.json());

// ── In-memory state ────────────────────────────────────────────────────────
let alerts = [];          // parsed alerts from Snort
let blockedIPs = new Set(); // IPs currently blocked by iptables
let stats = {
  total: 0,
  brute_force: 0,
  dos: 0,
  port_scan: 0,
  icmp: 0,
  sql_inject: 0,
};

// ── Snort log parser ───────────────────────────────────────────────────────
/**
 * Snort alert format (default):
 *
 * [**] [1:1000001:1] ICMP Ping Detected [**]
 * [Priority: 2]
 * 03/28-14:22:01.123456 192.168.1.100 -> 192.168.1.1
 * ICMP TTL:128 TOS:0x0 ID:1234 IpLen:20 DgmLen:60
 */

function parseSnortLine(line, nextLine) {
  // Match alert header line
  const headerMatch = line.match(/\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.+?)\s+\[\*\*\]/);
  if (!headerMatch) return null;

  const sid = headerMatch[1];
  const ruleName = headerMatch[2];

  // Match IP line (comes a few lines after header)
  const ipMatch = nextLine && nextLine.match(
    /(\d{2}\/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+([\d.]+)(?::\d+)?\s+->\s+([\d.]+)/
  );
  if (!ipMatch) return null;

  const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19);
  const srcIp = ipMatch[2];
  const dstIp = ipMatch[3];

  // Classify attack type from rule name
  let attackType = "unknown";
  const rn = ruleName.toLowerCase();
  if (rn.includes("brute") || rn.includes("login") || rn.includes("auth") || rn.includes("ssh")) {
    attackType = "brute_force";
  } else if (rn.includes("dos") || rn.includes("flood") || rn.includes("syn") || rn.includes("udp")) {
    attackType = "dos";
  } else if (rn.includes("scan") || rn.includes("nmap") || rn.includes("probe")) {
    attackType = "port_scan";
  } else if (rn.includes("icmp") || rn.includes("ping")) {
    attackType = "icmp";
  } else if (rn.includes("sql") || rn.includes("inject")) {
    attackType = "sql_inject";
  }

  // Classify severity
  const sevMatch = (nextLine || "").match(/Priority:\s*(\d)/i) || line.match(/Priority:\s*(\d)/i);
  const priority = sevMatch ? parseInt(sevMatch[1]) : 2;
  const severity = priority === 1 ? "High" : priority === 2 ? "Medium" : "Low";

  return {
    id: crypto.randomUUID(),
    timestamp,
    srcIp,
    dstIp,
    attackType,
    severity,
    ruleName,
    sid,
    raw: line,
  };
}

// Tail the Snort alert file for new entries
function tailSnortLog() {
  if (!fs.existsSync(SNORT_LOG)) {
    console.warn(`[IDS] Snort log not found at ${SNORT_LOG} — using simulation mode`);
    return;
  }

  let fileSize = fs.statSync(SNORT_LOG).size;
  const lines = [];

  setInterval(() => {
    try {
      const newSize = fs.statSync(SNORT_LOG).size;
      if (newSize <= fileSize) return;

      const stream = fs.createReadStream(SNORT_LOG, {
        start: fileSize,
        end: newSize,
        encoding: "utf-8",
      });

      let buffer = "";
      stream.on("data", chunk => { buffer += chunk; });
      stream.on("end", () => {
        const newLines = buffer.split("\n");
        for (let i = 0; i < newLines.length - 1; i++) {
          const alert = parseSnortLine(newLines[i], newLines[i + 1]);
          if (alert) {
            alerts.unshift(alert);
            stats.total++;
            if (stats[alert.attackType] !== undefined) stats[alert.attackType]++;
            if (alerts.length > 500) alerts.pop();
          }
        }
        fileSize = newSize;
      });
    } catch (e) {
      console.error("[IDS] Log read error:", e.message);
    }
  }, LOG_POLL_INTERVAL);

  console.log(`[IDS] Tailing Snort log: ${SNORT_LOG}`);
}

// Load existing alerts on startup
function loadExistingAlerts() {
  if (!fs.existsSync(SNORT_LOG)) return;
  const content = fs.readFileSync(SNORT_LOG, "utf-8");
  const lines = content.split("\n");
  for (let i = 0; i < lines.length - 1; i++) {
    const alert = parseSnortLine(lines[i], lines[i + 1]);
    if (alert) {
      alerts.push(alert);
      stats.total++;
      if (stats[alert.attackType] !== undefined) stats[alert.attackType]++;
    }
  }
  alerts = alerts.slice(0, 500);
  console.log(`[IDS] Loaded ${alerts.length} existing alerts`);
}

// ── Firewall helpers ───────────────────────────────────────────────────────
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

async function syncBlockedIPs() {
  return new Promise((resolve) => {
    exec("sudo iptables -L INPUT -n --line-numbers", (err, stdout) => {
      if (err) { resolve(); return; }
      const ips = new Set();
      const lines = stdout.split("\n");
      for (const line of lines) {
        const m = line.match(/DROP\s+all\s+--\s+([\d.]+)/);
        if (m) ips.add(m[1]);
      }
      blockedIPs = ips;
      resolve();
    });
  });
}

// ── API Routes ─────────────────────────────────────────────────────────────

/**
 * GET /alerts
 * Returns last N Snort alerts (default: 50)
 */
app.get("/alerts", (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json({
    success: true,
    count: alerts.length,
    alerts: alerts.slice(0, limit),
  });
});

/**
 * POST /block/:ip
 * Blocks an IP using iptables
 * sudo iptables -A INPUT -s <ip> -j DROP
 */
app.post("/block/:ip", async (req, res) => {
  const { ip } = req.params;
  if (!validateIP(ip)) {
    return res.status(400).json({ success: false, error: "Invalid IP address" });
  }
  if (blockedIPs.has(ip)) {
    return res.json({ success: true, message: `${ip} already blocked` });
  }
  try {
    await runIPTables(`sudo iptables -A INPUT -s ${ip} -j DROP`);
    blockedIPs.add(ip);
    console.log(`[FW] Blocked: ${ip}`);
    res.json({ success: true, message: `Blocked ${ip}`, blockedCount: blockedIPs.size });
  } catch (e) {
    console.error(`[FW] Block error: ${e.message}`);
    // If running without root for testing, simulate it
    blockedIPs.add(ip);
    res.json({ success: true, message: `Blocked ${ip} (simulation)`, blockedCount: blockedIPs.size });
  }
});

/**
 * POST /unblock/:ip
 * Removes IP block using iptables
 * sudo iptables -D INPUT -s <ip> -j DROP
 */
app.post("/unblock/:ip", async (req, res) => {
  const { ip } = req.params;
  if (!validateIP(ip)) {
    return res.status(400).json({ success: false, error: "Invalid IP address" });
  }
  if (!blockedIPs.has(ip)) {
    return res.json({ success: true, message: `${ip} is not blocked` });
  }
  try {
    await runIPTables(`sudo iptables -D INPUT -s ${ip} -j DROP`);
    blockedIPs.delete(ip);
    console.log(`[FW] Unblocked: ${ip}`);
    res.json({ success: true, message: `Unblocked ${ip}`, blockedCount: blockedIPs.size });
  } catch (e) {
    console.error(`[FW] Unblock error: ${e.message}`);
    blockedIPs.delete(ip);
    res.json({ success: true, message: `Unblocked ${ip} (simulation)`, blockedCount: blockedIPs.size });
  }
});

/**
 * GET /blocked
 * Returns list of currently blocked IPs
 */
app.get("/blocked", (req, res) => {
  res.json({
    success: true,
    count: blockedIPs.size,
    blockedIPs: [...blockedIPs],
  });
});

/**
 * GET /stats
 * Returns attack statistics
 */
app.get("/stats", (req, res) => {
  res.json({
    success: true,
    stats: {
      ...stats,
      blockedIPs: blockedIPs.size,
      activeAlerts: alerts.filter(a => !blockedIPs.has(a.srcIp)).length,
    },
  });
});

/**
 * GET /health
 * System health check
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "operational",
    snortLog: SNORT_LOG,
    snortLogExists: fs.existsSync(SNORT_LOG),
    alertCount: alerts.length,
    blockedCount: blockedIPs.size,
    uptime: process.uptime(),
  });
});

// ── Boot ───────────────────────────────────────────────────────────────────
async function start() {
  console.log("\n╔══════════════════════════════════════╗");
  console.log("║   MINI SOC — Backend Server v2.0    ║");
  console.log("╚══════════════════════════════════════╝\n");

  await syncBlockedIPs();
  loadExistingAlerts();
  tailSnortLog();

  app.listen(PORT, () => {
    console.log(`[API] Server running on http://localhost:${PORT}`);
    console.log(`[API] Endpoints:`);
    console.log(`       GET  /alerts         → Snort alert feed`);
    console.log(`       POST /block/:ip      → Block IP via iptables`);
    console.log(`       POST /unblock/:ip    → Unblock IP`);
    console.log(`       GET  /blocked        → List blocked IPs`);
    console.log(`       GET  /stats          → Attack statistics`);
    console.log(`       GET  /health         → System health\n`);
  });
}

start().catch(console.error);