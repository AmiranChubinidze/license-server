const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cors = require("cors");
app.use(cors());


const app = express();
app.use(bodyParser.json());

// --- SQLite database ---
const db = new sqlite3.Database(path.join(__dirname, "licenses.db"), (err) => {
  if (err) console.error(err);
  else console.log("Connected to SQLite database.");
});

// --- Ensure licenses table exists ---
db.run(`
  CREATE TABLE IF NOT EXISTS licenses (
    key TEXT PRIMARY KEY,
    deviceId TEXT,
    notes TEXT DEFAULT ''
  )
`, (err) => {
  if (err) console.error(err);
  else console.log("Licenses table ready.");
});

// --- Add test keys (optional) ---
const testKeys = ["TEST123", "ABC456"];
testKeys.forEach(k => {
  const key = k.trim().toUpperCase(); // normalize
  db.run("INSERT OR IGNORE INTO licenses (key, deviceId, notes) VALUES (?, NULL, '')", [key]);
});

// --- Validate license ---
app.post("/validate", (req, res) => {
  let key = (req.body.key || "").trim().toUpperCase();
  const deviceId = (req.body.deviceId || "").trim();

  if (!key || !deviceId) return res.json({ valid: false, message: "Missing key or deviceId" });

  db.get("SELECT deviceId FROM licenses WHERE key = ?", [key], (err, row) => {
    if (err) return res.json({ valid: false, message: "Server error" });
    if (!row) return res.json({ valid: false, message: "Invalid key" });

    if (!row.deviceId) {
      db.run("UPDATE licenses SET deviceId = ? WHERE key = ?", [deviceId, key]);
      return res.json({ valid: true, message: "Key activated" });
    }

    if (row.deviceId === deviceId) return res.json({ valid: true, message: "Key already activated on this device" });

    return res.json({ valid: false, message: "Key already used on another device" });
  });
});

// --- Serve admin panel ---
app.use(express.static(__dirname));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));

// --- Admin endpoints ---
// List keys
app.get("/admin/list", (req, res) => {
  db.all("SELECT * FROM licenses ORDER BY key ASC", [], (err, rows) => {
    if (err) return res.json([]);
    res.json(rows);
  });
});

// Add key
app.post("/admin/add", (req, res) => {
  let key = (req.body.key || "").trim().toUpperCase();
  if (!key) return res.json({ success: false, message: "Missing key" });

  db.run(
    "INSERT OR IGNORE INTO licenses (key, deviceId, notes) VALUES (?, NULL, '')",
    [key],
    function (err) {
      if (err) return res.json({ success: false, message: "DB error" });
      if (this.changes === 0) return res.json({ success: false, message: "Key already exists" });
      res.json({ success: true, message: "Key added" });
    }
  );
});

// Revoke key
app.post("/admin/revoke", (req, res) => {
  let key = (req.body.key || "").trim().toUpperCase();
  if (!key) return res.json({ success: false, message: "Missing key" });

  db.run("DELETE FROM licenses WHERE key = ?", [key], function (err) {
    if (err) return res.json({ success: false, message: "DB error" });
    res.json({ success: true, message: "Key revoked" });
  });
});

// Update notes
app.post("/admin/note", (req, res) => {
  let key = (req.body.key || "").trim().toUpperCase();
  const note = req.body.note || "";
  if (!key) return res.json({ success: false, message: "Missing key" });

  db.run("UPDATE licenses SET notes = ? WHERE key = ?", [note, key], function (err) {
    if (err) return res.json({ success: false, message: "DB error" });
    res.json({ success: true, message: "Note updated" });
  });
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));
