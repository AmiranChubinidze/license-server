const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const cors = require("cors");

const sequelize = require("./db");
const License = require("./models/license");

const app = express();

// --- Secrets for protection ---
const EXTENSION_SECRET = process.env.EXTENSION_SECRET || "EXTENSION_SECRET_123";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "ADMIN_SECRET_456";

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// --- Middleware for extension-only endpoints ---
function verifyExtensionToken(req, res, next) {
  const token = req.headers["x-extension-token"];
  if (!token || token !== EXTENSION_SECRET) {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }
  next();
}

// --- Middleware for admin-only endpoints ---
function verifyAdminToken(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_SECRET) {
    return res.status(403).json({ success: false, message: "Admin Forbidden" });
  }
  next();
}

// --- Initialize database ---
(async () => {
  try {
    await sequelize.authenticate();
    console.log("✅ Database connected");

    await License.sync(); // creates table if missing
    console.log("✅ Licenses table ready");
  } catch (err) {
    console.error("❌ DB connection failed:", err);
  }
})();

// --- License validation endpoint (EXTENSION ONLY) ---
app.post("/validate", verifyExtensionToken, async (req, res) => {
  const key = (req.body.key || "").trim().toUpperCase();
  const deviceId = (req.body.deviceId || "").trim();

  if (!key || !deviceId)
    return res.json({ valid: false, message: "Missing key or deviceId" });

  try {
    let license = await License.findByPk(key);

    if (!license) return res.json({ valid: false, message: "Invalid key" });

    if (!license.deviceId) {
      license.deviceId = deviceId;
      await license.save();
      return res.json({ valid: true, message: "Key activated" });
    }

    if (license.deviceId === deviceId)
      return res.json({
        valid: true,
        message: "Key already activated on this device",
      });

    return res.json({
      valid: false,
      message: "Key already used on another device",
    });
  } catch (err) {
    console.error(err);
    return res.json({ valid: false, message: "Server error" });
  }
});

// --- Serve admin panel (ADMIN ONLY) ---
app.get("/", verifyAdminToken, (req, res) =>
  res.sendFile(path.join(__dirname, "admin.html"))
);

// --- Admin endpoints (ADMIN ONLY) ---

// List keys
app.get("/admin/list", verifyAdminToken, async (req, res) => {
  const licenses = await License.findAll({ order: [["key", "ASC"]] });
  res.json(licenses);
});

// Add key
app.post("/admin/add", verifyAdminToken, async (req, res) => {
  const key = (req.body.key || "").trim().toUpperCase();
  if (!key) return res.json({ success: false, message: "Missing key" });

  try {
    const [license, created] = await License.findOrCreate({ where: { key } });
    if (!created) return res.json({ success: false, message: "Key exists" });
    res.json({ success: true, message: "Key added" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// Revoke key
app.post("/admin/revoke", verifyAdminToken, async (req, res) => {
  const key = (req.body.key || "").trim().toUpperCase();
  if (!key) return res.json({ success: false, message: "Missing key" });

  try {
    const deleted = await License.destroy({ where: { key } });
    if (!deleted) return res.json({ success: false, message: "Key not found" });
    res.json({ success: true, message: "Key revoked" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// Update notes
app.post("/admin/note", verifyAdminToken, async (req, res) => {
  const key = (req.body.key || "").trim().toUpperCase();
  const note = req.body.note || "";
  if (!key) return res.json({ success: false, message: "Missing key" });

  try {
    const license = await License.findByPk(key);
    if (!license) return res.json({ success: false, message: "Key not found" });
    license.notes = note;
    await license.save();
    res.json({ success: true, message: "Note updated" });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Server running on port ${PORT}`)
);
