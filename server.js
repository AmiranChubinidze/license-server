const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const cors = require("cors");
const basicAuth = require("express-basic-auth");

const sequelize = require("./db");
const License = require("./models/license");

const app = express();

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

// --- Admin authentication ---
// Only protect /admin routes
app.use("/admin", basicAuth({
  users: { 'admin': process.env.ADMIN_PASSWORD || "yourStrongPassword" },
  challenge: true
}));

// --- Initialize database ---
(async () => {
  try {
    await sequelize.authenticate();
    console.log("✅ Database connected");

    await License.sync(); // creates table if missing
    console.log("✅ Licenses table ready");

    // Optional: add test keys if table is empty
    /* const count = await License.count();
    if (count === 0) {
      await License.bulkCreate([
        { key: "TEST123" },
        { key: "ABC456" },
      ]);
      console.log("✅ Test keys added");
    } */
  } catch (err) {
    console.error("❌ DB connection failed:", err);
  }
})();

// --- License validation endpoint (open for extension) ---
app.post("/validate", async (req, res) => {
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
        message: "Key already activated on this device"
      });

    return res.json({
      valid: false,
      message: "Key already used on another device"
    });
  } catch (err) {
    console.error(err);
    return res.json({ valid: false, message: "Server error" });
  }
});

// --- Serve admin panel ---
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "admin.html")));

// --- Admin endpoints ---
// List keys
app.get("/admin/list", async (req, res) => {
  try {
    const licenses = await License.findAll({ order: [["key", "ASC"]] });
    res.json(licenses);
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "DB error" });
  }
});

// Add key
app.post("/admin/add", async (req, res) => {
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
app.post("/admin/revoke", async (req, res) => {
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
app.post("/admin/note", async (req, res) => {
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
