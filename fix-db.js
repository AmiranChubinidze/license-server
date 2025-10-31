const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const db = new sqlite3.Database(path.join(__dirname, "licenses.db"));

db.serialize(() => {
  // Drop old table
  db.run("DROP TABLE IF EXISTS licenses", (err) => {
    if (err) console.error("Error dropping table:", err);
    else console.log("Old licenses table dropped.");
  });

  // Recreate table with notes column
  db.run(`
    CREATE TABLE IF NOT EXISTS licenses (
      key TEXT PRIMARY KEY,
      deviceId TEXT,
      notes TEXT DEFAULT ''
    )
  `, (err) => {
    if (err) console.error("Error creating table:", err);
    else console.log("Licenses table recreated successfully.");
  });

  // Add test keys
  const testKeys = ["TEST123", "ABC456"];
  const stmt = db.prepare("INSERT OR IGNORE INTO licenses (key, deviceId, notes) VALUES (?, NULL, '')");
  testKeys.forEach(k => stmt.run(k.trim().toUpperCase()));
  stmt.finalize(() => {
    console.log("Test keys added.");
    db.close();
  });
});
