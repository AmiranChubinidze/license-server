const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const DB_PATH =
  process.env.SQLITE_PATH ||
  path.join(__dirname, "amnairi.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("SQLite connection failed:", err);
  } else {
    console.log("SQLite connected:", DB_PATH);
  }
});

const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

const all = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });

module.exports = { db, run, get, all, DB_PATH };
