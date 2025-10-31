const path = require("path");
const Database = require("better-sqlite3");

const DB_PATH = process.env.SQLITE_PATH || path.join(__dirname, "amnairi.db");

const db = (() => {
  try {
    return new Database(DB_PATH, { fileMustExist: false, timeout: 5000 });
  } catch (err) {
    console.error("Database initialization failed:", err.message);
    return null;
  }
})();

function ensureDb() {
  if (!db) {
    return Promise.reject(new Error("Database not initialized"));
  }
  return Promise.resolve(db);
}

function run(sql, params = []) {
  return ensureDb().then((instance) => {
    const stmt = instance.prepare(sql);
    const info = stmt.run(...params);
    return info;
  });
}

function get(sql, params = []) {
  return ensureDb().then((instance) => {
    const stmt = instance.prepare(sql);
    const row = stmt.get(...params);
    return row;
  });
}

function all(sql, params = []) {
  return ensureDb().then((instance) => {
    const stmt = instance.prepare(sql);
    const rows = stmt.all(...params);
    return rows;
  });
}

module.exports = { db, run, get, all, DB_PATH };
