const path = require("path");
const Database = require("better-sqlite3");

const DB_PATH = process.env.SQLITE_PATH || path.join(__dirname, "amnairi.db");

const db = new Database(DB_PATH, {
fileMustExist: false,
timeout: 5000,
});

function run(sql, params = []) {
const stmt = db.prepare(sql);
const info = stmt.run(...params);
return Promise.resolve(info);
}

function get(sql, params = []) {
const stmt = db.prepare(sql);
const row = stmt.get(...params);
return Promise.resolve(row);
}

function all(sql, params = []) {
const stmt = db.prepare(sql);
const rows = stmt.all(...params);
return Promise.resolve(rows);
}

module.exports = { db, run, get, all, DB_PATH };