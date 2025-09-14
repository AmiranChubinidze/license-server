const { Sequelize } = require("sequelize");

const DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://licenses_db_htbf_user:gODMDR7UwEOR1C1phPMzwVTqjespYxKr@dpg-d334mgmmcj7s73a2iri0-a/licenses_db_htbf";

const sequelize = new Sequelize(DATABASE_URL, {
  dialect: "postgres",
  logging: false, // change to console.log for debugging
});

module.exports = sequelize;
