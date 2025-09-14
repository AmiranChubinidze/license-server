const { Sequelize } = require("sequelize");
const path = require("path");

const isProduction = process.env.NODE_ENV === "production";

const sequelize = isProduction
  ? new Sequelize(process.env.DATABASE_URL, {
      dialect: "postgres",
      protocol: "postgres",
      logging: false,
      dialectOptions: { ssl: { require: true, rejectUnauthorized: false } },
    })
  : new Sequelize({
      dialect: "sqlite",
      storage: path.join(__dirname, "licenses.db"),
      logging: false,
    });

module.exports = sequelize;
