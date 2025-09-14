const { DataTypes } = require("sequelize");
const sequelize = require("./db");

const License = sequelize.define("License", {
  key: { type: DataTypes.STRING, primaryKey: true },
  deviceId: { type: DataTypes.STRING, allowNull: true },
  notes: { type: DataTypes.STRING, defaultValue: "" },
});

sequelize.sync(); // creates table if not exists
module.exports = License;
