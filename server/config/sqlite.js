// SQLite configuration for development/testing
const sqlite3 = require('sqlite3').verbose();
const { Database } = require('sqlite3');

const dbConfig = {
  development: {
    dialect: 'sqlite',
    storage: './cybertoolkit.db'
  },
  production: {
    dialect: 'sqlite',
    storage: './cybertoolkit.db'
  }
};

module.exports = dbConfig;
