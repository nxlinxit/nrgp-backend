const { Pool } = require('pg');
require('dotenv').config();

// Initialize PostgreSQL Connection Pool using your Neon Connection String
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Neon SSL connection
  }
});

pool.on('connect', () => {
  console.log('Connected to Neon PostgreSQL Database');
});

module.exports = {
  query: (text, params) => pool.query(text, params),
  getClient: () => pool.connect()
};