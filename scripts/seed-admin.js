// One-off helper to create (or update) the first ADMIN account.
// Usage:
//   ADMIN_EMAIL=admin@example.com ADMIN_NAME="Portal Admin" ADMIN_PASSWORD='choose-a-strong-password' node scripts/seed-admin.js
//
// Never commit real credentials; pass them as environment variables at run time.

require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db');

async function main() {
  const email = process.env.ADMIN_EMAIL;
  const name = process.env.ADMIN_NAME || 'Portal Admin';
  const password = process.env.ADMIN_PASSWORD;

  if (!email || !password) {
    console.error('ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required.');
    process.exit(1);
  }
  if (password.length < 8) {
    console.error('ADMIN_PASSWORD must be at least 8 characters.');
    process.exit(1);
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const result = await db.query(
    `INSERT INTO users (name, email, password_hash, role, active)
     VALUES ($1, $2, $3, 'ADMIN', TRUE)
     ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'ADMIN'
     RETURNING id, email, role`,
    [name, email, passwordHash]
  );

  console.log('Admin user ready:', result.rows[0]);
  process.exit(0);
}

main().catch((err) => {
  console.error('Failed to seed admin user:', err);
  process.exit(1);
});
