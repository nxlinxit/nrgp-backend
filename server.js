const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Fail fast rather than silently signing tokens with a known, hardcoded secret.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}

const ROLES = ['ADMIN', 'NX', 'RECEIVER', 'SUPPLIER'];

// Middleware
app.use(helmet());
app.use(cors({
  // Restrict via CORS_ORIGIN (comma-separated) in production; defaults to
  // allowing any origin only when the env var isn't configured.
  origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',').map(o => o.trim()) : true
}));
app.use(express.json());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please try again later.' }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// ==========================================
// 1. AUTHENTICATION (SHARED LOGIN PAGE)
// ==========================================
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    // Find user in Users Master (Single login point)
    const result = await db.query(
      `SELECT u.id, u.email, u.password_hash, u.role, u.name, u.receiver_id, u.active, r.code as receiver_code, r.name as receiver_name, r.active as receiver_active
       FROM users u
       LEFT JOIN receivers r ON u.receiver_id = r.id
       WHERE LOWER(u.email) = LOWER($1)`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    if (user.active === false || user.receiver_active === false) {
      return res.status(403).json({ message: 'This account has been deactivated' });
    }

    const isBcryptHash = user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2a$');
    let validPassword = false;

    if (isBcryptHash) {
      validPassword = await bcrypt.compare(password, user.password_hash);
    } else {
      // Legacy plain-text password from initial seeding. Only ever matches
      // this specific account's own stored value (no universal bypass).
      validPassword = password === user.password_hash;
      if (validPassword) {
        // Migrate to a proper hash now that we've verified the password.
        const newHash = await bcrypt.hash(password, 10);
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
      }
    }

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token containing user context
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        receiverId: user.receiver_id
      },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name, // Used for Warehouse PIC auto-fill
        receiverId: user.receiver_id,
        receiverCode: user.receiver_code,
        receiverName: user.receiver_name
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ==========================================
// 2. FETCH DISPATCHES (BY ROLE & TAB)
// ==========================================
app.get('/api/dispatches', authenticateToken, async (req, res) => {
  const { role, receiverId } = req.user;
  const { status } = req.query;

  try {
    let query = `
      SELECT
        d.id,
        d.transaction_id,
        d.dispatch_date_time,
        d.dispatch_submitted_at,
        d.receiving_date_time,
        d.receipt_submitted_at,
        d.vehicle_no,
        d.driver_details,
        d.warehouse_pic,
        d.status,
        d.resolution_note,
        r.code as receiver_code,
        r.name as receiver_name
      FROM dispatches d
      JOIN receivers r ON d.receiver_id = r.id
    `;

    let params = [];
    let conditions = [];

    // Filter by role scope
    if (role === 'RECEIVER') {
      params.push(receiverId);
      conditions.push(`d.receiver_id = $${params.length}`);
    }

    // Filter by status if requested
    if (status) {
      params.push(status);
      conditions.push(`d.status = $${params.length}`);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY d.dispatch_submitted_at DESC';

    const result = await db.query(query, params);
    res.json(result.rows);

  } catch (error) {
    console.error('Fetch dispatches error:', error);
    res.status(500).json({ message: 'Failed to fetch dispatches' });
  }
});

// ==========================================
// 3. CREATE NEW DISPATCH (NX EMPLOYEE)
// ==========================================
app.post('/api/dispatches', authenticateToken, async (req, res) => {
  if (req.user.role !== 'NX' && req.user.role !== 'ADMIN') {
    return res.status(403).json({ message: 'Only NX employees can create dispatches' });
  }

  const { receiver_id, dispatch_date_time, vehicle_no, driver_details, lines } = req.body;

  if (!receiver_id) {
    return res.status(400).json({ message: 'receiver_id is required' });
  }
  if (!Array.isArray(lines) || lines.length === 0) {
    return res.status(400).json({ message: 'At least one packaging line is required' });
  }
  for (const line of lines) {
    if (!line.package_code) {
      return res.status(400).json({ message: 'Each line requires a package_code' });
    }
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const year = new Date().getFullYear();

    // Atomically claim the next sequence number for this year, avoiding the
    // race condition of a plain COUNT(*)-based approach under concurrency.
    const counterResult = await client.query(
      `INSERT INTO dispatch_counters (year, last_num)
       VALUES ($1, 1)
       ON CONFLICT (year) DO UPDATE SET last_num = dispatch_counters.last_num + 1
       RETURNING last_num`,
      [year]
    );
    const nextNum = String(counterResult.rows[0].last_num).padStart(4, '0');
    const transactionId = `NRGP-${year}-${nextNum}`;

    // Auto-fill Warehouse PIC from logged-in NX user's name
    const warehousePic = req.user.name || 'NX Dispatch Staff';

    const dispatchResult = await client.query(
      `INSERT INTO dispatches
       (transaction_id, receiver_id, dispatch_date_time, vehicle_no, driver_details, warehouse_pic, status, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
       RETURNING *`,
      [transactionId, receiver_id, dispatch_date_time || new Date(), vehicle_no, driver_details, warehousePic, req.user.id]
    );

    const newDispatch = dispatchResult.rows[0];

    for (const line of lines) {
      await client.query(
        `INSERT INTO dispatch_lines (dispatch_id, package_code, dispatched_qty)
         VALUES ($1, $2, $3)`,
        [newDispatch.id, line.package_code, line.dispatched_qty || 0]
      );
    }

    await client.query('COMMIT');

    res.status(201).json({
      message: 'Dispatch created successfully',
      dispatch: newDispatch
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Create dispatch error:', error);
    res.status(500).json({ message: 'Failed to create dispatch' });
  } finally {
    client.release();
  }
});

// ==========================================
// 4. RECEIVERS DIRECTORY (for dispatch creation dropdown)
// ==========================================
app.get('/api/receivers', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, code, name FROM receivers WHERE active = TRUE ORDER BY name ASC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch receivers error:', error);
    res.status(500).json({ message: 'Failed to fetch receivers' });
  }
});

// ==========================================
// 5. ADMIN SUPPLIER / RECEIVER MASTER
// ==========================================
// Each row is a receiver company (code, name, address) paired 1:1 with its
// own RECEIVER-role login account (email/password), since dispatches route
// by receiver_id but a receiver logs in as a user.
app.get('/api/admin/receivers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT r.id, r.code, r.name, r.address, r.active, r.created_at,
              u.id as user_id, u.email as login_email
       FROM receivers r
       LEFT JOIN users u ON u.receiver_id = r.id AND u.role = 'RECEIVER'
       ORDER BY r.created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch supplier accounts error:', error);
    res.status(500).json({ message: 'Failed to fetch supplier accounts' });
  }
});

app.post('/api/admin/receivers', authenticateToken, requireAdmin, async (req, res) => {
  const { code, name, address, email, password } = req.body;

  if (!code || !name || !email || !password) {
    return res.status(400).json({ message: 'code, name, email and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'password must be at least 8 characters' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const receiverResult = await client.query(
      `INSERT INTO receivers (code, name, address, email, active)
       VALUES ($1, $2, $3, $4, TRUE)
       RETURNING id, code, name, address, active, created_at`,
      [code, name, address || null, email]
    );
    const receiver = receiverResult.rows[0];

    const passwordHash = await bcrypt.hash(password, 10);
    const userResult = await client.query(
      `INSERT INTO users (name, email, password_hash, role, receiver_id, active)
       VALUES ($1, $2, $3, 'RECEIVER', $4, TRUE)
       RETURNING id, email`,
      [name, email, passwordHash, receiver.id]
    );

    await client.query('COMMIT');

    res.status(201).json({ ...receiver, user_id: userResult.rows[0].id, login_email: userResult.rows[0].email });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') {
      return res.status(409).json({ message: 'A supplier with this code or login email already exists' });
    }
    console.error('Create supplier account error:', error);
    res.status(500).json({ message: 'Failed to create supplier account' });
  } finally {
    client.release();
  }
});

app.put('/api/admin/receivers/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { code, name, address, email } = req.body;

  if (!code || !name || !email) {
    return res.status(400).json({ message: 'code, name and email are required' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const receiverResult = await client.query(
      `UPDATE receivers SET code = $1, name = $2, address = $3, email = $4
       WHERE id = $5
       RETURNING id, code, name, address, active, created_at`,
      [code, name, address || null, email, id]
    );
    if (receiverResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Supplier not found' });
    }

    const userResult = await client.query(
      `UPDATE users SET name = $1, email = $2
       WHERE receiver_id = $3 AND role = 'RECEIVER'
       RETURNING id, email`,
      [name, email, id]
    );

    await client.query('COMMIT');

    res.json({
      ...receiverResult.rows[0],
      user_id: userResult.rows[0]?.id || null,
      login_email: userResult.rows[0]?.email || null
    });
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === '23505') {
      return res.status(409).json({ message: 'A supplier with this code or login email already exists' });
    }
    console.error('Update supplier account error:', error);
    res.status(500).json({ message: 'Failed to update supplier account' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/receivers/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ message: 'newPassword must be at least 8 characters' });
  }

  try {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    const result = await db.query(
      `UPDATE users SET password_hash = $1 WHERE receiver_id = $2 AND role = 'RECEIVER' RETURNING id`,
      [passwordHash, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Supplier login account not found' });
    }
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset supplier password error:', error);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});

app.patch('/api/admin/receivers/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  if (typeof active !== 'boolean') {
    return res.status(400).json({ message: 'active must be a boolean' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const receiverResult = await client.query(
      `UPDATE receivers SET active = $1 WHERE id = $2 RETURNING id, active`,
      [active, id]
    );
    if (receiverResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Supplier not found' });
    }

    // Deactivating/reactivating the company cascades to its login account.
    await client.query(
      `UPDATE users SET active = $1 WHERE receiver_id = $2 AND role = 'RECEIVER'`,
      [active, id]
    );

    await client.query('COMMIT');
    res.json(receiverResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Toggle supplier status error:', error);
    res.status(500).json({ message: 'Failed to update supplier status' });
  } finally {
    client.release();
  }
});

// ==========================================
// 6. ADMIN USER MANAGEMENT (NX employees)
// ==========================================
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, name, email, role, phone, receiver_id, active, created_at FROM users ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch users error:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const { name, email, role, phone, password } = req.body;

  if (!name || !email || !role || !password) {
    return res.status(400).json({ message: 'name, email, role and password are required' });
  }
  if (!ROLES.includes(role)) {
    return res.status(400).json({ message: `role must be one of: ${ROLES.join(', ')}` });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'password must be at least 8 characters' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await db.query(
      `INSERT INTO users (name, email, password_hash, role, phone, active)
       VALUES ($1, $2, $3, $4, $5, TRUE)
       RETURNING id, name, email, role, phone, active, created_at`,
      [name, email, passwordHash, role, phone || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: 'A user with this email already exists' });
    }
    console.error('Create user error:', error);
    res.status(500).json({ message: 'Failed to create user' });
  }
});

app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, role, phone } = req.body;

  if (!name || !email || !role) {
    return res.status(400).json({ message: 'name, email and role are required' });
  }
  if (!ROLES.includes(role)) {
    return res.status(400).json({ message: `role must be one of: ${ROLES.join(', ')}` });
  }

  try {
    const result = await db.query(
      `UPDATE users SET name = $1, email = $2, role = $3, phone = $4
       WHERE id = $5
       RETURNING id, name, email, role, phone, active, created_at`,
      [name, email, role, phone || null, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ message: 'A user with this email already exists' });
    }
    console.error('Update user error:', error);
    res.status(500).json({ message: 'Failed to update user' });
  }
});

app.post('/api/admin/users/:id/reset-password', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ message: 'newPassword must be at least 8 characters' });
  }

  try {
    const passwordHash = await bcrypt.hash(newPassword, 10);
    const result = await db.query(
      `UPDATE users SET password_hash = $1 WHERE id = $2 RETURNING id`,
      [passwordHash, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Failed to reset password' });
  }
});

app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { active } = req.body;

  if (typeof active !== 'boolean') {
    return res.status(400).json({ message: 'active must be a boolean' });
  }

  try {
    const result = await db.query(
      `UPDATE users SET active = $1 WHERE id = $2 RETURNING id, active`,
      [active, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).json({ message: 'Failed to update user status' });
  }
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send('NRGP Backend API is running successfully.');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
