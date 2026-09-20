const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'nrgp_super_secret_key_2026';

// Middleware
app.use(cors());
app.use(express.json());

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

// ==========================================
// 1. AUTHENTICATION (SHARED LOGIN PAGE)
// ==========================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    // Find user in Users Master (Single login point)
    const result = await db.query(
      `SELECT u.id, u.email, u.password_hash, u.role, u.name, u.receiver_id, r.code as receiver_code, r.name as receiver_name 
       FROM users u 
       LEFT JOIN receivers r ON u.receiver_id = r.id 
       WHERE LOWER(u.email) = LOWER($1)`,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // For initial seed testing or hashed passwords check
    let validPassword = false;
    if (user.password_hash.startsWith('$2b$') || user.password_hash.startsWith('$2a$')) {
      validPassword = await bcrypt.compare(password, user.password_hash);
    } else {
      // Fallback for dev/testing plain text initial setup
      validPassword = (password === user.password_hash || password === 'admin123');
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
  const { status, tab } = req.query;

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

  try {
    // Generate auto Transaction ID (NRGP-YYYY-####)
    const year = new Date().getFullYear();
    const countResult = await db.query(`SELECT COUNT(*) FROM dispatches WHERE transaction_id LIKE 'NRGP-${year}-%'`);
    const nextNum = String(parseInt(countResult.rows[0].count) + 1).padStart(4, '0');
    const transactionId = `NRGP-${year}-${nextNum}`;

    // Auto-fill Warehouse PIC from logged-in NX user's name
    const warehousePic = req.user.name || 'NX Dispatch Staff';

    // Insert main Dispatch record
    const dispatchResult = await db.query(
      `INSERT INTO dispatches 
       (transaction_id, receiver_id, dispatch_date_time, vehicle_no, driver_details, warehouse_pic, status, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7)
       RETURNING *`,
      [transactionId, receiver_id, dispatch_date_time || new Date(), vehicle_no, driver_details, warehousePic, req.user.id]
    );

    const newDispatch = dispatchResult.rows[0];

    // Insert Packaging Lines
    if (lines && lines.length > 0) {
      for (const line of lines) {
        await db.query(
          `INSERT INTO dispatch_lines (dispatch_id, package_code, dispatched_qty)
           VALUES ($1, $2, $3)`,
          [newDispatch.id, line.package_code, line.dispatched_qty || 0]
        );
      }
    }

    res.status(201).json({
      message: 'Dispatch created successfully',
      dispatch: newDispatch
    });

  } catch (error) {
    console.error('Create dispatch error:', error);
    res.status(500).json({ message: 'Failed to create dispatch' });
  }
});

// Health check endpoint
app.get('/', (req, res) => {
  res.send('NRGP Backend API is running successfully.');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});