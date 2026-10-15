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
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DEFAULT_BULK_PASSWORD = 'Password@123';

const PKG_LABELS = {
  'BIN-001': 'Bin', 'PAL-001': 'Pallet', 'STP-001': 'Steel pallet',
  'TRO-001': 'Trolley', 'CB-001': 'Carton box', 'OTH-001': 'Others'
};
// NX's answer to a dispute.
const NX_DECISIONS = ['accept_mismatch', 'dispatched_correct'];
const isNxRole = (role) => role === 'NX' || role === 'ADMIN';

// Appends an entry to a dispatch's history. `queryable` is the pool or a
// transaction client.
const addDispatchEvent = (queryable, dispatchId, user, eventType, { decision = null, remark = null } = {}) =>
  queryable.query(
    `INSERT INTO dispatch_events (dispatch_id, user_id, actor_role, actor_name, event_type, decision, remark)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [dispatchId, user.id, user.role, user.name || null, eventType, decision, remark]
  );

const markDispatchRead = (queryable, userId, dispatchId) =>
  queryable.query(
    `INSERT INTO dispatch_reads (user_id, dispatch_id, last_read_at) VALUES ($1, $2, now())
     ON CONFLICT (user_id, dispatch_id) DO UPDATE SET last_read_at = now()`,
    [userId, dispatchId]
  );

// SQL condition: dispatch `d` has history from the *other* side (NX vs.
// supplier) that user $userParam hasn't opened since it happened. A clean
// receipt confirmation needs no NX attention, so it never counts.
const unreadCondition = (role, userParam) => `EXISTS (
  SELECT 1 FROM dispatch_events ev
  WHERE ev.dispatch_id = d.id AND NOT ev.backfilled
    AND ev.event_type <> 'receipt_confirmed'
    AND ev.actor_role ${role === 'RECEIVER' ? "IN ('NX', 'ADMIN')" : "= 'RECEIVER'"}
    AND ev.created_at > COALESCE(
      (SELECT rd.last_read_at FROM dispatch_reads rd WHERE rd.user_id = ${userParam} AND rd.dispatch_id = d.id),
      '-infinity'::timestamptz)
)`;

const EVENT_COLUMNS = 'id, dispatch_id, event_type, actor_role, actor_name, decision, remark, created_at, backfilled';

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

// Restores the signed-in user from a stored token (e.g. after a page refresh).
// Re-reads the account so a deactivation since login ends the session.
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.email, u.role, u.name, u.receiver_id, u.active, r.code as receiver_code, r.name as receiver_name, r.active as receiver_active
       FROM users u
       LEFT JOIN receivers r ON u.receiver_id = r.id
       WHERE u.id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Account not found' });
    }

    const user = result.rows[0];

    if (user.active === false || user.receiver_active === false) {
      return res.status(403).json({ message: 'This account has been deactivated' });
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        name: user.name,
        receiverId: user.receiver_id,
        receiverCode: user.receiver_code,
        receiverName: user.receiver_name
      }
    });
  } catch (error) {
    console.error('Fetch current user error:', error);
    res.status(500).json({ message: 'Failed to load current user' });
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
        d.nx_decision,
        d.resolved_at,
        ru.name as resolved_by_name,
        ru.role as resolved_by_role,
        r.code as receiver_code,
        r.name as receiver_name,
        ${unreadCondition(role, '$1')} as unread
      FROM dispatches d
      JOIN receivers r ON d.receiver_id = r.id
      LEFT JOIN users ru ON ru.id = d.resolved_by
    `;

    let params = [req.user.id];
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
    const rows = result.rows;

    // ?details=1 adds package lines and full history (used by CSV export).
    if (req.query.details && rows.length > 0) {
      const ids = rows.map((r) => r.id);
      const [linesResult, eventsResult] = await Promise.all([
        db.query(
          `SELECT id, dispatch_id, package_code, dispatched_qty, received_qty, confirm_status, remark, description
           FROM dispatch_lines WHERE dispatch_id = ANY($1) ORDER BY id ASC`,
          [ids]
        ),
        db.query(
          `SELECT ${EVENT_COLUMNS} FROM dispatch_events WHERE dispatch_id = ANY($1) ORDER BY created_at ASC, id ASC`,
          [ids]
        )
      ]);
      const byId = new Map(rows.map((r) => [r.id, Object.assign(r, { lines: [], events: [] })]));
      linesResult.rows.forEach((l) => byId.get(l.dispatch_id).lines.push(l));
      eventsResult.rows.forEach((e) => byId.get(e.dispatch_id).events.push(e));
    }

    res.json(rows);

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
  if (!vehicle_no || !String(vehicle_no).trim()) {
    return res.status(400).json({ message: 'vehicle_no is required' });
  }
  if (!Array.isArray(lines) || lines.length === 0) {
    return res.status(400).json({ message: 'At least one packaging line is required' });
  }
  let totalQty = 0;
  for (const line of lines) {
    if (!line.package_code) {
      return res.status(400).json({ message: 'Each line requires a package_code' });
    }
    const qty = Number(line.dispatched_qty) || 0;
    if (line.package_code === 'OTH-001' && qty > 0 && !(line.description || '').trim()) {
      return res.status(400).json({ message: 'A description is required for the "Others" package type' });
    }
    totalQty += qty;
  }
  if (totalQty <= 0) {
    return res.status(400).json({ message: 'Total dispatched quantity must be greater than zero' });
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
        `INSERT INTO dispatch_lines (dispatch_id, package_code, dispatched_qty, description)
         VALUES ($1, $2, $3, $4)`,
        [newDispatch.id, line.package_code, line.dispatched_qty || 0, line.description || null]
      );
    }

    await addDispatchEvent(client, newDispatch.id, req.user, 'created');
    await markDispatchRead(client, req.user.id, newDispatch.id);

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
// 3b. DISPATCH DETAIL, RECEIPT CONFIRMATION & DISPUTE RESOLUTION
// ==========================================
app.get('/api/dispatches/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { role, receiverId } = req.user;

  try {
    const dispatchResult = await db.query(
      `SELECT d.*, r.code as receiver_code, r.name as receiver_name,
              ru.name as resolved_by_name, ru.role as resolved_by_role
       FROM dispatches d
       JOIN receivers r ON d.receiver_id = r.id
       LEFT JOIN users ru ON ru.id = d.resolved_by
       WHERE d.id = $1`,
      [id]
    );
    if (dispatchResult.rows.length === 0) {
      return res.status(404).json({ message: 'Dispatch not found' });
    }
    const dispatch = dispatchResult.rows[0];

    if (role === 'RECEIVER' && dispatch.receiver_id !== receiverId) {
      return res.status(403).json({ message: 'Not authorized to view this dispatch' });
    }

    const linesResult = await db.query(
      `SELECT id, package_code, dispatched_qty, received_qty, confirm_status, remark, description
       FROM dispatch_lines WHERE dispatch_id = $1 ORDER BY id ASC`,
      [id]
    );

    const eventsResult = await db.query(
      `SELECT ${EVENT_COLUMNS} FROM dispatch_events WHERE dispatch_id = $1 ORDER BY created_at ASC, id ASC`,
      [id]
    );

    await markDispatchRead(db, req.user.id, dispatch.id);

    res.json({ ...dispatch, lines: linesResult.rows, events: eventsResult.rows });
  } catch (error) {
    console.error('Fetch dispatch detail error:', error);
    res.status(500).json({ message: 'Failed to fetch dispatch' });
  }
});

// RECEIVER confirms what actually arrived. Any line whose received quantity
// doesn't match what was dispatched is auto-marked Disputed (and requires a
// remark), which flips the whole dispatch to 'disputed' instead of 'confirmed'.
app.post('/api/dispatches/:id/receive', authenticateToken, async (req, res) => {
  if (req.user.role !== 'RECEIVER') {
    return res.status(403).json({ message: 'Only the receiver can confirm a receipt' });
  }

  const { id } = req.params;
  const { receiving_date_time, lines } = req.body;

  if (!Array.isArray(lines) || lines.length === 0) {
    return res.status(400).json({ message: 'lines is required' });
  }
  for (const line of lines) {
    if (line.id === undefined || line.received_qty === undefined) {
      return res.status(400).json({ message: 'Each line requires id and received_qty' });
    }
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const dispatchResult = await client.query(
      `SELECT id, receiver_id, status FROM dispatches WHERE id = $1 FOR UPDATE`,
      [id]
    );
    if (dispatchResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Dispatch not found' });
    }
    const dispatch = dispatchResult.rows[0];

    if (dispatch.receiver_id !== req.user.receiverId) {
      await client.query('ROLLBACK');
      return res.status(403).json({ message: 'Not authorized to confirm this dispatch' });
    }
    if (dispatch.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'This dispatch has already been confirmed' });
    }

    let anyDisputed = false;
    const disputeSummary = [];
    for (const line of lines) {
      const lineResult = await client.query(
        `SELECT package_code, dispatched_qty FROM dispatch_lines WHERE id = $1 AND dispatch_id = $2`,
        [line.id, id]
      );
      if (lineResult.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: `Line ${line.id} does not belong to this dispatch` });
      }

      const dispatchedQty = lineResult.rows[0].dispatched_qty;
      const receivedQty = Number(line.received_qty) || 0;
      const confirmStatus = receivedQty === dispatchedQty ? 'Accepted' : 'Disputed';

      if (confirmStatus === 'Disputed' && !line.remark) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'A remark is required for every disputed line' });
      }
      if (confirmStatus === 'Disputed') {
        anyDisputed = true;
        const label = PKG_LABELS[lineResult.rows[0].package_code] || lineResult.rows[0].package_code;
        disputeSummary.push(`${label}: sent ${dispatchedQty}, received ${receivedQty} - ${line.remark}`);
      }

      await client.query(
        `UPDATE dispatch_lines SET received_qty = $1, confirm_status = $2, remark = $3 WHERE id = $4`,
        [receivedQty, confirmStatus, line.remark || null, line.id]
      );
    }

    const newStatus = anyDisputed ? 'disputed' : 'confirmed';
    const updateResult = await client.query(
      `UPDATE dispatches
       SET status = $1, receiving_date_time = $2, receipt_submitted_at = now()
       WHERE id = $3
       RETURNING *`,
      [newStatus, receiving_date_time || new Date(), id]
    );

    await addDispatchEvent(client, dispatch.id, req.user, anyDisputed ? 'mismatch_reported' : 'receipt_confirmed', {
      remark: anyDisputed ? disputeSummary.join('; ') : null
    });
    await markDispatchRead(client, req.user.id, dispatch.id);

    await client.query('COMMIT');
    res.json({ message: 'Receipt submitted', dispatch: updateResult.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Submit receipt error:', error);
    res.status(500).json({ message: 'Failed to submit receipt' });
  } finally {
    client.release();
  }
});

// Locks a dispatch for a dispute action and checks the caller may act on it.
// Returns { dispatch } or { error: [status, message] }.
const lockDispatchForAction = async (client, id, user, allowedStatuses) => {
  const result = await client.query(
    `SELECT id, receiver_id, status, nx_decision FROM dispatches WHERE id = $1 FOR UPDATE`,
    [id]
  );
  if (result.rows.length === 0) return { error: [404, 'Dispatch not found'] };
  const dispatch = result.rows[0];
  if (user.role === 'RECEIVER' && dispatch.receiver_id !== user.receiverId) {
    return { error: [403, 'Not authorized to act on this dispatch'] };
  }
  if (!allowedStatuses.includes(dispatch.status)) {
    return { error: [400, `This action isn't available while the dispatch is ${dispatch.status}`] };
  }
  return { dispatch };
};

// Runs a dispute action in a transaction with the dispatch locked.
const runDisputeAction = async (req, res, allowedStatuses, action, failMessage) => {
  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const { dispatch, error } = await lockDispatchForAction(client, req.params.id, req.user, allowedStatuses);
    if (error) {
      await client.query('ROLLBACK');
      return res.status(error[0]).json({ message: error[1] });
    }
    const updated = await action(client, dispatch);
    await markDispatchRead(client, req.user.id, dispatch.id);
    await client.query('COMMIT');
    res.json({ dispatch: updated });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(`${failMessage}:`, err);
    res.status(500).json({ message: failMessage });
  } finally {
    client.release();
  }
};

const requireRemark = (req, res) => {
  const remark = String(req.body.remark ?? req.body.resolution_note ?? '').trim();
  if (!remark) {
    res.status(400).json({ message: 'A remark is required' });
    return null;
  }
  return remark;
};

// NX (or ADMIN) answers a dispute. This moves it to the Open ticket folder
// (it never jumps straight to resolved) and can be repeated there to change
// the answer; every reply is kept in the history.
app.post('/api/dispatches/:id/reply', authenticateToken, async (req, res) => {
  if (!isNxRole(req.user.role)) {
    return res.status(403).json({ message: 'Only NX employees can reply to a dispute' });
  }
  const { decision } = req.body;
  if (!NX_DECISIONS.includes(decision)) {
    return res.status(400).json({ message: `decision must be one of: ${NX_DECISIONS.join(', ')}` });
  }
  const remark = requireRemark(req, res);
  if (!remark) return;

  await runDisputeAction(req, res, ['disputed', 'open'], async (client, dispatch) => {
    const result = await client.query(
      `UPDATE dispatches SET status = 'open', nx_decision = $1 WHERE id = $2 RETURNING *`,
      [decision, dispatch.id]
    );
    await addDispatchEvent(client, dispatch.id, req.user, 'nx_reply', { decision, remark });
    return result.rows[0];
  }, 'Failed to send reply');
});

// Either side adds a remark to an open ticket.
app.post('/api/dispatches/:id/remark', authenticateToken, async (req, res) => {
  const remark = requireRemark(req, res);
  if (!remark) return;

  await runDisputeAction(req, res, ['open'], async (client, dispatch) => {
    await addDispatchEvent(client, dispatch.id, req.user, 'remark', { remark });
    return dispatch;
  }, 'Failed to add remark');
});

// Either side closes an open ticket with a closing remark. Disputes must get
// an NX reply first, so a disputed dispatch can't be resolved directly.
app.post('/api/dispatches/:id/resolve', authenticateToken, async (req, res) => {
  const remark = requireRemark(req, res);
  if (!remark) return;

  await runDisputeAction(req, res, ['open'], async (client, dispatch) => {
    const result = await client.query(
      `UPDATE dispatches
       SET status = 'resolved', resolution_note = $1, resolved_by = $2, resolved_at = now()
       WHERE id = $3
       RETURNING *`,
      [remark, req.user.id, dispatch.id]
    );
    await addDispatchEvent(client, dispatch.id, req.user, 'resolved', { remark });
    return result.rows[0];
  }, 'Failed to resolve ticket');
});

// ==========================================
// 3c. NOTIFICATIONS (unread badges + supplier pop-up)
// ==========================================
app.get('/api/notifications', authenticateToken, async (req, res) => {
  const { id: userId, role, receiverId } = req.user;

  try {
    const params = [userId];
    let scope = '';
    if (role === 'RECEIVER') {
      params.push(receiverId);
      scope = `AND d.receiver_id = $2`;
    }
    const countsResult = await db.query(
      `SELECT d.status, COUNT(*)::int AS count
       FROM dispatches d
       WHERE ${unreadCondition(role, '$1')} ${scope}
       GROUP BY d.status`,
      params
    );
    const unread = Object.fromEntries(countsResult.rows.map((r) => [r.status, r.count]));

    // Suppliers get a one-time pop-up for NX activity since they last saw it.
    let popup = [];
    if (role === 'RECEIVER') {
      const popupResult = await db.query(
        `SELECT e.id, e.dispatch_id, e.event_type, e.actor_name, e.decision, e.remark, e.created_at, d.transaction_id
         FROM dispatch_events e
         JOIN dispatches d ON d.id = e.dispatch_id
         JOIN users u ON u.id = $1
         WHERE d.receiver_id = $2
           AND e.actor_role IN ('NX', 'ADMIN')
           AND e.event_type IN ('nx_reply', 'remark', 'resolved')
           AND NOT e.backfilled
           AND e.created_at > COALESCE(u.last_notified_at, u.created_at)
         ORDER BY e.created_at DESC
         LIMIT 50`,
        [userId, receiverId]
      );
      popup = popupResult.rows;
    }

    res.json({ unread, popup });
  } catch (error) {
    console.error('Fetch notifications error:', error);
    res.status(500).json({ message: 'Failed to fetch notifications' });
  }
});

// Marks the pop-up as seen up to `upToEventId` (the newest entry it showed),
// so activity that arrives while it is open still pops up next time. Uses
// the event's own timestamp because JS dates lose Postgres' microseconds.
app.post('/api/notifications/dismiss', authenticateToken, async (req, res) => {
  const upToEventId = Number(req.body.upToEventId);
  if (!Number.isInteger(upToEventId) || upToEventId <= 0) {
    return res.status(400).json({ message: 'upToEventId is required' });
  }
  try {
    await db.query(
      `UPDATE users
       SET last_notified_at = GREATEST(
         COALESCE(last_notified_at, '-infinity'::timestamptz),
         (SELECT created_at FROM dispatch_events WHERE id = $1))
       WHERE id = $2`,
      [upToEventId, req.user.id]
    );
    res.json({ message: 'Dismissed' });
  } catch (error) {
    console.error('Dismiss notifications error:', error);
    res.status(500).json({ message: 'Failed to dismiss notifications' });
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

// Bulk-create supplier accounts (receiver + linked login) from a CSV parsed
// client-side. Valid rows are created; invalid or duplicate rows are
// skipped and reported by row number so the admin can fix just those and
// re-upload.
app.post('/api/admin/receivers/bulk', authenticateToken, requireAdmin, async (req, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ message: 'rows is required and must be a non-empty array' });
  }

  const existingEmailsResult = await db.query(`SELECT LOWER(email) as email FROM users`);
  const existingEmails = new Set(existingEmailsResult.rows.map((r) => r.email));
  const existingCodesResult = await db.query(`SELECT UPPER(code) as code FROM receivers`);
  const existingCodes = new Set(existingCodesResult.rows.map((r) => r.code));
  const seenEmails = new Set();
  const seenCodes = new Set();

  const errors = [];
  let created = 0;
  const passwordHash = await bcrypt.hash(DEFAULT_BULK_PASSWORD, 10);

  for (let i = 0; i < rows.length; i++) {
    const rowNum = i + 2; // account for the CSV header row
    const row = rows[i] || {};
    const code = (row.code || '').trim();
    const name = (row.name || '').trim();
    const email = (row.email || '').trim();
    const address = (row.address || '').trim();
    const emailLower = email.toLowerCase();
    const codeUpper = code.toUpperCase();

    if (!code) {
      errors.push({ row: rowNum, message: 'code is required' });
      continue;
    }
    if (!name) {
      errors.push({ row: rowNum, message: 'name is required' });
      continue;
    }
    if (!email || !EMAIL_RE.test(email)) {
      errors.push({ row: rowNum, message: 'a valid email is required' });
      continue;
    }
    if (existingCodes.has(codeUpper) || seenCodes.has(codeUpper)) {
      errors.push({ row: rowNum, message: `code already exists: ${code}` });
      continue;
    }
    if (existingEmails.has(emailLower) || seenEmails.has(emailLower)) {
      errors.push({ row: rowNum, message: `email already exists: ${email}` });
      continue;
    }

    const client = await db.getClient();
    try {
      await client.query('BEGIN');
      const receiverResult = await client.query(
        `INSERT INTO receivers (code, name, address, email, active)
         VALUES ($1, $2, $3, $4, TRUE)
         RETURNING id`,
        [code, name, address || null, email]
      );
      await client.query(
        `INSERT INTO users (name, email, password_hash, role, receiver_id, active)
         VALUES ($1, $2, $3, 'RECEIVER', $4, TRUE)`,
        [name, email, passwordHash, receiverResult.rows[0].id]
      );
      await client.query('COMMIT');
      seenCodes.add(codeUpper);
      seenEmails.add(emailLower);
      created += 1;
    } catch (error) {
      await client.query('ROLLBACK');
      if (error.code === '23505') {
        errors.push({ row: rowNum, message: `code or email already exists: ${code} / ${email}` });
      } else {
        console.error('Bulk create supplier row error:', error);
        errors.push({ row: rowNum, message: 'Failed to create this row' });
      }
    } finally {
      client.release();
    }
  }

  res.json({ created, errors, defaultPassword: DEFAULT_BULK_PASSWORD });
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

// Bulk-create NX employees from a CSV parsed client-side. Valid rows are
// created; invalid or duplicate rows are skipped and reported by row
// number so the admin can fix just those and re-upload.
app.post('/api/admin/users/bulk', authenticateToken, requireAdmin, async (req, res) => {
  const { rows } = req.body;
  if (!Array.isArray(rows) || rows.length === 0) {
    return res.status(400).json({ message: 'rows is required and must be a non-empty array' });
  }

  const existing = await db.query(`SELECT LOWER(email) as email FROM users`);
  const existingEmails = new Set(existing.rows.map((r) => r.email));
  const seenInBatch = new Set();

  const errors = [];
  let created = 0;
  const passwordHash = await bcrypt.hash(DEFAULT_BULK_PASSWORD, 10);

  for (let i = 0; i < rows.length; i++) {
    const rowNum = i + 2; // account for the CSV header row
    const row = rows[i] || {};
    const name = (row.name || '').trim();
    const email = (row.email || '').trim();
    const role = (row.role || '').trim().toUpperCase();
    const phone = (row.phone || '').trim();
    const emailLower = email.toLowerCase();

    if (!name) {
      errors.push({ row: rowNum, message: 'name is required' });
      continue;
    }
    if (!email || !EMAIL_RE.test(email)) {
      errors.push({ row: rowNum, message: 'a valid email is required' });
      continue;
    }
    if (!['NX', 'ADMIN'].includes(role)) {
      errors.push({ row: rowNum, message: 'role must be NX or ADMIN' });
      continue;
    }
    if (existingEmails.has(emailLower)) {
      errors.push({ row: rowNum, message: `email already exists: ${email}` });
      continue;
    }
    if (seenInBatch.has(emailLower)) {
      errors.push({ row: rowNum, message: `duplicate email in file: ${email}` });
      continue;
    }

    try {
      await db.query(
        `INSERT INTO users (name, email, password_hash, role, phone, active)
         VALUES ($1, $2, $3, $4, $5, TRUE)`,
        [name, email, passwordHash, role, phone || null]
      );
      seenInBatch.add(emailLower);
      created += 1;
    } catch (error) {
      if (error.code === '23505') {
        errors.push({ row: rowNum, message: `email already exists: ${email}` });
      } else {
        console.error('Bulk create user row error:', error);
        errors.push({ row: rowNum, message: 'Failed to create this row' });
      }
    }
  }

  res.json({ created, errors, defaultPassword: DEFAULT_BULK_PASSWORD });
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
