const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'lekkal_secret_secure_key_1234!';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('CRITICAL: DATABASE_URL environment variable is not defined.');
  process.exit(1);
}

// Middleware
app.use(cors());
app.use(express.json());

// Connection Pool Settings
const isProduction = process.env.NODE_ENV === 'production' || (!DATABASE_URL.includes('localhost') && !DATABASE_URL.includes('127.0.0.1'));
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

// Initialize PostgreSQL Database
async function initDb() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Expenses table with local_id to map back to Room DB IDs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS expenses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        local_id INTEGER NOT NULL,
        merchant VARCHAR(255) NOT NULL,
        amount DOUBLE PRECISION NOT NULL,
        timestamp BIGINT NOT NULL,
        category VARCHAR(255) NOT NULL,
        payment_method VARCHAR(255) NOT NULL,
        is_simulated INTEGER DEFAULT 0,
        sms_sender VARCHAR(255),
        notes TEXT,
        raw_sms_text TEXT,
        updated_at BIGINT NOT NULL,
        UNIQUE(user_id, local_id)
      )
    `);

    // Budgets table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS budgets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        local_id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        is_category INTEGER DEFAULT 0,
        category_name VARCHAR(255),
        amount DOUBLE PRECISION NOT NULL,
        timestamp BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        UNIQUE(user_id, local_id)
      )
    `);

    console.log('Successfully configured PostgreSQL schemas for Users, Expenses, and Budgets.');
  } catch (err) {
    console.error('Error configuring database schemas:', err.message);
    process.exit(1);
  }
}

initDb();

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required. Please authenticate.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
}

// --- AUTH API ENDPOINTS ---

// Register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const query = `INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id`;
    const result = await pool.query(query, [email, hashedPassword, name || 'User']);
    const userId = result.rows[0].id;

    const token = jwt.sign({ id: userId, email, name: name || 'User' }, JWT_SECRET, { expiresIn: '30d' });
    return res.status(201).json({
      message: 'Registration successful!',
      token,
      user: { id: userId, email, name: name || 'User' }
    });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQL unique_violation
      return res.status(400).json({ error: 'An account with this email already exists.' });
    }
    return res.status(500).json({ error: 'Database signup failed: ' + err.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'No account registered with this email.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect passcode/password.' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({
      message: 'Login successful!',
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Database authentication error: ' + err.message });
  }
});

// Profile status check
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, email, name, created_at FROM users WHERE id = $1`, [req.user.id]);
    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User profiles not found.' });
    }
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ error: 'Database error: ' + err.message });
  }
});


// --- REAL-TIME DATA SYNCHRONIZATION API ---

// Unified Sync Endpoint
app.post('/api/sync', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { expenses = [], budgets = [] } = req.body;

  console.log(`Sync requested for User ID: ${userId}. Incoming items: ${expenses.length} expenses, ${budgets.length} budgets.`);
  await runSyncForUser(userId, expenses, budgets, res);
});

// Anonymous / Accountless Sync Endpoint based on unique device identifier
app.post('/api/sync/anonymous', async (req, res) => {
  const { deviceId, expenses = [], budgets = [] } = req.body;

  if (!deviceId) {
    return res.status(400).json({ error: 'Device ID is required for anonymous sync.' });
  }

  try {
    // Find or create anonymous user for this device ID
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [deviceId]);
    const user = result.rows[0];

    if (user) {
      await runSyncForUser(user.id, expenses, budgets, res);
    } else {
      // Create new virtual anonymous user
      const insertResult = await pool.query(
        `INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id`,
        [deviceId, 'anonymous_pass', 'Device ' + deviceId]
      );
      await runSyncForUser(insertResult.rows[0].id, expenses, budgets, res);
    }
  } catch (err) {
    return res.status(500).json({ error: 'Database anonymous user registration failed: ' + err.message });
  }
});

async function runSyncForUser(userId, expenses, budgets, res) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Process Expenses
    const expenseQuery = `
      INSERT INTO expenses (
        user_id, local_id, merchant, amount, timestamp, category, payment_method, is_simulated, sms_sender, notes, raw_sms_text, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT(user_id, local_id) DO UPDATE SET
        merchant = excluded.merchant,
        amount = excluded.amount,
        timestamp = excluded.timestamp,
        category = excluded.category,
        payment_method = excluded.payment_method,
        is_simulated = excluded.is_simulated,
        sms_sender = excluded.sms_sender,
        notes = excluded.notes,
        raw_sms_text = excluded.raw_sms_text,
        updated_at = excluded.updated_at
      WHERE excluded.updated_at > expenses.updated_at
    `;

    for (const exp of expenses) {
      await client.query(expenseQuery, [
        userId,
        exp.id, // mapped local id
        exp.merchant,
        exp.amount,
        exp.timestamp,
        exp.category,
        exp.paymentMethod,
        exp.isSimulated ? 1 : 0,
        exp.smsSender || null,
        exp.notes || '',
        exp.rawSmsText || null,
        exp.timestamp // use timestamp as updated_at
      ]);
    }

    // 2. Process Budgets
    const budgetQuery = `
      INSERT INTO budgets (
        user_id, local_id, name, is_category, category_name, amount, timestamp, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT(user_id, local_id) DO UPDATE SET
        name = excluded.name,
        is_category = excluded.is_category,
        category_name = excluded.category_name,
        amount = excluded.amount,
        timestamp = excluded.timestamp,
        updated_at = excluded.updated_at
      WHERE excluded.updated_at > budgets.updated_at
    `;

    for (const bud of budgets) {
      await client.query(budgetQuery, [
        userId,
        bud.id, // mapped local id
        bud.name,
        bud.isCategory ? 1 : 0,
        bud.categoryName || null,
        bud.amount,
        bud.timestamp,
        bud.timestamp
      ]);
    }

    await client.query('COMMIT');

    // Fetch back updated dataset to return to client
    const expensesRes = await client.query(`SELECT * FROM expenses WHERE user_id = $1`, [userId]);
    const budgetsRes = await client.query(`SELECT * FROM budgets WHERE user_id = $1`, [userId]);

    // Format appropriately for Jetpack Compose models
    const formattedExpenses = expensesRes.rows.map(exp => ({
      id: typeof exp.local_id === 'string' ? parseInt(exp.local_id, 10) : exp.local_id,
      merchant: exp.merchant,
      amount: typeof exp.amount === 'string' ? parseFloat(exp.amount) : exp.amount,
      timestamp: typeof exp.timestamp === 'string' ? parseInt(exp.timestamp, 10) : exp.timestamp,
      category: exp.category,
      paymentMethod: exp.payment_method,
      isSimulated: exp.is_simulated === 1,
      smsSender: exp.sms_sender,
      notes: exp.notes || '',
      rawSmsText: exp.raw_sms_text
    }));

    const formattedBudgets = budgetsRes.rows.map(bud => ({
      id: typeof bud.local_id === 'string' ? parseInt(bud.local_id, 10) : bud.local_id,
      name: bud.name,
      isCategory: bud.is_category === 1,
      categoryName: bud.category_name,
      amount: typeof bud.amount === 'string' ? parseFloat(bud.amount) : bud.amount,
      timestamp: typeof bud.timestamp === 'string' ? parseInt(bud.timestamp, 10) : bud.timestamp
    }));

    return res.json({
      message: 'Sync completed successfully!',
      timestamp: Date.now(),
      expenses: formattedExpenses,
      budgets: formattedBudgets
    });

  } catch (e) {
    console.error('Exception during transaction sync, rolling back:', e);
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Rollback failed:', rollbackErr);
    }
    return res.status(500).json({ error: 'Sync server fatal error: ' + e.message });
  } finally {
    client.release();
  }
}


// App health status check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    return res.json({
      status: 'online',
      serverTime: new Date().toISOString(),
      database: 'PostgreSQL - Connected',
      appName: 'Lekkal Finance API Gateway'
    });
  } catch (err) {
    return res.status(500).json({
      status: 'error',
      serverTime: new Date().toISOString(),
      database: 'PostgreSQL - Connection Failed: ' + err.message,
      appName: 'Lekkal Finance API Gateway'
    });
  }
});

// --- DATA RETRIEVAL API ---

// Get all expenses with optional filters
app.get('/api/expenses', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { merchant, category, minAmount, maxAmount } = req.query;

  try {
    let query = `SELECT * FROM expenses WHERE user_id = $1`;
    const params = [userId];

    if (merchant) {
      params.push(`%${merchant}%`);
      query += ` AND merchant ILIKE $${params.length}`;
    }
    if (category) {
      params.push(category);
      query += ` AND category = $${params.length}`;
    }
    if (minAmount) {
      params.push(parseFloat(minAmount));
      query += ` AND amount >= $${params.length}`;
    }
    if (maxAmount) {
      params.push(parseFloat(maxAmount));
      query += ` AND amount <= $${params.length}`;
    }

    query += ` ORDER BY timestamp DESC`;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch expenses: ' + err.message });
  }
});

// Serve backup instructions as a simple UI on root
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Lekkal Server Gateway</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0B0E14; color: #E2E8F0; padding: 40px; line-height: 1.6; }
          .container { max-width: 650px; margin: 0 auto; background: #131822; padding: 30px; border-radius: 12px; border: 1px solid #1E293B; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
          h1 { color: #38BDF8; border-bottom: 1px solid #1E293B; padding-bottom: 10px; }
          code { background: #1E293B; color: #38BDF8; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
          .status { display: inline-block; background: #10B981; color: #fff; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Lekkal Backend Server <span class="status">ONLINE</span></h1>
          <p>Lekkal's fully functional database-connected cloud sync gateway is running successfully!</p>
          <p>This backend utilizes <strong>Express.js</strong> and a secure <strong>PostgreSQL</strong> database for seamless local and multi-device backups.</p>
          <h3>Active Sync Routes</h3>
          <ul>
            <li><code>POST /api/auth/register</code> - Register accounts</li>
            <li><code>POST /api/auth/login</code> - Retrieve JWT Token</li>
            <li><code>POST /api/sync</code> - Dual bidirectional transaction & budget backup sync</li>
            <li><code>GET /api/health</code> - Status monitor checks</li>
          </ul>
        </div>
      </body>
    </html>
  `);
});

// Start listening
app.listen(PORT, () => {
  console.log(`Lekkal sync backend listening at http://localhost:${PORT}`);
});
