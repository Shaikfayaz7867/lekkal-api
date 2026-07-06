const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'lekkal_secret_secure_key_1234!';

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const dbPath = path.resolve(__dirname, 'lekkal_backup.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to the SQLite database: lekkal_backup.db');
    createTables();
  }
});

// Create tables
function createTables() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Expenses table with local_id to map back to Room DB IDs
    db.run(`
      CREATE TABLE IF NOT EXISTS expenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        local_id INTEGER NOT NULL,
        merchant TEXT NOT NULL,
        amount REAL NOT NULL,
        timestamp INTEGER NOT NULL,
        category TEXT NOT NULL,
        payment_method TEXT NOT NULL,
        is_simulated INTEGER DEFAULT 0,
        sms_sender TEXT,
        notes TEXT,
        raw_sms_text TEXT,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, local_id)
      )
    `);

    // Budgets table
    db.run(`
      CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        local_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        is_category INTEGER DEFAULT 0,
        category_name TEXT,
        amount REAL NOT NULL,
        timestamp INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, local_id)
      )
    `);

    console.log('Successfully configured SQLite schemas for Users, Expenses, and Budgets.');
  });
}

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
app.post('/api/auth/register', (req, res) => {
  const { email, password, name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Encryption failed.' });
    }

    const query = `INSERT INTO users (email, password, name) VALUES (?, ?, ?)`;
    db.run(query, [email, hashedPassword, name || 'User'], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ error: 'An account with this email already exists.' });
        }
        return res.status(500).json({ error: 'Database signup failed: ' + err.message });
      }

      const token = jwt.sign({ id: this.lastID, email, name: name || 'User' }, JWT_SECRET, { expiresIn: '30d' });
      res.status(201).json({
        message: 'Registration successful!',
        token,
        user: { id: this.lastID, email, name: name || 'User' }
      });
    });
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database authentication error.' });
    }
    if (!user) {
      return res.status(400).json({ error: 'No account registered with this email.' });
    }

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ error: 'Decryption failed.' });
      }
      if (!isMatch) {
        return res.status(400).json({ error: 'Incorrect passcode/password.' });
      }

      const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
      res.json({
        message: 'Login successful!',
        token,
        user: { id: user.id, email: user.email, name: user.name }
      });
    });
  });
});

// Profile status check
app.get('/api/auth/me', authenticateToken, (req, res) => {
  db.get(`SELECT id, email, name, created_at FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User profiles not found.' });
    }
    res.json(user);
  });
});


// --- REAL-TIME DATA SYNCHRONIZATION API ---

// Unified Sync Endpoint
app.post('/api/sync', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { expenses = [], budgets = [] } = req.body;

  console.log(`Sync requested for User ID: ${userId}. Incoming items: ${expenses.length} expenses, ${budgets.length} budgets.`);

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    try {
      // 1. Process Expenses
      const expenseStmt = db.prepare(`
        INSERT INTO expenses (
          user_id, local_id, merchant, amount, timestamp, category, payment_method, is_simulated, sms_sender, notes, raw_sms_text, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      `);

      expenses.forEach(exp => {
        expenseStmt.run([
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
          exp.timestamp // use timestamp or current time as updated_at
        ]);
      });
      expenseStmt.finalize();

      // 2. Process Budgets
      const budgetStmt = db.prepare(`
        INSERT INTO budgets (
          user_id, local_id, name, is_category, category_name, amount, timestamp, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, local_id) DO UPDATE SET
          name = excluded.name,
          is_category = excluded.is_category,
          category_name = excluded.category_name,
          amount = excluded.amount,
          timestamp = excluded.timestamp,
          updated_at = excluded.updated_at
        WHERE excluded.updated_at > budgets.updated_at
      `);

      budgets.forEach(bud => {
        budgetStmt.run([
          userId,
          bud.id, // mapped local id
          bud.name,
          bud.isCategory ? 1 : 0,
          bud.categoryName || null,
          bud.amount,
          bud.timestamp,
          bud.timestamp
        ]);
      });
      budgetStmt.finalize();

      db.run('COMMIT', (err) => {
        if (err) {
          console.error('Commit failed, rolling back:', err);
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Sync transaction failed to commit.' });
        }

        // Fetch back updated dataset to return to client
        db.all(`SELECT * FROM expenses WHERE user_id = ?`, [userId], (err, allExpenses) => {
          if (err) return res.status(500).json({ error: 'Failed to retrieve synced expenses.' });

          db.all(`SELECT * FROM budgets WHERE user_id = ?`, [userId], (err, allBudgets) => {
            if (err) return res.status(500).json({ error: 'Failed to retrieve synced budgets.' });

            // Format appropriately for Jetpack Compose models
            const formattedExpenses = allExpenses.map(exp => ({
              id: exp.local_id, // map back to client's local room ID
              merchant: exp.merchant,
              amount: exp.amount,
              timestamp: exp.timestamp,
              category: exp.category,
              paymentMethod: exp.payment_method,
              isSimulated: exp.is_simulated === 1,
              smsSender: exp.sms_sender,
              notes: exp.notes || '',
              rawSmsText: exp.raw_sms_text
            }));

            const formattedBudgets = allBudgets.map(bud => ({
              id: bud.local_id, // map back to client's local room ID
              name: bud.name,
              isCategory: bud.is_category === 1,
              categoryName: bud.category_name,
              amount: bud.amount,
              timestamp: bud.timestamp
            }));

            res.json({
              message: 'Sync completed successfully!',
              timestamp: Date.now(),
              expenses: formattedExpenses,
              budgets: formattedBudgets
            });
          });
        });
      });

    } catch (e) {
      console.error('Exception during transaction sync, rolling back:', e);
      db.run('ROLLBACK');
      res.status(500).json({ error: 'Sync server fatal error: ' + e.message });
    }
  });
});

// Anonymous / Accountless Sync Endpoint based on unique device identifier
app.post('/api/sync/anonymous', (req, res) => {
  const { deviceId, expenses = [], budgets = [] } = req.body;

  if (!deviceId) {
    return res.status(400).json({ error: 'Device ID is required for anonymous sync.' });
  }

  // Find or create anonymous user for this device ID
  db.get(`SELECT * FROM users WHERE email = ?`, [deviceId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database search error: ' + err.message });
    }

    if (user) {
      runSyncForUser(user.id, expenses, budgets, res);
    } else {
      // Create new virtual anonymous user
      db.run(`INSERT INTO users (email, password, name) VALUES (?, ?, ?)`, [deviceId, 'anonymous_pass', 'Device ' + deviceId], function (err) {
        if (err) {
          return res.status(500).json({ error: 'Database anonymous user registration failed: ' + err.message });
        }
        runSyncForUser(this.lastID, expenses, budgets, res);
      });
    }
  });
});

function runSyncForUser(userId, expenses, budgets, res) {
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    try {
      // 1. Process Expenses
      const expenseStmt = db.prepare(`
        INSERT INTO expenses (
          user_id, local_id, merchant, amount, timestamp, category, payment_method, is_simulated, sms_sender, notes, raw_sms_text, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      `);

      expenses.forEach(exp => {
        expenseStmt.run([
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
          exp.timestamp // use timestamp or current time as updated_at
        ]);
      });
      expenseStmt.finalize();

      // 2. Process Budgets
      const budgetStmt = db.prepare(`
        INSERT INTO budgets (
          user_id, local_id, name, is_category, category_name, amount, timestamp, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, local_id) DO UPDATE SET
          name = excluded.name,
          is_category = excluded.is_category,
          category_name = excluded.category_name,
          amount = excluded.amount,
          timestamp = excluded.timestamp,
          updated_at = excluded.updated_at
        WHERE excluded.updated_at > budgets.updated_at
      `);

      budgets.forEach(bud => {
        budgetStmt.run([
          userId,
          bud.id, // mapped local id
          bud.name,
          bud.isCategory ? 1 : 0,
          bud.categoryName || null,
          bud.amount,
          bud.timestamp,
          bud.timestamp
        ]);
      });
      budgetStmt.finalize();

      db.run('COMMIT', (err) => {
        if (err) {
          console.error('Commit failed, rolling back:', err);
          db.run('ROLLBACK');
          return res.status(500).json({ error: 'Sync transaction failed to commit.' });
        }

        // Fetch back updated dataset to return to client
        db.all(`SELECT * FROM expenses WHERE user_id = ?`, [userId], (err, allExpenses) => {
          if (err) return res.status(500).json({ error: 'Failed to retrieve synced expenses.' });

          db.all(`SELECT * FROM budgets WHERE user_id = ?`, [userId], (err, allBudgets) => {
            if (err) return res.status(500).json({ error: 'Failed to retrieve synced budgets.' });

            // Format appropriately for Jetpack Compose models
            const formattedExpenses = allExpenses.map(exp => ({
              id: exp.local_id, // map back to client's local room ID
              merchant: exp.merchant,
              amount: exp.amount,
              timestamp: exp.timestamp,
              category: exp.category,
              paymentMethod: exp.payment_method,
              isSimulated: exp.is_simulated === 1,
              smsSender: exp.sms_sender,
              notes: exp.notes || '',
              rawSmsText: exp.raw_sms_text
            }));

            const formattedBudgets = allBudgets.map(bud => ({
              id: bud.local_id, // map back to client's local room ID
              name: bud.name,
              isCategory: bud.is_category === 1,
              categoryName: bud.category_name,
              amount: bud.amount,
              timestamp: bud.timestamp
            }));

            res.json({
              message: 'Sync completed successfully!',
              timestamp: Date.now(),
              expenses: formattedExpenses,
              budgets: formattedBudgets
            });
          });
        });
      });

    } catch (e) {
      console.error('Exception during transaction sync, rolling back:', e);
      db.run('ROLLBACK');
      res.status(500).json({ error: 'Sync server fatal error: ' + e.message });
    }
  });
}


// App health status check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    serverTime: new Date().toISOString(),
    database: 'SQLite - Connected',
    appName: 'Lekkal Finance API Gateway'
  });
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
          <p>This backend utilizes <strong>Express.js</strong> and a local, secure <strong>SQLite</strong> database for seamless local and multi-device backups.</p>
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
