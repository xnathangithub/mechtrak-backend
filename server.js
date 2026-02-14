const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const rateLimit = require('express-rate-limit');

// General API rate limit
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, error: 'Too many login attempts, please try again in 15 minutes' },
  handler: (req, res, next, options) => {
    console.log(`⚠️ Rate limit hit on ${req.path} from ${req.ip}`);
    res.status(429).json(options.message);
  }
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { success: false, error: 'Too many requests, please try again later' },
  handler: (req, res, next, options) => {
    console.log(`⚠️ Rate limit hit on ${req.path} from ${req.ip}`);
    res.status(429).json(options.message);
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { success: false, error: 'Too many requests, please try again later' },
  handler: (req, res, next, options) => {
    console.log(`⚠️ Rate limit hit on ${req.path} from ${req.ip}`);
    res.status(429).json(options.message);
  }
});


// Apply general limit to all routes
app.use('/api/', apiLimiter);

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection error:', err);
  } else {
    console.log('✅ Database connected successfully');
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Auth middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
};

// Helper to get userId from token
const getUserIdFromToken = (req) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded.userId;
  } catch (e) {
    return null;
  }
};

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'Server is running!', database: 'connected' });
});

// Store last heartbeat time per user (in memory for now)
const pluginHeartbeats = {};

// Plugin heartbeat - called by plugin every 30 seconds
app.post('/api/heartbeat', async (req, res) => {
  try {
    const { session_id } = req.body;
    const userId = getUserIdFromToken(req);
    const key = userId || session_id || 'anonymous';
    pluginHeartbeats[key] = Date.now();
    res.json({ success: true, message: 'Heartbeat received' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Check if plugin is connected
app.get('/api/heartbeat/check', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);

    console.log('Heartbeats stored:', pluginHeartbeats);
    console.log('Looking for userId:', userId);

    const userKey = userId ? userId.toString() : null;
    
    const lastHeartbeat = 
      (userKey && pluginHeartbeats[userKey]) || 
      pluginHeartbeats['anonymous'] ||
      Object.values(pluginHeartbeats).sort((a, b) => b - a)[0];
    
    console.log('Last heartbeat found:', lastHeartbeat);
    
    if (!lastHeartbeat) {
      return res.json({ success: true, connected: false });
    }
    
    const secondsSinceHeartbeat = (Date.now() - lastHeartbeat) / 1000;
    const connected = secondsSinceHeartbeat < 60;
    
    res.json({ success: true, connected, secondsSinceHeartbeat: Math.round(secondsSinceHeartbeat) });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body;

    const existingUser = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ success: false, error: 'Email already in use' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash, username) VALUES ($1, $2, $3) RETURNING id, email, username, created_at',
      [email, passwordHash, username]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ User registered:', user.email);
    res.json({ success: true, token, user });

  } catch (error) {
    console.error('❌ Register error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login
app.post('/api/auth/login', authLimiter,async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    await pool.query(
      'UPDATE users SET last_login = NOW() WHERE id = $1',
      [user.id]
    );

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('✅ User logged in:', user.email);
    res.json({ 
      success: true, 
      token, 
      user: { 
        id: user.id, 
        email: user.email, 
        username: user.username 
      } 
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Store current user token for plugin
let currentUserToken = null;

// Add column to users table to store plugin token
// Run this in Supabase SQL editor:
// ALTER TABLE users ADD COLUMN IF NOT EXISTS plugin_token TEXT;

app.post('/api/plugin/register-token', async (req, res) => {
  const userId = getUserIdFromToken(req);
  if (!userId) return res.status(401).json({ success: false });
  
  const token = req.headers.authorization?.split(' ')[1];
  
  await pool.query(
    'UPDATE users SET plugin_token = $1 WHERE id = $2',
    [token, userId]
  );
  
  res.json({ success: true });
});

app.get('/api/plugin/token', async (req, res) => {
  try {
    // Get most recently active user's token
    const result = await pool.query(
      'SELECT plugin_token FROM users WHERE plugin_token IS NOT NULL ORDER BY last_login DESC LIMIT 1'
    );
    
    if (result.rows.length === 0 || !result.rows[0].plugin_token) {
      return res.json({ success: true, token: null });
    }
    
    res.json({ success: true, token: result.rows[0].plugin_token });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify token
app.get('/api/auth/verify', verifyLimiter, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, error: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await pool.query(
      'SELECT id, email, username FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: result.rows[0] });

  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
});

// Upload session
app.post('/api/sessions', async (req, res) => {
  try {
    const sessionData = req.body;
    let userId = getUserIdFromToken(req);
    
    // If no token, try to find user_id from existing session record
    if (!userId) {
      const existingSession = await pool.query(
        'SELECT user_id FROM sessions WHERE session_id = $1',
        [sessionData.sessionId]
      );
      if (existingSession.rows.length > 0 && existingSession.rows[0].user_id) {
        userId = existingSession.rows[0].user_id;
      }
    }
    
    console.log('📥 Received session:', sessionData.sessionId, 'userId:', userId);
    
    const query = `
      INSERT INTO sessions (
        session_id, status, start_time, last_updated, 
        duration_minutes, total_attempts, total_goals, 
        total_accuracy, total_shots, shots_data, user_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      ON CONFLICT (session_id) 
      DO UPDATE SET 
        status = $2,
        last_updated = $4,
        duration_minutes = $5,
        total_attempts = $6,
        total_goals = $7,
        total_accuracy = $8,
        total_shots = $9,
        shots_data = $10,
        user_id = COALESCE(sessions.user_id, $11)
      RETURNING *;
    `;
    
    const values = [
      sessionData.sessionId,
      sessionData.status,
      sessionData.startTime,
      sessionData.lastUpdated,
      sessionData.durationMinutes,
      sessionData.totalAttempts,
      sessionData.totalGoals,
      sessionData.totalAccuracy,
      sessionData.totalShots,
      JSON.stringify(sessionData.shots),
      userId
    ];
    
    const result = await pool.query(query, values);
    
    console.log('💾 Session saved to database');
    res.json({ 
      success: true, 
      message: 'Session uploaded successfully',
      sessionId: sessionData.sessionId,
      data: result.rows[0]
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all sessions - filter by user
app.get('/api/sessions', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    
    let result;
    if (userId) {
      result = await pool.query(
        'SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at DESC',
        [userId]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM sessions ORDER BY created_at DESC'
      );
    }
    
    res.json({ success: true, sessions: result.rows });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create new session from plan
// Create new session from plan
app.post('/api/sessions/start', async (req, res) => {
  try {
    const { plan_id } = req.body;
    const userId = getUserIdFromToken(req);

    // DELETE EMPTY SESSIONS for this user
    if (userId) {
      await pool.query(
        "DELETE FROM sessions WHERE total_attempts = 0 AND user_id = $1",
        [userId]
      );
    } else {
      await pool.query("DELETE FROM sessions WHERE total_attempts = 0");
    }
    console.log('🗑️ Deleted empty sessions');

    // MARK ALL EXISTING ACTIVE SESSIONS AS COMPLETED for this user
    if (userId) {
      await pool.query(
        "UPDATE sessions SET status = 'completed' WHERE status = 'active' AND user_id = $1",
        [userId]
      );
    } else {
      await pool.query("UPDATE sessions SET status = 'completed' WHERE status = 'active'");
    }
    console.log('✅ Marked all previous sessions as completed');

    // GET PLAN FIRST before using plan.name
    const planResult = await pool.query(
      'SELECT * FROM training_plans WHERE id = $1',
      [plan_id]
    );
    
    if (planResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Plan not found' });
    }
    
    const plan = planResult.rows[0];

    // NOW we can use plan.name to generate session name
    const sessionDate = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const existingNames = await pool.query(
      "SELECT name FROM sessions WHERE name LIKE $1",
      [`${plan.name} - ${sessionDate}%`]
    );

    let sessionName = `${plan.name} - ${sessionDate}`;
    if (existingNames.rows.length > 0) {
      sessionName = `${plan.name} - ${sessionDate} (${existingNames.rows.length + 1})`;
    }

    const sessionId = `session_${Date.now()}`;
    
    const shots = {};
    plan.shot_names.forEach((shotName, index) => {
      shots[index + 1] = {
        shotType: shotName,
        attempts: 0,
        goals: 0,
        attemptHistory: []
      };
    });
    
    const query = `
      INSERT INTO sessions (
        session_id, status, start_time, last_updated, 
        duration_minutes, total_attempts, total_goals, 
        total_accuracy, total_shots, shots_data, plan_id, user_id, name
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *;
    `;
    
    const now = new Date().toISOString();
    const values = [
      sessionId, 'active', now, now, 0, 0, 0, 0,
      plan.shot_names.length,
      JSON.stringify(shots),
      plan_id,
      userId,
      sessionName
    ];
    
    const result = await pool.query(query, values);
    
    console.log('✅ Session created from plan:', plan.name);
    res.json({ 
      success: true, 
      session: result.rows[0],
      plan: plan
    });
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Rename session
app.patch('/api/sessions/:id/rename', async (req, res) => {
  try {
    const { name } = req.body;
    const userId = getUserIdFromToken(req);

    const result = await pool.query(
      'UPDATE sessions SET name = $1 WHERE session_id = $2 AND user_id = $3 RETURNING *',
      [name, req.params.id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    res.json({ success: true, session: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get active session - filter by user
app.get('/api/sessions/active', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    
    let result;
    if (userId) {
      result = await pool.query(
        'SELECT * FROM sessions WHERE status = $1 AND user_id = $2 ORDER BY start_time DESC LIMIT 1',
        ['active', userId]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM sessions WHERE status = $1 ORDER BY start_time DESC LIMIT 1',
        ['active']
      );
    }
    
    if (result.rows.length === 0) {
      return res.json({ success: true, session: null });
    }
    
    res.json({ success: true, session: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific session
app.get('/api/sessions/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sessions WHERE session_id = $1',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    res.json({ success: true, session: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all training plans - filter by user + presets
app.get('/api/plans', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    
    let result;
    if (userId) {
      result = await pool.query(
        'SELECT * FROM training_plans WHERE is_preset = true OR user_id = $1 ORDER BY is_preset DESC, name ASC',
        [userId]
      );
    } else {
      result = await pool.query(
        'SELECT * FROM training_plans ORDER BY is_preset DESC, name ASC'
      );
    }
    
    res.json({ success: true, plans: result.rows });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create custom training plan
app.post('/api/plans', async (req, res) => {
  try {
    const { name, description, shot_names } = req.body;
    const userId = getUserIdFromToken(req);
    
    const query = `
      INSERT INTO training_plans (name, description, is_preset, shot_names, user_id)
      VALUES ($1, $2, false, $3, $4)
      RETURNING *;
    `;
    
    const result = await pool.query(query, [name, description, shot_names, userId]);
    
    console.log('✅ Plan created:', name);
    res.json({ success: true, plan: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM training_plans WHERE id = $1',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Plan not found' });
    }
    
    res.json({ success: true, plan: result.rows[0] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get sessions by plan
app.get('/api/plans/:id/sessions', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sessions WHERE plan_id = $1 ORDER BY created_at DESC',
      [req.params.id]
    );
    
    res.json({ success: true, sessions: result.rows });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete session
app.delete('/api/sessions/:id', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    
    const result = await pool.query(
      'DELETE FROM sessions WHERE session_id = $1 AND (user_id = $2 OR $2 IS NULL) RETURNING *',
      [req.params.id, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }
    
    console.log('🗑️ Session deleted:', req.params.id);
    res.json({ success: true, message: 'Session deleted' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete plan
app.delete('/api/plans/:id', async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    
    const result = await pool.query(
      'DELETE FROM training_plans WHERE id = $1 AND (user_id = $2 OR $2 IS NULL) AND is_preset = false RETURNING *',
      [req.params.id, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Plan not found or cannot delete preset' });
    }
    
    console.log('🗑️ Plan deleted:', req.params.id);
    res.json({ success: true, message: 'Plan deleted' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});