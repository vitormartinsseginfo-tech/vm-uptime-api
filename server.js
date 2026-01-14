// server.js - VM Uptime / Vulnerability unified API (CORS + preflight + logs)
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || null;

// ========== WHITELIST CORS ==========
const CORS_WHITELIST = [
  'https://vulnerability.vm-security.com',
  'https://vm-security.com',
  'https://radar.vm-security.com',
  'https://24x7.vm-security.com',
  'https://www.24x7.vm-security.com'
];

// ========== FIREBASE ==========
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: serviceAccount.project_id || process.env.FIREBASE_PROJECT_ID
    });
    console.log('✅ Firebase Admin Ativo');
  } catch (err) {
    console.error('❌ Erro Firebase:', err.message);
  }
} else {
  console.warn('⚠️ FIREBASE_SERVICE_ACCOUNT não definido — autenticação Firebase desativada');
}

// ========== DB (Postgres) ==========
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
  console.log('✅ Postgres pool criado');
}

async function initDB() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        url TEXT,
        status TEXT DEFAULT 'unknown',
        response_ms INTEGER DEFAULT 0,
        last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Tabela monitored_domains pronta');
  } catch (err) {
    console.error('❌ Erro initDB:', err.message);
  }
}
initDB().catch(console.error);

// ========== MIDDLEWARES ==========
app.use(express.json());
app.use(cookieParser());

// CORS config: responde apenas para origens permitidas e aceita preflight
const corsOptions = {
  origin: (origin, callback) => {
    // allow requests with no origin (like server-to-server, curl, mobile)
    if (!origin) return callback(null, true);
    if (CORS_WHITELIST.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Service-Token']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // preflight handler

// safety: also set headers explicitly (ensures presence even on errors)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && CORS_WHITELIST.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Service-Token');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// ========== AUTH MIDDLEWARE ==========
async function requireAuth(req, res, next) {
  try {
    // 1) cookie legacy (optional)
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();

    // 2) legacy static token
    const authHeader = req.headers['authorization'] || '';
    const maybeToken = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (maybeToken === 'vm_access_granted') return next();

    // 3) Firebase token (if initialized)
    if (maybeToken && admin.apps.length > 0) {
      try {
        const decoded = await admin.auth().verifyIdToken(maybeToken);
        req.user = decoded;
        return next();
      } catch (err) {
        console.warn('Firebase verifyIdToken falhou:', err.message);
        return res.status(401).json({ error: 'Token inválido' });
      }
    }

    return res.status(401).json({ error: 'Não autorizado' });
  } catch (err) {
    console.error('requireAuth error:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'Erro interno de autenticação' });
  }
}

// ========== ROUTAS ==========

app.get('/', (req, res) => res.send('VM Uptime / Vulnerability API'));

// Rota de Scan (usada pela ferramenta Vulnerability)
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL ausente' });

  try {
    const response = await axios.get(target, { timeout: 10000, validateStatus: null });
    return res.json({ target, status: response.status, headers: response.headers });
  } catch (err) {
    console.error('Scan error for', target, err.message);
    return res.status(500).json({ error: 'Erro ao escanear', detail: err.message });
  }
});

// 24x7: listar sites
app.get('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
    return res.json(result.rows);
  } catch (err) {
    console.error('/api/sites error:', err.message);
    return res.status(500).json({ error: 'DB error' });
  }
});

// adicionar site
app.post('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'DB not configured' });
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing url' });
  try {
    const normalized = /^https?:\/\//i.test(url) ? url.trim() : `https://${url.trim()}`;
    const insert = await pool.query('INSERT INTO monitored_domains (url) VALUES ($1) RETURNING id', [normalized]);
    return res.json({ success: true, id: insert.rows[0].id });
  } catch (err) {
    console.error('/api/sites POST error:', err.message);
    return res.status(500).json({ error: 'Insert error' });
  }
});

// deletar site
app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'DB not configured' });
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    return res.json({ success: true });
  } catch (err) {
    console.error('/api/sites DELETE error:', err.message);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

// forçar check-now
app.post('/api/check-now', requireAuth, async (req, res) => {
  if (!pool) return res.json({ success: true, note: 'DB not configured' });
  try {
    const { rows } = await pool.query('SELECT id, url FROM monitored_domains');
    for (const site of rows) {
      let status = 'offline', latency = 0;
      try {
        const start = Date.now();
        const resp = await axios.get(site.url, { timeout: 8000, validateStatus: null });
        latency = Date.now() - start;
        status = (resp.status >= 200 && resp.status < 400) ? 'online' : 'offline';
      } catch (err) {
        console.warn('check-now error for', site.url, err.message);
        status = 'offline';
      }
      try {
        await pool.query('UPDATE monitored_domains SET status=$1, response_ms=$2, last_check=NOW() WHERE id=$3', [status, latency, site.id]);
      } catch (dbErr) {
        console.error('DB update failed for', site.id, dbErr.message);
      }
    }
    return res.json({ success: true });
  } catch (err) {
    console.error('/api/check-now error:', err.message);
    return res.status(500).json({ error: 'Check error' });
  }
});

// error handler
app.use((err, req, res, next) => {
  console.error('Unhandled exception:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'Unhandled server error' });
});

app.listen(PORT, () => console.log(`🚀 Servidor Unificado VM Security na porta ${PORT}`));
