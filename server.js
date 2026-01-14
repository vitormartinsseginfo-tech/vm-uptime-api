const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || null;

// ========== INICIALIZAÇÃO FIREBASE ==========
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('✅ Firebase Admin Ativo');
  } catch (err) { console.error('❌ Erro Firebase:', err.message); }
}

// ========== BANCO DE DADOS (Postgres) ==========
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
}

async function initDB() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY, url TEXT, status TEXT DEFAULT 'unknown', 
        response_ms INTEGER DEFAULT 0, last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('✅ Banco de Dados Pronto');
  } catch (err) { console.error('❌ Erro DB:', err.message); }
}
initDB();

// ========== MIDDLEWARES ==========
app.use(express.json());
app.use(cors({
  origin: [
    'https://vulnerability.vm-security.com',
    'https://vm-security.com',
    'https://radar.vm-security.com',
    'https://24x7.vm-security.com'
  ],
  credentials: true
}));

// Middleware de Proteção (Firebase)
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.split('Bearer ')[1];
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (e) { res.status(401).json({ error: 'Sessão expirada' }); }
}

// ========== ROTAS ==========

// Rota de Scan (Usada pela ferramenta de Vulnerabilidade)
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL ausente' });
  try {
    const resp = await axios.get(target, { timeout: 10000, validateStatus: null });
    res.json({ status: resp.status, headers: resp.headers });
  } catch (err) { res.status(500).json({ error: 'Erro ao escanear' }); }
});

// Rotas do Monitor 24x7
app.get('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.json([]);
  const result = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
  res.json(result.rows);
});

app.post('/api/sites', requireAuth, async (req, res) => {
  const { url } = req.body;
  await pool.query('INSERT INTO monitored_domains (url) VALUES ($1)', [url]);
  res.json({ success: true });
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/check-now', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, url FROM monitored_domains');
  for (const site of rows) {
    let status = 'offline', latency = 0;
    try {
      const start = Date.now();
      await axios.get(site.url, { timeout: 5000 });
      latency = Date.now() - start;
      status = 'online';
    } catch (e) { status = 'offline'; }
    await pool.query('UPDATE monitored_domains SET status=$1, response_ms=$2, last_check=NOW() WHERE id=$3', [status, latency, site.id]);
  }
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`🚀 Servidor Unificado VM Security na porta ${PORT}`));
