// server.js - VM Security Unified API (Firebase-safe, robust)
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');

const app = express();

// ========== CONFIG ==========
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || null;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_KEY = process.env.SUPABASE_KEY || null;
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT || null; // JSON string (optional)
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT || null;
const SERVICE_TOKEN = process.env.SERVICE_TOKEN || null;

// ========== OPTIONAL SUPABASE CLIENT ==========
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log('Supabase client initialized.');
}

// ========== DATABASE (pg Pool) ==========
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  console.log('Postgres pool created.');
} else {
  console.warn('WARNING: DATABASE_URL not set. Monitor routes will fail without a DB.');
}

// ========== FIREBASE (SAFE INIT) ==========
let firebaseInitialized = false;
if (FIREBASE_SERVICE_ACCOUNT) {
  try {
    // tenta parse seguro
    const svc = JSON.parse(FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(svc),
      projectId: svc.project_id || FIREBASE_PROJECT_ID
    });
    firebaseInitialized = true;
    console.log('Firebase Admin inicializado com sucesso.');
  } catch (err) {
    // não deixe a aplicação cair; apenas logamos
    console.error('Firebase init falhou — FIREBASE_SERVICE_ACCOUNT inválido ou incompleto. Firebase desabilitado.', err.message || err);
    firebaseInitialized = false;
  }
} else {
  console.log('FIREBASE_SERVICE_ACCOUNT não fornecido — Firebase desabilitado.');
}

// ========== MIGRATION / TABLE ENSURE ==========
async function ensureTables() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        url TEXT,
        domain TEXT,
        status TEXT DEFAULT 'unknown',
        response_ms INTEGER DEFAULT 0,
        last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const colsRes = await pool.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'monitored_domains';
    `);
    const cols = colsRes.rows.map(r => r.column_name);
    const hasUrl = cols.includes('url');
    const hasDomain = cols.includes('domain');

    if (!hasUrl && hasDomain) {
      await pool.query('ALTER TABLE monitored_domains ADD COLUMN url TEXT;');
      await pool.query('UPDATE monitored_domains SET url = domain WHERE url IS NULL;');
      console.log('DB: migrated domain -> url (copied values).');
    } else if (hasUrl && hasDomain) {
      await pool.query('UPDATE monitored_domains SET url = domain WHERE url IS NULL AND domain IS NOT NULL;');
      console.log('DB: synchronized url with domain where needed.');
    }

    console.log('DB: monitored_domains ensured.');
  } catch (err) {
    console.error('Erro ensureTables:', err);
  }
}
ensureTables().catch(console.error);

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cookieParser());

// CORS
app.use(cors({
  origin: (origin, cb) => {
    const allowed = [
      'https://vulnerability.vm-security.com',
      'https://dashboard.vm-security.com',
      'https://vmleakhunter.vm-security.com',
      'https://vm-security.com',
      'https://radar.vm-security.com',
      'https://24x7.vm-security.com',
      'https://www.24x7.vm-security.com'
    ];
    if (!origin) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Service-Token','X-Vm-Service-Token'],
  exposedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204
}));

// ========== AUTH MIDDLEWARE (resilient) ==========
async function requireAuth(req, res, next) {
  try {
    // service token
    const svc = req.headers['x-service-token'] || req.headers['x-vm-service-token'];
    if (svc && SERVICE_TOKEN && svc === SERVICE_TOKEN) return next();

    // cookie
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();

    // bearer legacy
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (token === 'vm_access_granted') return next();

    // firebase (apenas se inicializado)
    if (token && firebaseInitialized) {
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        return next();
      } catch (err) {
        console.warn('Firebase token inválido/excedido:', err.message || err);
        return res.status(401).json({ error: 'Token Firebase inválido ou expirado.' });
      }
    }

    // fallback: não autorizado
    return res.status(401).json({ error: 'Não autorizado. Forneça credenciais válidas.' });
  } catch (err) {
    console.error('Erro no requireAuth (unhandled):', err);
    return res.status(500).json({ error: 'Erro interno de autenticação' });
  }
}

// ========== ROUTES ==========
// Root / health
app.get('/', (req, res) => res.send('VM Uptime API OK'));
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString(), firebase: firebaseInitialized }));

// Login / logout (unchanged)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const MASTER_PASSWORD = process.env.PANEL_PASSWORD || PANEL_PASSWORD;
    let authenticated = false;

    if (password && password === MASTER_PASSWORD) authenticated = true;
    else if (email && password && supabase) {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (!error && data?.user) authenticated = true;
    }

    if (authenticated) {
      res.cookie('vm_uptime_auth', 'true', { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24*60*60*1000 });
      return res.json({ success: true, token: 'vm_access_granted', user: { email: email || 'admin@vm-security.com' } });
    }
    return res.status(401).json({ error: 'Senha ou credenciais incorretas' });
  } catch (err) {
    console.error('Erro /api/login:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
});
app.post('/api/logout', (req, res) => { res.clearCookie('vm_uptime_auth'); return res.json({ success: true }); });

// Placeholder dehashe
app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  res.json({ total: 0, entries: [], user: req.user || null });
});

// Monitor routes (compatibility)
app.get('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
    const sites = result.rows.map(r => ({ id: r.id, url: r.url || r.domain || '', status: r.status || 'unknown', response_ms: r.response_ms || 0, last_check: r.last_check }));
    res.json(sites);
  } catch (err) {
    console.error('/api/sites error:', err);
    res.status(500).json({ error: 'Erro ao buscar sites' });
  }
});

app.post('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'DB não configurado' });
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    let u = url.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const insert = await pool.query('INSERT INTO monitored_domains (url, domain, status) VALUES ($1, $1, $2) RETURNING id, url, status, response_ms, last_check', [u, 'unknown']);
    res.json({ success: true, site: insert.rows[0] });
  } catch (err) {
    console.error('monitor insert error:', err);
    res.status(500).json({ error: 'Erro ao salvar site' });
  }
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'DB não configurado' });
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('monitor delete error:', err);
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

app.post('/api/check-now', requireAuth, async (req, res) => {
  if (!pool) return res.json({ success: true, note: 'No DB configured, nothing to check' });
  try {
    const result = await pool.query('SELECT id, url FROM monitored_domains ORDER BY id ASC');
    const rows = result.rows;
    for (const r of rows) {
      const url = r.url;
      let status = 'offline', latency = 0;
      try {
        const start = Date.now();
        const resp = await axios.get(url, { timeout: 10000, maxRedirects: 3, validateStatus: null });
        latency = Date.now() - start;
        status = (resp.status >= 200 && resp.status < 400) ? 'online' : 'offline';
      } catch (err) {
        status = 'offline'; latency = 0;
      }
      try { await pool.query('UPDATE monitored_domains SET status=$1, response_ms=$2, last_check=NOW() WHERE id=$3', [status, latency, r.id]); } catch (err) { console.error('Error updating domain after check:', r.id, err); }
    }
    return res.json({ success: true, checked: rows.length });
  } catch (err) {
    console.error('/api/check-now error:', err);
    return res.status(500).json({ error: 'Erro ao checar sites' });
  }
});

// Scan route (unchanged)
app.get('/api/scan', requireAuth, async (req, res) => {
  const raw = req.query.url;
  if (!raw) return res.status(400).json({ error: 'URL ausente. Use ?url=https://exemplo.com' });
  let target;
  try {
    target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    const u = new URL(target);
    if (['localhost','127.0.0.1'].includes(u.hostname)) return res.status(400).json({ error: 'Host não permitido' });
  } catch (err) { return res.status(400).json({ error: 'URL inválida' }); }

  try {
    const response = await axios.get(target, { headers: { 'User-Agent': 'VM-Security-Scanner/1.0 (+https://vm-security.com)', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' }, timeout: 12000, maxRedirects: 5, validateStatus: null });
    const statusCode = response.status;
    const headers = Object.keys(response.headers).reduce((acc,k)=>{ acc[k.toLowerCase()] = response.headers[k]; return acc; }, {});
    const vulns = []; let score = 100;
    if (!headers['strict-transport-security']) { vulns.push({ name:'HSTS ausente', severity:'MEDIUM' }); score -= 15; }
    if (!headers['content-security-policy']) { vulns.push({ name:'CSP ausente', severity:'HIGH' }); score -= 25; }
    if (!headers['x-frame-options'] && !(headers['content-security-policy'] && /frame-ancestors/i.test(headers['content-security-policy']))) { vulns.push({ name:'Proteção contra clickjacking ausente', severity:'MEDIUM' }); score -= 10; }
    if (!headers['x-content-type-options']) { vulns.push({ name:'X-Content-Type-Options ausente', severity:'LOW' }); score -= 5; }
    if (!headers['referrer-policy']) { vulns.push({ name:'Referrer-Policy ausente', severity:'LOW' }); score -= 2; }
    if (statusCode >= 400) vulns.push({ name:`Resposta HTTP ${statusCode}`, severity:'INFO', desc:`O alvo respondeu com status ${statusCode}` });
    const result = { target, status: statusCode, score: Math.max(0,score), tech: { server: headers['server'] || 'Oculto' }, vulnerabilities: vulns, headers };
    return res.json(result);
  } catch (err) {
    console.error('[SCAN] error for', target, err && (err.message || err));
    if (err.code === 'ECONNABORTED') return res.status(504).json({ error: 'Timeout ao contatar o alvo.' });
    return res.status(502).json({ error: 'Falha ao acessar o alvo. (' + (err.code || 'unknown') + ')' });
  }
});

// Global error handler (logs)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && (err.stack || err.message || err));
  res.status(500).json({ error: 'Unhandled server error' });
});

// START
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT} - firebaseInitialized=${firebaseInitialized}`);
});
