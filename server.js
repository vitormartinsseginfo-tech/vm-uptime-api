// server.js - VM Security Unified API (compatível /api/sites + CORS 24x7)
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
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT || null; // JSON string
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT || null;
const SERVICE_TOKEN = process.env.SERVICE_TOKEN || null;

// ========== OPTIONAL SUPABASE CLIENT ==========
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
}

// ========== DATABASE (pg Pool) ==========
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
} else {
  console.warn('WARNING: DATABASE_URL not set. Monitor routes will fail without a DB.');
}

// Ensure monitored_domains table exists (if DB configured)
// This table matches the frontend expectations: id, url, status, response_ms, last_check
async function ensureTables() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'unknown',
        response_ms INTEGER DEFAULT 0,
        last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('DB: monitored_domains OK');
  } catch (err) {
    console.error('Error creating tables:', err);
  }
}
ensureTables().catch(console.error);

// ========== FIREBASE ADMIN INIT (OPTIONAL) ==========
if (FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      projectId: serviceAccount.project_id || FIREBASE_PROJECT_ID
    });
    console.log('Firebase Admin inicializado via JSON de serviço.');
  } catch (err) {
    console.error('Erro ao inicializar Firebase Admin com FIREBASE_SERVICE_ACCOUNT:', err);
  }
} else if (FIREBASE_PROJECT_ID) {
  try {
    admin.initializeApp({ projectId: FIREBASE_PROJECT_ID });
    console.log('Firebase Admin inicializado com projectId (sem chave explícita).');
  } catch (err) {
    console.error('Erro ao inicializar Firebase Admin com projectId:', err);
  }
} else {
  console.log('Firebase Admin não configurado. Rotas Firebase não serão validadas.');
}

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cookieParser());

// CORS - incluir 24x7 origin
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
    if (!origin) return cb(null, true); // server-to-server or curl
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Service-Token','X-Vm-Service-Token'],
  exposedHeaders: ['Content-Type','Authorization'],
  optionsSuccessStatus: 204
}));

// ========== AUTH MIDDLEWARE (Híbrido: Cookie || Legacy token || Firebase Token || Service Token) ==========
async function requireAuth(req, res, next) {
  try {
    // 0) Token de serviço (para Workers / crons)
    const svc = req.headers['x-service-token'] || req.headers['x-vm-service-token'];
    if (svc && SERVICE_TOKEN && svc === SERVICE_TOKEN) {
      return next();
    }

    // 1) Cookie-based session
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') {
      return next();
    }

    // 2) Bearer legacy token
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (token === 'vm_access_granted') {
      return next();
    }

    // 3) Firebase token
    if (token && admin.apps && admin.apps.length > 0) {
      try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;
        return next();
      } catch (err) {
        console.warn('Firebase token inválido:', err.message || err);
        return res.status(401).json({ error: 'Token Firebase inválido ou expirado.' });
      }
    }

    return res.status(401).json({ error: 'Não autorizado. Forneça credenciais válidas.' });
  } catch (err) {
    console.error('Erro no requireAuth:', err);
    return res.status(500).json({ error: 'Erro interno de autenticação' });
  }
}

// ========== ROTA DE LOGIN ==========
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const MASTER_PASSWORD = process.env.PANEL_PASSWORD || PANEL_PASSWORD;

    let authenticated = false;

    if (password && password === MASTER_PASSWORD) {
      authenticated = true;
    } else if (email && password && supabase) {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (!error && data?.user) authenticated = true;
    }

    if (authenticated) {
      res.cookie('vm_uptime_auth', 'true', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 24 * 60 * 60 * 1000
      });

      return res.json({ success: true, token: 'vm_access_granted', user: { email: email || 'admin@vm-security.com' } });
    }

    return res.status(401).json({ error: 'Senha ou credenciais incorretas' });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

// ========== ROTA DE LOGOUT ==========
app.post('/api/logout', (req, res) => {
  res.clearCookie('vm_uptime_auth', { httpOnly: true, secure: true, sameSite: 'none' });
  return res.json({ success: true });
});

// ========== ROTA DE DEHASHED / BUSCA (exemplo) ==========
app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  res.json({ total: 0, entries: [], user: req.user || null });
});

// ========== ROTAS DE MONITORAMENTO (compatíveis) ==========

// Legacy route (mantida)
app.get('/api/monitor/domains', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    const result = await pool.query('SELECT id, url, status, response_ms, last_check FROM monitored_domains ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('monitor list error', err);
    res.status(500).json({ error: 'Erro ao buscar domínios' });
  }
});

// Compatibility: frontend uses /api/sites
app.get('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.json([]); // if no DB, return empty list (frontend handles it)
  try {
    const result = await pool.query('SELECT id, url, status, response_ms, last_check FROM monitored_domains ORDER BY id DESC');
    res.json(result.rows.map(r => ({
      id: r.id,
      url: r.url,
      status: r.status,
      response_ms: r.response_ms,
      last_check: r.last_check
    })));
  } catch (err) {
    console.error('/api/sites error', err);
    res.status(500).json({ error: 'Erro ao buscar sites' });
  }
});

app.post('/api/sites', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    // Normalize basic URL
    let u = url.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const insert = await pool.query('INSERT INTO monitored_domains(url) VALUES($1) RETURNING id, url, status, response_ms, last_check', [u]);
    res.json({ success: true, site: insert.rows[0] });
  } catch (err) {
    console.error('monitor insert error', err);
    res.status(500).json({ error: 'Erro ao salvar site' });
  }
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('monitor delete error', err);
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

// Endpoint to trigger an immediate check for all monitored sites
app.post('/api/check-now', requireAuth, async (req, res) => {
  if (!pool) return res.json({ success: true, note: 'No DB configured, nothing to check' });

  try {
    const result = await pool.query('SELECT id, url FROM monitored_domains ORDER BY id ASC');
    const rows = result.rows;

    // sequential checks to avoid bursts
    for (const r of rows) {
      const url = r.url;
      let status = 'offline';
      let latency = 0;
      try {
        const start = Date.now();
        const resp = await axios.get(url, { timeout: 10000, maxRedirects: 3, validateStatus: null });
        latency = Date.now() - start;
        status = (resp.status >= 200 && resp.status < 400) ? 'online' : 'offline';
      } catch (err) {
        status = 'offline';
        latency = 0;
      }

      try {
        await pool.query(
          'UPDATE monitored_domains SET status=$1, response_ms=$2, last_check=NOW() WHERE id=$3',
          [status, latency, r.id]
        );
      } catch (err) {
        console.error('Error updating domain after check:', r.id, err);
      }
    }

    return res.json({ success: true, checked: rows.length });
  } catch (err) {
    console.error('/api/check-now error', err);
    return res.status(500).json({ error: 'Erro ao checar sites' });
  }
});

// ===== ROTA DE SCAN DE VULNERABILIDADES =====
// GET /api/scan?url=<URL>
app.get('/api/scan', requireAuth, async (req, res) => {
  const raw = req.query.url;
  console.log('[SCAN] request received for url:', raw);

  if (!raw) return res.status(400).json({ error: 'URL ausente. Use ?url=https://exemplo.com' });

  let target;
  try {
    target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    const u = new URL(target);
    if (['localhost', '127.0.0.1'].includes(u.hostname)) {
      return res.status(400).json({ error: 'Host não permitido' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'URL inválida' });
  }

  try {
    const response = await axios.get(target, {
      headers: {
        'User-Agent': 'VM-Security-Scanner/1.0 (+https://vm-security.com)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout: 12000,
      maxRedirects: 5,
      validateStatus: null
    });

    const statusCode = response.status;
    const headers = Object.keys(response.headers).reduce((acc, k) => {
      acc[k.toLowerCase()] = response.headers[k];
      return acc;
    }, {});

    const vulns = [];
    let score = 100;

    if (!headers['strict-transport-security']) {
      vulns.push({ name: 'HSTS ausente', severity: 'MEDIUM', desc: 'Strict-Transport-Security header missing' });
      score -= 15;
    }
    if (!headers['content-security-policy']) {
      vulns.push({ name: 'CSP ausente', severity: 'HIGH', desc: 'Content-Security-Policy header missing' });
      score -= 25;
    }
    if (!headers['x-frame-options'] && !(headers['content-security-policy'] && /frame-ancestors/i.test(headers['content-security-policy']))) {
      vulns.push({ name: 'Proteção contra clickjacking ausente', severity: 'MEDIUM', desc: 'No X-Frame-Options or frame-ancestors CSP found' });
      score -= 10;
    }
    if (!headers['x-content-type-options']) {
      vulns.push({ name: 'X-Content-Type-Options ausente', severity: 'LOW', desc: 'Missing header to prevent MIME sniffing' });
      score -= 5;
    }
    if (!headers['referrer-policy']) {
      vulns.push({ name: 'Referrer-Policy ausente', severity: 'LOW', desc: 'Missing Referrer-Policy header' });
      score -= 2;
    }

    const serverHeader = headers['server'] || 'Oculto';
    const powered = headers['x-powered-by'] || headers['x-generator'] || 'Não detectado';

    if (statusCode >= 400) {
      vulns.push({ name: `Resposta HTTP ${statusCode}`, severity: 'INFO', desc: `O alvo respondeu com status ${statusCode}` });
    }

    const result = {
      target,
      status: statusCode,
      score: Math.max(0, score),
      tech: {
        server: serverHeader,
        poweredBy: powered
      },
      vulnerabilities: vulns,
      headers
    };

    console.log('[SCAN] result for', target, 'score', result.score, 'vulns', result.vulnerabilities.length);
    return res.json(result);
  } catch (err) {
    console.error('[SCAN] error for', target, err && (err.message || err));
    if (err.code === 'ECONNABORTED') return res.status(504).json({ error: 'Timeout ao contatar o alvo.' });
    return res.status(502).json({ error: 'Falha ao acessar o alvo. (' + (err.code || 'unknown') + ')' });
  }
});

// ========== START ==========
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
