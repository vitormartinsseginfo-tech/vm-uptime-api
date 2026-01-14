// server.js - VM Uptime / Vulnerability unified API (CORS + preflight + header-audit)
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
    if (!origin) return callback(null, true); // server-to-server
    if (CORS_WHITELIST.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Service-Token']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // preflight

// set explicit headers to ensure preflight passes
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
    // cookie legacy
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();

    // static token fallback
    const authHeader = req.headers['authorization'] || '';
    const maybeToken = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
    if (maybeToken === 'vm_access_granted') return next();

    // Firebase token
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

// ========== HELPERS DE AUDIT ==========
function analyzeHeaders(target, headers) {
  const vulns = [];

  function push(name, desc, severity) {
    vulns.push({ name, desc, severity });
  }

  // HSTS
  if (!headers['strict-transport-security']) {
    push('HSTS Ausente', 'O site não está enviando Strict-Transport-Security. Recomendado para forçar HTTPS.', 'HIGH');
  } else {
    // opcional: checar max-age
    try {
      const hsts = headers['strict-transport-security'];
      if (!/max-age=\d+/i.test(hsts)) {
        push('HSTS sem max-age', 'Strict-Transport-Security presente mas sem max-age explícito.', 'MEDIUM');
      }
    } catch (e) {}
  }

  // X-Frame-Options
  if (!headers['x-frame-options'] && !headers['content-security-policy']) {
    push('X-Frame-Options ausente', 'Sem proteção contra clickjacking (X-Frame-Options ou CSP frame-ancestors).', 'HIGH');
  }

  // Content-Security-Policy
  if (!headers['content-security-policy']) {
    push('CSP ausente', 'Content-Security-Policy ausente — expõe o site a riscos de XSS', 'HIGH');
  }

  // X-Content-Type-Options
  if (!headers['x-content-type-options']) {
    push('X-Content-Type-Options ausente', 'Sem X-Content-Type-Options: possibile risco de MIME sniffing.', 'LOW');
  }

  // Referrer-Policy
  if (!headers['referrer-policy']) {
    push('Referrer-Policy ausente', 'Sem política de referrer definida.', 'LOW');
  }

  // Permissions-Policy / Feature-Policy
  if (!headers['permissions-policy'] && !headers['feature-policy']) {
    push('Permissions-Policy ausente', 'Sem Permissions-Policy / Feature-Policy.', 'LOW');
  }

  // HTTP (inseguro)
  if (target.startsWith('http://')) {
    push('Uso de HTTP (inseguro)', 'O alvo usa HTTP e não HTTPS — tráfego não criptografado.', 'CRITICAL');
  }

  // Cookies sem Secure/HttpOnly check (simples)
  if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']];
    cookies.forEach(c => {
      if (!/HttpOnly/i.test(c) || !/Secure/i.test(c)) {
        push('Cookie sem HttpOnly/Secure', 'Um cookie foi encontrado sem flags HttpOnly ou Secure.', 'MEDIUM');
      }
    });
  }

  // Exemplo: identificar tecnologia via headers
  // (detecção heurística simples)
  return { vulns, heuristics: {} };
}

function detectServerTech(headers) {
  const out = { server: 'Não detectado', tech: 'Não detectado' };
  if (headers['server']) {
    const s = headers['server'].toLowerCase();
    if (s.includes('cloudflare')) out.server = 'Cloudflare';
    else if (s.includes('nginx')) out.server = 'nginx';
    else if (s.includes('apache')) out.server = 'Apache';
    else out.server = headers['server'];
  } else {
    // heurísticas
    if (headers['x-amz-id-2'] || headers['x-amz-request-id']) out.server = 'Amazon S3/CloudFront';
    if (headers['x-nf-request-id']) out.server = 'Netlify';
    if (headers['x-via'] || headers['via']) out.server = headers['via'];
  }

  if (headers['x-powered-by']) {
    out.tech = headers['x-powered-by'];
  } else if (headers['set-cookie']) {
    const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']];
    if (cookies.some(c => c.includes('PHPSESSID'))) out.tech = 'PHP';
    else if (cookies.some(c => c.toLowerCase().includes('asp.net'))) out.tech = 'ASP.NET';
  } else {
    // basic guess
    if (headers['x-powered-by'] === undefined && out.server.toLowerCase().includes('nginx')) out.tech = 'Possivelmente PHP / Node (via nginx)';
  }
  return out;
}

// scoring weights
const SCORE_WEIGHTS = { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 5 };

// ========== ROUTAS ==========
app.get('/', (req, res) => res.send('VM Uptime / Vulnerability API'));

// Rota de Scan (usada pela ferramenta Vulnerability)
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL ausente' });

  try {
    // fetch target
    const response = await axios.get(target, { timeout: 10000, validateStatus: null, headers: { 'User-Agent': 'VM-Security-Scanner/1.0' } });
    const headers = {};
    // normalize headers to lowercase keys
    Object.keys(response.headers).forEach(k => headers[k.toLowerCase()] = response.headers[k]);

    // detect server/tech
    const detected = detectServerTech(headers);

    // analyze headers
    const { vulns } = analyzeHeaders(target, headers);

    // map vulnerabilities to expected format (name, desc, severity)
    const mapped = vulns.map(v => ({
      name: v.name,
      desc: v.desc,
      severity: (v.severity || 'LOW').toString().toUpperCase()
    }));

    // calculate score
    let penalty = 0;
    mapped.forEach(v => {
      const w = SCORE_WEIGHTS[v.severity] || 5;
      penalty += w;
    });
    const score = Math.max(0, 100 - penalty);

    return res.json({
      target,
      status: response.status,
      detected_server: detected.server,
      detected_tech: detected.tech,
      vulnerabilities: mapped,
      score
    });
  } catch (err) {
    console.error('Scan error for', target, err && err.message ? err.message : err);
    return res.status(500).json({ error: 'Erro ao escanear', detail: err && err.message ? err.message : '' });
  }
});

// 24x7 endpoints (unchanged logic)
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
