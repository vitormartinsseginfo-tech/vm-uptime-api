// server.js - VM Security Unified API (Híbrido: Master password + Supabase + Firebase Admin)
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
async function ensureTables() {
  if (!pool) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        domain TEXT NOT NULL,
        last_count INTEGER DEFAULT 0,
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

// CORS - ajustar origens conforme necessário
app.use(cors({
  origin: (origin, cb) => {
    // Domínios permitidos (adicione outros subdomínios que precisar)
    const allowed = [
      'https://vulnerability.vm-security.com',
      'https://dashboard.vm-security.com',
      'https://vmleakhunter.vm-security.com',
      'https://vm-security.com',
      'https://radar.vm-security.com',
      'https://24x7.vm-security.com',
      'https://www.24x7.vm-security.com'
    ];
    // Requisições sem origin (curl, server-to-server) são permitidas
    if (!origin) return cb(null, true);
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

// service token shortcut (server-to-server)
const SERVICE_TOKEN = process.env.SERVICE_TOKEN || null;

async function requireAuth(req, res, next) {
  try {
    // 0) Token de serviço (para Workers / crons)
    const svc = req.headers['x-service-token'] || req.headers['x-vm-service-token'];
    if (svc && SERVICE_TOKEN && svc === SERVICE_TOKEN) {
      // opcional: set some context like req.isService = true;
      return next();
    }

    // ... existing checks (cookie, legacy, firebase) ...
  } catch (err) { /* ... */ }
}

// ========== AUTH MIDDLEWARE (Híbrido: Cookie || Legacy token || Firebase Token) ==========
async function requireAuth(req, res, next) {
  try {
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') {
      return next();
    }

    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

    if (token === 'vm_access_granted') {
      return next();
    }

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

// ========== ROTA DE DEHASHED / BUSCA ==========
app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  // Aqui você pode implementar integração real com DeHashed ou outra API
  // Por enquanto, retorna vazio para não quebrar frontend
  res.json({ total: 0, entries: [], user: req.user || null });
});

// ========== ROTAS DE MONITORAMENTO ==========
app.get('/api/monitor/domains', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    const result = await pool.query('SELECT id, domain, last_count, last_check FROM monitored_domains ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('monitor list error', err);
    res.status(500).json({ error: 'Erro ao buscar domínios' });
  }
});

app.post('/api/monitor/domains', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    await pool.query('INSERT INTO monitored_domains(domain) VALUES($1)', [domain]);
    res.json({ success: true });
  } catch (err) {
    console.error('monitor insert error', err);
    res.status(500).json({ error: 'Erro ao salvar domínio' });
  }
});

app.delete('/api/monitor/domains/:id', requireAuth, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('monitor delete error', err);
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

// ===== ROTA DE SCAN DE VULNERABILIDADES =====
// GET /api/scan?url=<URL>
// Requer autenticação via requireAuth ou header x-service-token (veja requireAuth)
app.get('/api/scan', requireAuth, async (req, res) => {
  const raw = req.query.url;
  console.log('[SCAN] request received for url:', raw);

  if (!raw) return res.status(400).json({ error: 'URL ausente. Use ?url=https://exemplo.com' });

  // Normaliza e valida a URL básica
  let target;
  try {
    target = raw.trim();
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
    // validação simples
    const u = new URL(target);
    // não permitir internal hosts (opcional)
    if (['localhost', '127.0.0.1'].includes(u.hostname)) {
      return res.status(400).json({ error: 'Host não permitido' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'URL inválida' });
  }

  try {
    // Request ao alvo
    const response = await axios.get(target, {
      headers: {
        'User-Agent': 'VM-Security-Scanner/1.0 (+https://vm-security.com)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout: 12000,
      maxRedirects: 5,
      validateStatus: null // vamos tratar status manualmente
    });

    const statusCode = response.status;
    const headers = Object.keys(response.headers).reduce((acc, k) => {
      acc[k.toLowerCase()] = response.headers[k];
      return acc;
    }, {});

    // Construir lista de vulnerabilidades simples baseada nos headers
    const vulns = [];
    let score = 100;

    // HSTS
    if (!headers['strict-transport-security']) {
      vulns.push({ name: 'HSTS ausente', severity: 'MEDIUM', desc: 'Strict-Transport-Security header missing' });
      score -= 15;
    }

    // CSP
    if (!headers['content-security-policy']) {
      vulns.push({ name: 'CSP ausente', severity: 'HIGH', desc: 'Content-Security-Policy header missing' });
      score -= 25;
    }

    // X-Frame-Options or frame-ancestors
    if (!headers['x-frame-options'] && !(headers['content-security-policy'] && /frame-ancestors/i.test(headers['content-security-policy']))) {
      vulns.push({ name: 'Proteção contra clickjacking ausente', severity: 'MEDIUM', desc: 'No X-Frame-Options or frame-ancestors CSP found' });
      score -= 10;
    }

    // X-Content-Type-Options
    if (!headers['x-content-type-options']) {
      vulns.push({ name: 'X-Content-Type-Options ausente', severity: 'LOW', desc: 'Missing header to prevent MIME sniffing' });
      score -= 5;
    }

    // Referrer-Policy
    if (!headers['referrer-policy']) {
      vulns.push({ name: 'Referrer-Policy ausente', severity: 'LOW', desc: 'Missing Referrer-Policy header' });
      score -= 2;
    }

    // Server disclosure
    const serverHeader = headers['server'] || 'Oculto';
    const powered = headers['x-powered-by'] || headers['x-generator'] || 'Não detectado';

    // Handle non-2xx responses: consider them as potential fingerprinting/info-leak issues but don't fail
    if (statusCode >= 400) {
      vulns.push({ name: `Resposta HTTP ${statusCode}`, severity: 'INFO', desc: `O alvo respondeu com status ${statusCode}` });
      // não reduzir muito o score apenas por status, pois pode ser proteção
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
      headers // retorna os headers crus para diagnóstico no frontend
    };

    console.log('[SCAN] result for', target, 'score', result.score, 'vulns', result.vulnerabilities.length);
    return res.json(result);
  } catch (err) {
    console.error('[SCAN] error for', target, err && (err.message || err));
    // Timeout / DNS / SSL errors
    if (err.code === 'ECONNABORTED') return res.status(504).json({ error: 'Timeout ao contatar o alvo.' });
    return res.status(502).json({ error: 'Falha ao acessar o alvo. (' + (err.code || 'unknown') + ')' });
  }
});

// ========== START ==========
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
