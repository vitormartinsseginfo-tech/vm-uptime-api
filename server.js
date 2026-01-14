// server.js - VM Security Unified API (Token + Monitor)
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ========== CONFIG ==========
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_KEY = process.env.SUPABASE_KEY || null;

// Supabase client (optional)
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
}

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cookieParser());

// CORS - permita seus domínios de frontend aqui (ou use origin: true para dev)
app.use(cors({
  origin: (origin, cb) => {
    // Ajuste as origens permitidas:
    const allowed = [
      'https://vulnerability.vm-security.com',
      'https://vmleakhunter.vm-security.com',
      'https://vm-security.com',
      // adicionar outras origens necessárias
    ];
    if (!origin || allowed.includes(origin)) return cb(null, true);
    return cb(new Error('CORS not allowed'), false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

// ========== DATABASE ==========
if (!DATABASE_URL) {
  console.warn('WARNING: DATABASE_URL not set. Monitor routes will fail without a DB.');
}
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Ensure monitored_domains table exists
async function ensureTables() {
  if (!DATABASE_URL) return;
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

// ========== AUTH MIDDLEWARE (Híbrido: Cookie ou Token) ==========
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // Se tiver o cookie vm_uptime_auth === 'true' OU token 'vm_access_granted', libera
  if ((req.cookies && req.cookies.vm_uptime_auth === 'true') || token === 'vm_access_granted') {
    return next();
  }
  return res.status(401).json({ error: 'Não autorizado' });
}

// ========== ROTA DE LOGIN (Gera Token + Cookie) ==========
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const MASTER_PASSWORD = process.env.PANEL_PASSWORD || PANEL_PASSWORD;

    let authenticated = false;

    // 1) Senha Mestra
    if (password && password === MASTER_PASSWORD) {
      authenticated = true;
    } 
    // 2) Supabase auth (opcional)
    else if (email && password && supabase) {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (!error && data?.user) authenticated = true;
    }

    if (authenticated) {
      // Define cookie (para clientes que usam sessão/cookie)
      res.cookie('vm_uptime_auth', 'true', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 24 * 60 * 60 * 1000
      });

      // Retorna token também (para frontends que usam token)
      return res.json({ success: true, token: 'vm_access_granted', user: { email: email || 'admin@vm-security.com' } });
    }

    return res.status(401).json({ error: 'Senha incorreta' });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

// ========== ROTA DE LOGOUT ==========
app.post('/api/logout', (req, res) => {
  // Limpa cookie (informa o browser)
  res.clearCookie('vm_uptime_auth', { httpOnly: true, secure: true, sameSite: 'none' });
  return res.json({ success: true });
});

// ========== ROTA DE SCAN (Protegida) ==========
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL obrigatória' });

  const url = target.startsWith('http') ? target : `https://${target}`;
  const results = { target: url, score: 100, vulnerabilities: [], tech: {} };

  try {
    const response = await axios.get(url, { timeout: 8000, validateStatus: false, headers: { 'User-Agent': 'VM-Scanner/1.0' } });
    results.tech.server = response.headers['server'] || 'Não identificado';
    results.tech.poweredBy = response.headers['x-powered-by'] || 'Não identificado';

    // Testes simples
    const tests = [
      { path: '/.env', name: 'Arquivo .env exposto', sev: 'CRITICAL' },
      { path: '/.git/config', name: 'Repositório Git exposto', sev: 'CRITICAL' },
      { path: '/wp-config.php.bak', name: 'Backup de config exposto', sev: 'HIGH' }
    ];

    for (const t of tests) {
      try {
        const c = await axios.get(`${url}${t.path}`, { timeout: 2000, validateStatus: false });
        if (c.status === 200) {
          results.vulnerabilities.push({ name: t.name, severity: t.sev, desc: `O arquivo ${t.path} foi encontrado publicamente.` });
          results.score -= 30;
        }
      } catch (e) { /* ignore file check errors */ }
    }

    if (!response.headers['x-frame-options']) {
      results.vulnerabilities.push({ name: 'Falta de X-Frame-Options', severity: 'LOW', desc: 'Risco de Clickjacking.' });
      results.score -= 5;
    }

    results.score = Math.max(0, results.score);
    res.json(results);
  } catch (err) {
    console.error('scan error', err.message);
    res.status(500).json({ error: 'Erro ao acessar site: ' + err.message });
  }
});

// Rota de verificação simples
app.get('/api/auth/check', requireAuth, (req, res) => {
  res.json({ authenticated: true });
});

// ========== ROTAS DO LEAK HUNTER (MONITORAMENTO) ==========
app.get('/api/monitor/domains', requireAuth, async (req, res) => {
  if (!DATABASE_URL) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    const result = await pool.query('SELECT id, domain, last_count, last_check FROM monitored_domains ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('monitor list error', err);
    res.status(500).json({ error: 'Erro ao buscar domínios' });
  }
});

app.post('/api/monitor/domains', requireAuth, async (req, res) => {
  if (!DATABASE_URL) return res.status(500).json({ error: 'Banco de dados não configurado' });
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
  if (!DATABASE_URL) return res.status(500).json({ error: 'Banco de dados não configurado' });
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('monitor delete error', err);
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

// ========== PLACEHOLDER: DeHashed / Busca ==========
app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  // Implementar integração com DeHashed/Outras APIs aqui se tiver a API Key.
  // Por enquanto retorna vazio para não quebrar frontend.
  res.json({ total: 0, entries: [] });
});

// ========== START ==========
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
});
