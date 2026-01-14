// server.js
// VM Security unified API (Monitor + Radar proxy + Contact Hunter proxy + Vulnerability scanner)
// Single hybrid login: PANEL_PASSWORD (master) OR Supabase email+password
// Env vars expected:
// DATABASE_URL (required), PANEL_PASSWORD, SUPABASE_URL, SUPABASE_KEY,
// RADAR_WORKER_URL, SPY_URL, SERPAPI_KEY, DEHASHED_API_KEY, DEHASHED_API_SECRET, FRONTEND_URL, PORT

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
const SPY_URL = process.env.SPY_URL || null;
const RADAR_WORKER_URL = process.env.RADAR_WORKER_URL || null;
const SERPAPI_KEY = process.env.SERPAPI_KEY || null;
const DEHASHED_API_KEY = process.env.DEHASHED_API_KEY || null;
const DEHASHED_API_SECRET = process.env.DEHASHED_API_SECRET || null;
const FRONTEND_URL = process.env.FRONTEND_URL || true; // true => reflect origin for cors
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_KEY = process.env.SUPABASE_KEY || null;

// Basic validation
if (!DATABASE_URL) {
  console.error('ERRO: DATABASE_URL não configurada. Defina DATABASE_URL no ambiente.');
  process.exit(1);
}

// Supabase client (optional)
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log('Supabase client inicializado.');
} else {
  console.log('Supabase não configurado (SUPABASE_URL / SUPABASE_KEY faltando). Login por email estará desativado.');
}

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS allowing credentials; for production you can set FRONTEND_URL to your exact domain
app.use(cors({
  origin: FRONTEND_URL === true ? true : FRONTEND_URL,
  credentials: true
}));

// ========== DATABASE ==========
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create tables if not exist (safe to run repeatedly)
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitor_sites (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'pendente',
        last_check TIMESTAMP,
        response_ms INTEGER DEFAULT 0
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        domain TEXT UNIQUE NOT NULL,
        created_at timestamptz DEFAULT now()
      );
    `);

    console.log('Tabelas verificadas/criadas.');
  } catch (err) {
    console.error('Erro ao criar tabelas iniciais:', err);
  }
})();

// ========== AUTH MIDDLEWARE ==========
function requireAuth(req, res, next) {
  try {
    if (req.cookies && req.cookies.vm_uptime_auth === 'true') {
      return next();
    }
    return res.status(401).json({ error: 'Unauthorized' });
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// ========== LOGIN (UNIFICADA) ==========
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const MASTER_PASSWORD = process.env.PANEL_PASSWORD || PANEL_PASSWORD;

    // 1) Master password (hunter style) - allows login by sending only password
    if (password && password === MASTER_PASSWORD && (!email || email === 'master@vm-security.com')) {
      res.cookie('vm_uptime_auth', 'true', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // secure only in prod (render provides https)
        sameSite: 'none',
        maxAge: 24 * 60 * 60 * 1000
      });
      return res.json({ success: true, user: { name: 'Admin', email: 'master@vm-security.com' } });
    }

    // 2) If email+password provided and Supabase configured, try Supabase auth
    if (email && password && supabase) {
      try {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (!error && data && data.user) {
          res.cookie('vm_uptime_auth', 'true', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
            maxAge: 24 * 60 * 60 * 1000
          });
          return res.json({ success: true, user: { email: data.user.email } });
        }
      } catch (supErr) {
        console.error('Supabase login error:', supErr);
      }
    }

    // 3) Fallback: unauthorized
    return res.status(401).json({ error: 'Senha incorreta' });
  } catch (err) {
    console.error('LOGIN ERROR:', err && err.message);
    return res.status(500).json({ error: 'Erro no servidor durante login' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('vm_uptime_auth');
  res.json({ success: true });
});

app.get('/api/auth/check', (req, res) => {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') {
    return res.json({ authenticated: true });
  }
  return res.status(401).json({ authenticated: false });
});

// ========== MONITOR / SITES ==========
app.get('/api/sites', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM monitor_sites ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/sites error:', err);
    res.status(500).json({ error: 'Erro ao buscar sites' });
  }
});

app.post('/api/sites', requireAuth, async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL é obrigatória' });
    await pool.query('INSERT INTO monitor_sites (url) VALUES ($1)', [url]);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/sites error:', err);
    res.status(500).json({ error: 'Erro ao adicionar site' });
  }
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM monitor_sites WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/sites/:id error:', err);
    res.status(500).json({ error: 'Erro ao remover site' });
  }
});

app.post('/api/check-now', requireAuth, async (req, res) => {
  try {
    await checkAll();
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/check-now error:', err);
    res.status(500).json({ error: 'Erro ao rodar checagem' });
  }
});

// ========== HEALTH ==========
app.get('/health', (req, res) => res.json({ ok: true }));

// ========== CHECK FUNCTIONS ==========
async function checkDirect(url) {
  const start = Date.now();
  const resp = await axios.get(url, {
    timeout: 15000,
    headers: {
      'User-Agent': 'VM-Uptime-Monitor/1.0',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    },
    maxRedirects: 5,
    validateStatus: null
  });
  return {
    ok: resp && resp.status >= 200 && resp.status < 400,
    status: resp ? resp.status : null,
    latency: Date.now() - start
  };
}

async function checkViaSpy(targetUrl) {
  if (!SPY_URL) return { ok: false, status: null, latency: null };
  const start = Date.now();
  const resp = await axios.get(`${SPY_URL}?url=${encodeURIComponent(targetUrl)}`, { timeout: 15000, validateStatus: null });
  if (resp && resp.data) {
    return {
      ok: resp.data.ok === true,
      status: resp.data.status || null,
      latency: resp.data.latency_ms || (Date.now() - start)
    };
  }
  return { ok: false, status: resp ? resp.status : null, latency: Date.now() - start };
}

async function checkAll() {
  try {
    const result = await pool.query('SELECT * FROM monitor_sites');
    for (let site of result.rows) {
      try {
        let r;
        if (SPY_URL && site.url.includes('vm-security.com')) {
          r = await checkViaSpy(site.url);
        } else {
          r = await checkDirect(site.url);
        }
        const newStatus = r.ok ? 'online' : 'offline';
        await pool.query(
          'UPDATE monitor_sites SET status = $1, last_check = NOW(), response_ms = $2 WHERE id = $3',
          [newStatus, Math.round(r.latency || 0), site.id]
        );
        console.log(`${r.ok ? '✅' : '❌'} ${site.url} -> ${newStatus} (status=${r.status} latency=${r.latency}ms)`);
      } catch (siteErr) {
        console.error('Erro checando site', site.url, siteErr && siteErr.message);
        await pool.query(
          'UPDATE monitor_sites SET status = $1, last_check = NOW(), response_ms = $2 WHERE id = $3',
          ['offline', 0, site.id]
        );
      }
    }
  } catch (err) {
    console.error('Erro checkAll:', err);
  }
}

// Schedule checks
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  checkAll().catch(e => console.error('checkAll interval error:', e));
}, CHECK_INTERVAL_MS);

setTimeout(() => {
  checkAll().catch(e => console.error('checkAll initial error:', e));
}, 2000);

// ========== CONTACT HUNTER PROXY ==========
app.get('/api/proxy', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'url query param missing' });

  try {
    const resp = await axios.get(target, {
      timeout: 15000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VM-Contact-Hunter',
        'Accept': 'text/html,application/xhtml+xml'
      },
      maxRedirects: 5,
      responseType: 'text',
      validateStatus: null
    });
    res.set('Content-Type', 'text/html; charset=utf-8');
    return res.status(200).send(resp.data);
  } catch (err) {
    console.error('proxy error for', target, err && err.message);
    return res.status(500).json({ error: 'Erro ao buscar o site (proxy)' });
  }
});

// ========== RADAR / SERPAPI WRAPPER ==========
app.get('/api/radar', requireAuth, async (req, res) => {
  const query = req.query.query || req.query.q;
  if (!query) return res.status(400).json({ error: 'Query missing' });

  const workerBaseUrl = RADAR_WORKER_URL || 'https://radar.vm-security.workers.dev';
  const workerUrl = `${workerBaseUrl}/?q=${encodeURIComponent(query)}&num=20`;

  try {
    console.log("Tentando acessar:", workerUrl);
    const response = await axios.get(workerUrl, { 
      timeout: 15000,
      headers: { 'User-Agent': 'VM-Radar-Proxy' } 
    });
    return res.json(response.data);
  } catch (err) {
    console.error('Erro no Radar:', err.message);
    return res.status(500).json({ 
      error: 'Erro ao conectar com o motor de busca',
      details: err.message,
      target: workerUrl 
    });
  }
});

// ========== DEHASHED WRAPPER ==========
app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  const { query, type } = req.query;
  if (!query) return res.status(400).json({ error: 'Query é obrigatória' });
  
  if (!DEHASHED_API_KEY || !DEHASHED_API_SECRET) {
    return res.status(500).json({ error: 'API DeHashed não configurada no Render' });
  }

  const auth = 'Basic ' + Buffer.from(`${DEHASHED_API_KEY}:${DEHASHED_API_SECRET}`).toString('base64');
  const typeMap = {
    all: '',
    email: 'email',
    username: 'username',
    password: 'password',
    hashed_password: 'hashed_password',
    ip_address: 'ip_address',
    name: 'name',
    address: 'address',
    phone: 'phone',
    vin: 'vin',
    domain_scan: 'domain_scan'
  };
  const filter = typeMap[type] || '';
  const finalQuery = filter ? `${filter}:"${query}"` : query;

  try {
    const url = `https://api.dehashed.com/search?query=${encodeURIComponent(finalQuery)}`;
    const resp = await axios.get(url, { headers: { Authorization: auth, Accept: 'application/json' }, timeout: 25000 });
    res.json(resp.data);
  } catch (err) {
    console.error('Dehashed error:', err && err.message);
    res.status(500).json({ error: 'Erro DeHashed', details: err.message });
  }
});

// ========== MONITORED DOMAINS ==========
app.get('/api/monitor/domains', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/monitor/domains error:', err);
    res.status(500).json({ error: 'Erro ao buscar domains' });
  }
});

app.post('/api/monitor/domains', requireAuth, async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domínio obrigatório' });
  try {
    await pool.query('INSERT INTO monitored_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING', [domain]);
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/monitor/domains error:', err);
    res.status(500).json({ error: 'Erro ao inserir domain' });
  }
});

app.delete('/api/monitor/domains/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('DELETE /api/monitor/domains/:id error:', err);
    res.status(500).json({ error: 'Erro ao remover domain' });
  }
});

// ========== VULNERABILITY SCANNER ==========
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL é obrigatória' });

  const url = target.startsWith('http') ? target : `https://${target}`;
  const results = { target: url, score: 100, vulnerabilities: [], tech: {} };

  try {
    const response = await axios.get(url, { timeout: 10000, validateStatus: false, headers: { 'User-Agent': 'VM-Security-Scanner/1.0' } });

    results.tech.server = response.headers['server'] || 'Não identificado';
    results.tech.poweredBy = response.headers['x-powered-by'] || 'Não identificado';

    const pathsToTest = [
      { path: '/.env', name: 'Arquivo de Configuração (.env)', severity: 'CRITICAL', desc: 'Contém senhas de banco de dados e chaves de API.' },
      { path: '/.git/config', name: 'Repositório Git Exposto', severity: 'CRITICAL', desc: 'Permite baixar todo o código-fonte do site.' },
      { path: '/wp-config.php.bak', name: 'Backup de Configuração WordPress', severity: 'HIGH', desc: 'Pode conter credenciais de acesso ao site.' },
      { path: '/phpinfo.php', name: 'PHP Info Exposto', severity: 'MEDIUM', desc: 'Revela detalhes internos do servidor para hackers.' }
    ];

    for (const item of pathsToTest) {
      try {
        const check = await axios.get(`${url}${item.path}`, { timeout: 3000, validateStatus: false });
        if (check.status === 200) {
          results.vulnerabilities.push(item);
          results.score -= 25;
        }
      } catch (e) { /* ignore */ }
    }

    const cookies = response.headers['set-cookie'];
    if (cookies) {
      const insecure = cookies.some(c => !c.toLowerCase().includes('httponly') || !c.toLowerCase().includes('secure'));
      if (insecure) {
        results.vulnerabilities.push({
          name: 'Cookies Inseguros',
          severity: 'MEDIUM',
          desc: 'Cookies de sessão sem flag HttpOnly/Secure podem ser roubados por scripts maliciosos.'
        });
        results.score -= 10;
      }
    }

    if (!response.headers['x-frame-options']) {
      results.vulnerabilities.push({
        name: 'Falta de Proteção contra Clickjacking',
        severity: 'LOW',
        desc: 'Permite que seu site seja exibido dentro de outros sites para enganar usuários.'
      });
      results.score -= 5;
    }

    if (results.score < 0) results.score = 0;
    res.json(results);
  } catch (error) {
    console.error('Erro no scan:', error && error.message);
    res.status(500).json({ error: 'Erro ao escanear o site: ' + (error && error.message) });
  }
});

// ========== SIMPLE TEST ROUTES ==========
app.get('/api/auth-test', async (req, res) => {
  res.json({ status: "API up. Supabase configured: " + !!supabase });
});

// ========== START SERVER ==========
app.listen(PORT, () => {
  console.log(`VM Security API rodando na porta ${PORT}`);
});
