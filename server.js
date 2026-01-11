// server.js
// VM Uptime API - Express + Postgres
// Features:
// - Login with PANEL_PASSWORD -> HttpOnly cookie
// - CRUD for monitored sites (GET/POST/DELETE /api/sites)
// - Force check endpoint POST /api/check-now (protected)
// - Periodic checkAll() every 5 minutes
// - Uses a Cloudflare Worker (SPY_URL) for domains under vm-security.com to bypass Cloudflare IP blocks
// Env vars required:
// - DATABASE_URL (postgres connection string)
// - PANEL_PASSWORD (recommended)
// - SPY_URL (URL of your Cloudflare Worker, e.g. https://monitor24x7.vm-security.workers.dev) - optional fallback is undefined
// - FRONTEND_URL (optional) - if set, used by CORS origin; otherwise origin reflected

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

// CONFIG
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SPY_URL = process.env.SPY_URL || 'https://monitor24x7.vm-security.workers.dev'; // set your worker URL in env
const FRONTEND_URL = process.env.FRONTEND_URL || true; // set to your Cloudflare Pages URL to lock origin, or true to reflect

if (!DATABASE_URL) {
  console.error('ERRO: a variável de ambiente DATABASE_URL não está definida.');
  process.exit(1);
}

// Postgres pool (Render & many hosts require SSL false rejectAuthorized)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// CORS - allow credentials, reflect origin or restrict to FRONTEND_URL
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// Initialize DB table (adds response_ms column)
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP,
    response_ms INTEGER
  )
`).catch(err => console.error('Erro ao criar tabela monitor_sites:', err));

// --- Authentication (login) ---
app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Senha requerida' });

  if (password === PANEL_PASSWORD) {
    // HttpOnly cookie; secure:true requires HTTPS (Render uses HTTPS)
    res.cookie('vm_uptime_auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    });
    return res.json({ success: true });
  } else {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
});

function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  return res.status(401).json({ error: 'Não autorizado' });
}

// --- API routes ---
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

// Force immediate check (protected)
app.post('/api/check-now', requireAuth, async (req, res) => {
  try {
    console.log('🔄 Forçando checagem manual via /api/check-now');
    await checkAll();
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/check-now error:', err);
    res.status(500).json({ error: 'Erro ao rodar checagem' });
  }
});

// health endpoint
app.get('/health', (req, res) => res.json({ ok: true }));

// --- Checking logic ---
// Helper: check a URL directly
async function checkDirect(url) {
  const start = Date.now();
  const resp = await axios.get(url, {
    timeout: 15000,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VM-Uptime-Monitor',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8'
    },
    maxRedirects: 5,
    validateStatus: null
  });
  const latency = Date.now() - start;
  const ok = resp && resp.status >= 200 && resp.status < 400;
  return { ok, status: resp ? resp.status : null, latency };
}

// Helper: ask the Cloudflare Worker (spy) to check for us
async function checkViaSpy(targetUrl) {
  const start = Date.now();
  const workerUrl = `${SPY_URL}?url=${encodeURIComponent(targetUrl)}`;
  const resp = await axios.get(workerUrl, { timeout: 15000, validateStatus: null });
  const latency = Date.now() - start;
  // Worker returns JSON: { target, status, ok, latency_ms, ... }
  if (resp && resp.data) {
    return {
      ok: resp.data.ok === true,
      status: resp.data.status || null,
      latency: resp.data.latency_ms || latency
    };
  }
  return { ok: false, status: resp ? resp.status : null, latency };
}

async function checkAll() {
  try {
    const result = await pool.query('SELECT * FROM monitor_sites');
    const sites = result.rows;

    for (let site of sites) {
      try {
        let isOnline = false;
        let statusCode = null;
        let latency = null;

        // If it's our domain (vm-security.com) or subdomains, route via Worker to avoid IP-blocking
        if (site.url.includes('vm-security.com') && SPY_URL) {
          const r = await checkViaSpy(site.url);
          isOnline = r.ok;
          statusCode = r.status;
          latency = r.latency;
        } else {
          const r = await checkDirect(site.url);
          isOnline = r.ok;
          statusCode = r.status;
          latency = r.latency;
        }

        const newStatus = isOnline ? 'online' : 'offline';
        await pool.query(
          'UPDATE monitor_sites SET status = $1, last_check = NOW(), response_ms = $2 WHERE id = $3',
          [newStatus, latency || null, site.id]
        );
        console.log(`${isOnline ? '✅' : '❌'} ${site.url} -> ${newStatus} (status=${statusCode} latency=${latency}ms)`);
      } catch (siteErr) {
        console.error('Erro checando site', site.url, siteErr && siteErr.message);
        await pool.query(
          'UPDATE monitor_sites SET status = $1, last_check = NOW(), response_ms = $2 WHERE id = $3',
          ['offline', null, site.id]
        );
      }
    }
  } catch (err) {
    console.error('Erro checkAll:', err);
  }
}

// Periodic scheduler: every 5 minutes
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  checkAll().catch(e => console.error('checkAll interval error:', e));
}, CHECK_INTERVAL_MS);

// Initial run shortly after startup
setTimeout(() => {
  checkAll().catch(e => console.error('checkAll initial error:', e));
}, 2000);

// Start server
app.listen(PORT, () => {
  console.log(`VM Uptime API rodando na porta ${PORT}`);
});
