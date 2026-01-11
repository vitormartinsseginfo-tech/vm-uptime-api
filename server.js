const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SPY_URL = 'https://monitor24x7.vm-security.workers.dev'; 

if (!DATABASE_URL) {
  console.error('ERRO: DATABASE_URL não encontrada!');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors({ origin: true, credentials: true }));

// Criar tabela se não existir
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP,
    response_ms INTEGER
  )
`).catch(err => console.log('Erro DB inicial:', err));

app.post('/api/login', (req, res) => {
  if (req.body.password === PANEL_PASSWORD) {
    res.cookie('vm_uptime_auth', 'true', { httpOnly: true, secure: true, sameSite: 'none', maxAge: 86400000 });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Incorreto' });
});

function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  res.status(401).json({ error: 'Auth' });
}

app.get('/api/sites', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM monitor_sites ORDER BY id DESC');
  res.json(result.rows);
});

app.post('/api/sites', requireAuth, async (req, res) => {
  await pool.query('INSERT INTO monitor_sites (url) VALUES ($1)', [req.body.url]);
  res.json({ success: true });
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM monitor_sites WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/check-now', requireAuth, async (req, res) => {
  checkAll();
  res.json({ success: true });
});

async function checkAll() {
  try {
    const result = await pool.query('SELECT * FROM monitor_sites');
    for (let site of result.rows) {
      let isOnline = false;
      let latency = 0;
      const start = Date.now();
      try {
        if (site.url.includes('vm-security.com')) {
          const spy = await axios.get(`${SPY_URL}?url=${encodeURIComponent(site.url)}`, { timeout: 10000 });
          isOnline = spy.data.ok === true;
          latency = spy.data.latency_ms || (Date.now() - start);
        } else {
          const resp = await axios.get(site.url, { timeout: 10000, headers: { 'User-Agent': 'VM-Monitor' } });
          isOnline = resp.status >= 200 && resp.status < 400;
          latency = Date.now() - start;
        }
      } catch (e) { isOnline = false; }

      const status = isOnline ? 'online' : 'offline';
      await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW(), response_ms = $2 WHERE id = $3', [status, Math.round(latency), site.id]);
    }
  } catch (err) { console.log('Erro checkAll:', err); }
}

setInterval(checkAll, 300000);
setTimeout(checkAll, 5000);

app.listen(PORT, () => console.log(`Rodando na porta ${PORT}`));
