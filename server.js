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

// COLOQUE O LINK DO SEU WORKER AQUI EMBAIXO:
const SPY_URL = 'https://vm-spy.vitor.workers.dev'; 

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors({ origin: true, credentials: true }));

pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP
  )
`).catch(err => console.error('Erro DB:', err));

app.post('/api/login', (req, res) => {
  if (req.body.password === PANEL_PASSWORD) {
    res.cookie('vm_uptime_auth', 'true', {
      httpOnly: true, secure: true, sameSite: 'none', maxAge: 86400000
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Senha incorreta' });
});

function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  res.status(401).json({ error: 'Não autorizado' });
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

async function checkAll() {
  const result = await pool.query('SELECT * FROM monitor_sites');
  for (let site of result.rows) {
    try {
      let finalUrl = site.url;
      
      // Se for o seu site, usa o espião para burlar o bloqueio de IP
      if (site.url.includes('vm-security.com')) {
        finalUrl = `${SPY_URL}?url=${encodeURIComponent(site.url)}`;
      }

      const resp = await axios.get(finalUrl, { timeout: 15000 });
      
      if (resp.status >= 200 && resp.status < 400) {
        await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['online', site.id]);
        console.log(`✅ ${site.url} ONLINE`);
      } else {
        throw new Error('Status inválido');
      }
    } catch (err) {
      await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['offline', site.id]);
      console.log(`❌ ${site.url} OFFLINE`);
    }
  }
}

setInterval(checkAll, 5 * 60 * 1000);
setTimeout(checkAll, 2000);

app.listen(PORT, () => console.log(`Monitor rodando na porta ${PORT}`));
