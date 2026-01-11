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

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors({
  origin: true,
  credentials: true
}));

// Inicializa tabela
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP
  )
`).catch(err => console.error('Erro DB:', err));

// Login
app.post('/api/login', (req, res) => {
  if (req.body.password === PANEL_PASSWORD) {
    res.cookie('vm_uptime_auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 86400000
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Senha incorreta' });
});

function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  res.status(401).json({ error: 'Não autorizado' });
}

// Rotas
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

// FUNÇÃO DE CHECAGEM COM TOKEN SECRETO
async function checkAll() {
  const result = await pool.query('SELECT * FROM monitor_sites');
  for (let site of result.rows) {
    try {
      await axios.get(site.url, {
        timeout: 15000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
          'X-VM-Monitor': 'VM_SECURITY_SECRET_ACCESS_2026' // <--- TOKEN SECRETO
        }
      });
      await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['online', site.id]);
    } catch (err) {
      await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['offline', site.id]);
    }
  }
}

setInterval(checkAll, 5 * 60 * 1000);
setTimeout(checkAll, 2000);

app.listen(PORT, () => console.log(`Monitor rodando na porta ${PORT}`));
