// server.js
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
// Pode setar FRONTEND_URL para seu domínio (ex: "https://monitor.vm-security.com") ou deixar true para refletir origem
const FRONTEND_URL = process.env.FRONTEND_URL || true;

if (!DATABASE_URL) {
  console.error('ERRO: a variável de ambiente DATABASE_URL não está definida.');
  process.exit(1);
}

// Conexão com Postgres (Render precisa ssl rejectUnauthorized: false)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// CORS - permite credenciais e reflete origem (origin: FRONTEND_URL)
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// Inicializa tabela (executa uma vez)
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP
  )
`).catch(err => console.error('Erro ao criar tabela monitor_sites:', err));

// --- Autenticação (login)
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Senha requerida' });

  if (password === PANEL_PASSWORD) {
    // Cookie HttpOnly; secure:true exige HTTPS (Render/Pages usam HTTPS)
    res.cookie('vm_uptime_auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000 // 1 dia
    });
    return res.json({ success: true });
  } else {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
});

// Middleware para proteger rotas
function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  return res.status(401).json({ error: 'Não autorizado' });
}

// --- Rotas da API (protegidas)
app.get('/api/sites', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM monitor_sites ORDER BY id DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
    console.error(err);
    res.status(500).json({ error: 'Erro ao adicionar site' });
  }
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM monitor_sites WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao remover site' });
  }
});

// Checagem manual (útil para debug), protegida
app.post('/api/check', requireAuth, async (req, res) => {
  try {
    await checkAll(); // roda uma vez
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erro ao rodar checagem' });
  }
});

// Health endpoint
app.get('/health', (req, res) => res.json({ ok: true }));

// --- Função de checagem com "disfarce" e retries
async function fetchWithRetry(url, attempts = 2, timeoutMs = 15000) {
  let lastErr = null;
  const headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Referer': 'https://www.google.com/'
  };

  for (let i = 0; i < attempts; i++) {
    try {
      const resp = await axios.get(url, {
        timeout: timeoutMs,
        headers,
        maxRedirects: 5,
        validateStatus: null // vamos avaliar manualmente
      });
      lastErr = null;
      return resp;
    } catch (err) {
      lastErr = err;
      // pequena espera antes de tentar novamente
      await new Promise(r => setTimeout(r, 300 + i * 200));
    }
  }
  throw lastErr;
}

async function checkAll() {
  const result = await pool.query('SELECT * FROM monitor_sites');
  const sites = result.rows;

  for (let site of sites) {
    try {
      const resp = await fetchWithRetry(site.url, 2, 15000);

      // Considera online se status code 2xx ou 3xx (redirecionamento aceitável)
      const statusOK = resp && resp.status >= 200 && resp.status < 400;

      if (statusOK) {
        await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['online', site.id]);
        console.log(`✅ ${site.url} -> online (${resp.status})`);
      } else {
        await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['offline', site.id]);
        console.log(`❌ ${site.url} -> offline (HTTP ${resp && resp.status})`);
      }
    } catch (err) {
      await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['offline', site.id]);
      console.log(`❌ ${site.url} -> offline (erro: ${err && err.message})`);
    }
  }
}

// Roda a checagem a cada 5 minutos (300000 ms)
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  checkAll().catch(err => console.error('Erro no checkAll:', err));
}, CHECK_INTERVAL_MS);

// rodada inicial (com timeout curto para permitir startup)
setTimeout(() => {
  checkAll().catch(err => console.error('Erro no checkAll inicial:', err));
}, 2000);

// Start server
app.listen(PORT, () => {
  console.log(`VM Uptime API rodando na porta ${PORT}`);
});
