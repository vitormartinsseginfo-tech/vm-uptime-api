// server.js
// API unificada para VM Security: Monitor + Radar proxy + Contact Hunter proxy
// Protegido com cookie de sessão; usa a mesma senha (PANEL_PASSWORD) do Uptime Monitor.
//
// Variáveis de ambiente esperadas:
// - DATABASE_URL (Postgres connection string)  [REQUIRED]
// - PANEL_PASSWORD (senha do painel)           [opcional - default: admin123]
// - SPY_URL (Cloudflare Worker para "espiar" domínios protegidos) [opcional]
// - RADAR_WORKER_URL (opcional) OR SERPAPI_KEY (opcional) - para /api/radar
// - FRONTEND_URL (opcional) - domínio do frontend para CORS (ou deixe undefined para refletir origem)
// - PORT (opcional)
//
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
const SPY_URL = process.env.SPY_URL || null; // ex: https://monitor24x7.vm-security.workers.dev
const RADAR_WORKER_URL = process.env.RADAR_WORKER_URL || null;
const SERPAPI_KEY = process.env.SERPAPI_KEY || null;
const FRONTEND_URL = process.env.FRONTEND_URL || true; // true => reflect origin (cors package accepts function/boolean)

// validação mínima
if (!DATABASE_URL) {
  console.error('ERRO: DATABASE_URL não configurada. Defina DATABASE_URL no ambiente.');
  process.exit(1);
}

// Pool Postgres
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// CORS: permitir credenciais (cookies). Para produção defina FRONTEND_URL com a URL do seu frontend (ex: https://radar.vm-security.com)
const corsOptions = {
  origin: FRONTEND_URL === true ? true : FRONTEND_URL,
  credentials: true
};
app.use(cors(corsOptions));

// Criar tabela básica usada pelo monitor
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP,
    response_ms INTEGER
  )
`).catch(err => console.error('Erro criando tabela monitor_sites:', err));

// -------------------- Auth / Sessão --------------------
app.post('/api/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Senha requerida' });

  if (password === PANEL_PASSWORD) {
    // Cookie HttpOnly; secure:true exige HTTPS (Render tem HTTPS)
    res.cookie('vm_uptime_auth', 'true', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000 // 1 dia
    });
    return res.json({ success: true });
  }
  return res.status(401).json({ error: 'Senha incorreta' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('vm_uptime_auth');
  res.json({ success: true });
});

function requireAuth(req, res, next) {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') return next();
  return res.status(401).json({ error: 'Acesso negado. Faça login.' });
}

// -------------------- Monitor (Uptime) --------------------
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

// Forçar checagem imediata (usado pelo botão "Atualizar Agora")
app.post('/api/check-now', requireAuth, async (req, res) => {
  try {
    await checkAll();
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/check-now error:', err);
    res.status(500).json({ error: 'Erro ao rodar checagem' });
  }
});

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Funções de checagem
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
  // SPY_URL é um Worker seu que já adicionamos (opcional)
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

// Agendador: a cada 5 minutos
const CHECK_INTERVAL_MS = 5 * 60 * 1000;
setInterval(() => {
  checkAll().catch(e => console.error('checkAll interval error:', e));
}, CHECK_INTERVAL_MS);

// Execução inicial após boot
setTimeout(() => {
  checkAll().catch(e => console.error('checkAll initial error:', e));
}, 2000);

// -------------------- Contact Hunter proxy (Protected) --------------------
// Uso: GET /api/proxy?url=https://target.example.com
// Retorna o HTML bruto do site (útil para o hunter extrair emails/telefones)
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

// -------------------- Radar proxy / SerpApi wrapper (Protected) --------------------
// Uso (preferido): configure RADAR_WORKER_URL (Worker que faz a busca e evita CORS)
// Alternativa: configure SERPAPI_KEY para que o servidor chame SerpApi direto.
// Endpoint protegido: GET /api/radar?query=nome+da+empresa&num=20
app.get('/api/radar', requireAuth, async (req, res) => {
  const query = req.query.query;
  const num = parseInt(req.query.num || '20', 10);

  if (!query) return res.status(400).json({ error: 'query param missing' });

  try {
    // 1) Se existir RADAR_WORKER_URL, delega para ele (melhor opção - evita expor SERPAPI_KEY)
    if (RADAR_WORKER_URL) {
      const workerResp = await axios.get(`${RADAR_WORKER_URL}?q=${encodeURIComponent(query)}&num=${num}`, { timeout: 15000 });
      return res.json(workerResp.data);
    }

    // 2) Se SERPAPI_KEY está configurado, chamamos o SerpApi (exemplo)
    if (SERPAPI_KEY) {
      // Ajuste a URL/params conforme sua necessidade; este é um exemplo genérico para Google Maps via SerpApi
      const serpUrl = `https://serpapi.com/search.json?engine=google_maps&q=${encodeURIComponent(query)}&num=${num}&api_key=${SERPAPI_KEY}`;
      const serpResp = await axios.get(serpUrl, { timeout: 15000 });
      return res.json(serpResp.data);
    }

    // 3) Se nenhum mecanismo configurado:
    return res.status(400).json({ error: 'Nenhum RADAR_WORKER_URL ou SERPAPI_KEY configurado' });
  } catch (err) {
    console.error('RADAR error:', err && err.message);
    return res.status(500).json({ error: 'Erro ao executar busca radar' });
  }
});

// -------------------- Start server --------------------
app.listen(PORT, () => {
  console.log(`VM Security API rodando na porta ${PORT}`);
});
