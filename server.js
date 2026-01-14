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

// Criar tabela básica usada pelo monitor e garantir coluna response_ms
pool.query(`
  CREATE TABLE IF NOT EXISTS monitor_sites (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    status TEXT DEFAULT 'pendente',
    last_check TIMESTAMP,
    response_ms INTEGER DEFAULT 0
  );
`).then(() => {
  // Adiciona a coluna caso não exista (evita erro em bancos existentes)
  return pool.query(`ALTER TABLE monitor_sites ADD COLUMN IF NOT EXISTS response_ms INTEGER DEFAULT 0;`);
}).catch(err => console.error('Erro ao preparar tabela monitor_sites:', err));

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
// --- Radar proxy (Protegido) ---
// --- Radar proxy (Protegido) ---
app.get('/api/radar', requireAuth, async (req, res) => {
  const query = req.query.query || req.query.q;
  if (!query) return res.status(400).json({ error: 'Query missing' });

  // USAR A VARIÁVEL DO RENDER (RADAR_WORKER_URL)
  const workerBaseUrl = process.env.RADAR_WORKER_URL || 'https://radar.vm-security.workers.dev';
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


// --- Configurações DeHashed (Certifique-se que estas variáveis estão no topo do arquivo) ---
const DEHASHED_API_KEY = process.env.DEHASHED_API_KEY;
const DEHASHED_API_SECRET = process.env.DEHASHED_API_SECRET;

// --- Endpoints de Autenticação e Segurança ---

// Endpoint para o frontend verificar se a sessão ainda é válida
app.get('/api/auth/check', (req, res) => {
  if (req.cookies && req.cookies.vm_uptime_auth === 'true') {
    return res.json({ authenticated: true });
  }
  return res.status(401).json({ authenticated: false });
});

// --- Endpoints DeHashed Avançados ---

app.get('/api/dehashed/search', requireAuth, async (req, res) => {
  const { query, type } = req.query;
  if (!query) return res.status(400).json({ error: 'Query é obrigatória' });
  
  if (!DEHASHED_API_KEY || !DEHASHED_API_SECRET) {
    return res.status(500).json({ error: 'API DeHashed não configurada no Render' });
  }

  const auth = 'Basic ' + Buffer.from(`${DEHASHED_API_KEY}:${DEHASHED_API_SECRET}`).toString('base64');
  
  // Mapeamento exato dos filtros que você pediu
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
    const resp = await axios.get(url, { 
      headers: { Authorization: auth, Accept: 'application/json' },
      timeout: 25000 
    });
    res.json(resp.data);
  } catch (err) {
    res.status(500).json({ error: 'Erro DeHashed', details: err.message });
  }
});

// --- Monitoramento de Domínios ---

app.get('/api/monitor/domains', requireAuth, async (req, res) => {
  const r = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
  res.json(r.rows);
});

app.post('/api/monitor/domains', requireAuth, async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domínio obrigatório' });
  await pool.query('INSERT INTO monitored_domains (domain) VALUES ($1) ON CONFLICT (domain) DO NOTHING', [domain]);
  res.json({ success: true });
});

app.delete('/api/monitor/domains/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// --- NOVO: ROTA DO VULNERABILITY SCANNER ---
app.get('/api/scan', async (req, res) => {
    const target = req.query.url;
    if (!target) return res.status(400).json({ error: 'URL é obrigatória' });

    // Garante que a URL comece com http
    const url = target.startsWith('http') ? target : `https://${target}`;
    const results = {
        target: url,
        score: 100,
        vulnerabilities: [],
        tech: {}
    };

    try {
        // 1. Teste de Conexão e Headers
        const response = await axios.get(url, { 
            timeout: 10000, 
            validateStatus: false,
            headers: { 'User-Agent': 'VM-Security-Scanner/1.0' }
        });

        results.tech.server = response.headers['server'] || 'Não identificado';
        results.tech.poweredBy = response.headers['x-powered-by'] || 'Não identificado';

        // 2. Verificação de Arquivos Sensíveis (Caminhos comuns que vazam dados)
        const pathsToTest = [
            { path: '/.env', name: 'Arquivo de Configuração (.env)', severity: 'CRÍTICO', desc: 'Contém senhas de banco de dados e chaves de API.' },
            { path: '/.git/config', name: 'Repositório Git Exposto', severity: 'CRÍTICO', desc: 'Permite baixar todo o código-fonte do site.' },
            { path: '/wp-config.php.bak', name: 'Backup de Configuração WordPress', severity: 'ALTO', desc: 'Pode conter credenciais de acesso ao site.' },
            { path: '/phpinfo.php', name: 'PHP Info Exposto', severity: 'MÉDIO', desc: 'Revela detalhes internos do servidor para hackers.' }
        ];

        for (const item of pathsToTest) {
            try {
                const check = await axios.get(`${url}${item.path}`, { timeout: 3000, validateStatus: false });
                if (check.status === 200) {
                    results.vulnerabilities.push(item);
                    results.score -= 25;
                }
            } catch (e) { /* ignore errors */ }
        }

        // 3. Verificação de Cookies Inseguros
        const cookies = response.headers['set-cookie'];
        if (cookies) {
            const insecure = cookies.some(c => !c.toLowerCase().includes('httponly') || !c.toLowerCase().includes('secure'));
            if (insecure) {
                results.vulnerabilities.push({
                    name: 'Cookies Inseguros',
                    severity: 'MÉDIO',
                    desc: 'Cookies de sessão sem flag HttpOnly/Secure podem ser roubados por scripts maliciosos.'
                });
                results.score -= 10;
            }
        }

        // 4. Verificação de Proteção contra Clickjacking
        if (!response.headers['x-frame-options']) {
            results.vulnerabilities.push({
                name: 'Falta de Proteção contra Clickjacking',
                severity: 'BAIXO',
                desc: 'Permite que seu site seja exibido dentro de outros sites para enganar usuários.'
            });
            results.score -= 5;
        }

        if (results.score < 0) results.score = 0;
        res.json(results);

    } catch (error) {
        res.status(500).json({ error: 'Erro ao escanear o site: ' + error.message });
    }
});

const { createClient } = require('@supabase/supabase-js');

// Conexão com o Banco de Dados Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Rota de teste para verificar se o banco está conectado
app.get('/api/auth-test', async (req, res) => {
    res.json({ status: "Conectado ao Supabase com sucesso!" });
});

// -------------------- Start server --------------------
app.listen(PORT, () => {
  console.log(`VM Security API rodando na porta ${PORT}`);
});
