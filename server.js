const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const net = require('net');
const UserAgent = require('user-agents');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');

// --- CONFIGURAÇÃO DE CORS (Para todas as ferramentas) ---
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // Se houver uma origem, reflete ela, senão usa '*'
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
});

// --- BANCO DE DADOS LOCAL (Para o 24x7) ---
let DB = { sites: [] };
if (fs.existsSync(DATA_FILE)) {
    try { DB = JSON.parse(fs.readFileSync(DATA_FILE)); } catch (e) {}
}
const saveData = () => fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 15000
});

// ============================================================
// 1. FERRAMENTA: HUNTER (CONTATOS)
// ============================================================
app.all('/hunt', async (req, res) => {
    const target = req.query.url || req.body.url;
    if (!target) return res.status(400).json({ error: 'URL missing' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const url = target.startsWith('http') ? target : 'http://' + target;
        const resp = await client.get(url, { headers: { 'User-Agent': ua } });
        const html = resp.data || '';
        const emails = [...new Set(html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
        const phones = [...new Set(html.match(/(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g) || [])];
        res.json({ emails, phones, socials: [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// 2. FERRAMENTA: VULNERABILITY (SCANNER)
// ============================================================
app.all(['/scan', '/api/scan'], async (req, res) => {
    const target = req.query.url || req.body.url;
    if (!target) return res.status(400).json({ error: 'URL missing' });
    try {
        const url = target.startsWith('http') ? target : 'http://' + target;
        const resp = await client.get(url, { headers: { 'User-Agent': new UserAgent().toString() }, validateStatus: () => true });
        const h = resp.headers;
        const vulns = [];
        let score = 100;

        if (!h['x-frame-options']) { vulns.push({ name: "Clickjacking", severity: "HIGH", desc: "Header X-Frame-Options ausente." }); score -= 25; }
        if (!h['content-security-policy']) { vulns.push({ name: "CSP Missing", severity: "MEDIUM", desc: "Política de Segurança de Conteúdo não definida." }); score -= 15; }
        if (!h['strict-transport-security']) { vulns.push({ name: "HSTS Missing", severity: "MEDIUM", desc: "Site não força HTTPS via HSTS." }); score -= 10; }

        res.json({
            target: url,
            score: Math.max(0, score),
            detected_server: h['server'] || 'Protegido',
            detected_tech: h['x-powered-by'] || 'Nginx/Web',
            vulnerabilities: vulns
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// 3. FERRAMENTA: 24x7 (MONITOR DE UPTIME)
// ============================================================
app.get(['/sites', '/api/sites'], (req, res) => {
    res.json(DB.sites.map(s => ({
        id: s.id,
        url: s.url,
        status: s.status || 'offline',
        response_ms: s.response_ms || 0,
        last_check: s.last_check || new Date().toISOString()
    })));
});

app.post(['/sites', '/api/sites'], async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL obrigatória' });
    const site = { id: Date.now().toString(36), url, status: 'online', response_ms: 50, last_check: new Date().toISOString() };
    DB.sites.push(site);
    saveData();
    res.json(site);
});

app.delete(['/sites/:id', '/api/sites/:id'], (req, res) => {
    DB.sites = DB.sites.filter(s => s.id !== req.params.id);
    saveData();
    res.json({ ok: true });
});

app.all(['/check-now', '/api/check-now'], async (req, res) => {
    const WORKER_URL = 'https://monitor24x7.vm-security.workers.dev'; // URL do seu worker

    for (const s of DB.sites) {
        try {
            // O Render pede para o Worker testar o site
            const resp = await axios.get(`${WORKER_URL}?url=${encodeURIComponent(s.url)}`);
            s.status = resp.data.status;
            s.response_ms = resp.data.ms;
            s.last_check = new Date().toISOString();
        } catch (e) {
            s.status = 'offline';
            s.response_ms = 0;
        }
    }
    saveData();
    res.json({ ok: true });
});

// --- NOVA FERRAMENTA: PORT SCANNER ---

app.get('/api/portcheck', async (req, res) => {
    try {
        let target = req.query.target;
        
        if (!target) {
            return res.json({ error: 'Alvo ausente', results: [] });
        }

        // Limpeza profunda do alvo: remove http, https, www e barras
        const cleanTarget = target
            .replace(/^https?:\/\//i, '')
            .replace(/^www\./i, '')
            .split('/')[0]
            .split(':')[0];

        const ports = [
            { port: 21, service: 'FTP' },
            { port: 22, service: 'SSH' },
            { port: 80, service: 'HTTP' },
            { port: 443, service: 'HTTPS' },
            { port: 3306, service: 'MySQL' },
            { port: 3389, service: 'RDP' },
            { port: 5432, service: 'PostgreSQL' },
            { port: 8080, service: 'HTTP-Proxy' }
        ];

        const checkPort = (port, host) => {
            return new Promise((resolve) => {
                const socket = new net.Socket();
                socket.setTimeout(2000); // 2 segundos de espera

                socket.on('connect', () => {
                    socket.destroy();
                    resolve('Aberta');
                });

                socket.on('timeout', () => {
                    socket.destroy();
                    resolve('Fechada/Filtrada');
                });

                socket.on('error', () => {
                    socket.destroy();
                    resolve('Fechada');
                });

                socket.connect(port, host);
            });
        };

        const results = [];
        // Executa o scan porta por porta
        for (const p of ports) {
            const status = await checkPort(p.port, cleanTarget);
            results.push({ ...p, status });
        }

        res.json({ target: cleanTarget, results });

    } catch (error) {
        console.error('Erro no scan:', error);
        res.json({ error: 'Erro interno no servidor', results: [] });
    }
});

// === ROTA: /api/dehashed/search (integração DeHashed, com verificação Firebase + cache) ===
const admin = require('firebase-admin');

// Inicializa Firebase Admin se a chave de serviço estiver nas env vars (Render)
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(sa)
    });
    console.log('Firebase Admin init ok');
  } catch (err) {
    console.warn('Erro ao inicializar Firebase Admin:', err.message);
  }
} else {
  console.warn('FIREBASE_SERVICE_ACCOUNT não configurado (Firebase Admin não inicializado)');
}

// middleware para validar token Firebase (expect: Authorization: Bearer <idToken>)
async function verifyFirebaseToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'NO_TOKEN' });
  const idToken = auth.split(' ')[1];

  if (!admin.apps.length) return res.status(500).json({ error: 'FIREBASE_NOT_CONFIGURED' });

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    return next();
  } catch (err) {
    console.warn('verifyIdToken failed', err.message);
    return res.status(401).json({ error: 'INVALID_TOKEN' });
  }
}

// cache simples em memória (map: key -> { ts, data })
const dehashedCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutos

app.get('/api/dehashed/search', verifyFirebaseToken, async (req, res) => {
  const query = (req.query.query || req.query.q || '').trim();
  const type = (req.query.type || 'all').trim();

  if (!query) return res.status(400).json({ error: 'query_missing', message: 'Use ?query=email@exemplo.com' });

  // env vars do Dehashed (adicionar no Render)
  const deEmail = process.env.DEHASHED_EMAIL;
  const deKey = process.env.DEHASHED_API_KEY;

  if (!deEmail || !deKey) {
    return res.status(503).json({
      error: 'DEHASHED_NOT_CONFIGURED',
      message: 'Adicione DEHASHED_EMAIL e DEHASHED_API_KEY nas Environment Variables do Render e redeploy.'
    });
  }

  // cache key pode usar também type se você segmentar por type
  const cacheKey = `dehashed:${type}:${query.toLowerCase()}`;
  const cached = dehashedCache.get(cacheKey);
  if (cached && (Date.now() - cached.ts) < CACHE_TTL_MS) {
    return res.json(cached.data);
  }

  try {
    const auth = Buffer.from(`${deEmail}:${deKey}`).toString('base64');
    // endpoint "light" é rápido; ajusta se preferir outro endpoint
    const url = `https://api.dehashed.com/light?query=${encodeURIComponent(query)}`;

    const resp = await axios.get(url, {
      headers: {
        'Accept': 'application/json',
        'Authorization': `Basic ${auth}`
      },
      timeout: 15000
    });

    // Normalize a resposta para { total, entries: [] } — seu frontend já espera entries/total
    const entries = resp.data?.entries || resp.data?.records || (Array.isArray(resp.data) ? resp.data : []);
    const total = resp.data?.total || entries.length || 0;

    const out = { total, entries };
    dehashedCache.set(cacheKey, { ts: Date.now(), data: out });

    return res.json(out);
  } catch (err) {
    console.error('Dehashed API error', err.response ? err.response.data : err.message);
    const status = err.response?.status || 500;
    return res.status(status).json({
      error: 'DEHASHED_ERROR',
      details: err.response?.data || err.message
    });
  }
});

// --- VMIntelligence module (safe insert) ---
if (!global.VMIntelligence) {
  global.VMIntelligence = (function () {
    // Checagens básicas
    if (typeof app === 'undefined') {
      console.error('VMIntelligence: erro - variável "app" não encontrada. Cole este bloco após a criação do app (const app = express()).');
      return {};
    }
    if (typeof axios === 'undefined') {
      console.error('VMIntelligence: erro - "axios" não encontrado. Instale e require axios no topo do server.js.');
      return {};
    }

    // Config via ENV
    const VT_API_KEY = process.env.VT_API_KEY || '';
    const ABUSE_API_KEY = process.env.ABUSE_API_KEY || '';

    // Cache local ao namespace (não sobrescreve globals)
    const cache = new Map();
    const DEFAULT_TTL = 1000 * 60 * 60; // 1 hora
    function setCache(key, value, ttl = DEFAULT_TTL) { cache.set(key, { ts: Date.now(), ttl, value }); }
    function getCache(key) {
      const e = cache.get(key);
      if (!e) return null;
      if (Date.now() - e.ts > e.ttl) { cache.delete(key); return null; }
      return e.value;
    }

    // Helpers
    const isIP = s => /^(?:\d{1,3}\.){3}\d{1,3}$/.test((s || '').trim());
    const isHash = s => /^[a-fA-F0-9]{32,64}$/.test((s || '').trim());

    // VT helpers
    async function vtGetIP(ip) {
      const k = `vt:ip:${ip}`;
      const cached = getCache(k); if (cached) return cached;
      const res = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_API_KEY } });
      setCache(k, res.data);
      return res.data;
    }
    async function vtGetDomain(domain) {
      const k = `vt:domain:${domain}`;
      const cached = getCache(k); if (cached) return cached;
      const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { 'x-apikey': VT_API_KEY } });
      setCache(k, res.data);
      return res.data;
    }
    async function vtGetFile(hash) {
      const k = `vt:file:${hash}`;
      const cached = getCache(k); if (cached) return cached;
      const res = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': VT_API_KEY } });
      setCache(k, res.data);
      return res.data;
    }

    // AbuseIPDB helper
    async function abuseCheckIP(ip) {
      const k = `abuse:ip:${ip}`;
      const cached = getCache(k); if (cached) return cached;
      const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
        params: { ipAddress: ip, maxAgeInDays: 90 },
        headers: { Key: ABUSE_API_KEY, Accept: 'application/json' }
      });
      setCache(k, res.data.data);
      return res.data.data;
    }

    // Classificação simples
    function classifyResult({ vt, abuse }) {
      let malicious = false;
      const reasons = [];
      if (abuse && typeof abuse.abuseConfidenceScore !== 'undefined') {
        const score = Number(abuse.abuseConfidenceScore || 0);
        if (score >= 10) { malicious = true; reasons.push(`AbuseIPDB score ${score}`); }
      }
      if (vt && vt.data && vt.data.attributes && vt.data.attributes.last_analysis_stats) {
        const stats = vt.data.attributes.last_analysis_stats;
        const maliciousCount = Number(stats.malicious || 0);
        if (maliciousCount > 0) { malicious = true; reasons.push(`VirusTotal: ${maliciousCount} detections`); }
      } else if (vt && Array.isArray(vt.data) && vt.data.length) {
        const d = vt.data[0];
        if (d && d.attributes && d.attributes.last_analysis_stats) {
          const s = d.attributes.last_analysis_stats;
          if ((s.malicious || 0) > 0) { malicious = true; reasons.push(`VirusTotal: ${s.malicious} detections`); }
        }
      }
      return { malicious, reasons };
    }

    // Se já adicionou rotas, não adiciona novamente
    if (!global.VMIntelligence.routesAdded) {

      // Middleware opcional: se existir verifyFirebaseToken global, usa para proteger rotas
      async function authMiddleware(req, res, next) {
        if (typeof global.verifyFirebaseToken !== 'function') return next();
        const auth = req.headers.authorization || '';
        if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized: no token' });
        const token = auth.split(' ')[1];
        try {
          const decoded = await global.verifyFirebaseToken(token);
          req.user = decoded;
          return next();
        } catch (err) {
          return res.status(401).json({ error: 'Unauthorized', details: err.message });
        }
      }

      // Endpoint single
      app.get('/analyze', authMiddleware, async (req, res) => {
        const target = (req.query.target || '').trim();
        if (!target) return res.status(400).json({ error: 'target query param required' });
        try {
          const result = { target, type: 'unknown', vt: null, abuse: null, classification: null };
          if (isIP(target)) {
            result.type = 'ip';
            const [abuse, vt] = await Promise.allSettled([abuseCheckIP(target), vtGetIP(target)]);
            if (abuse.status === 'fulfilled') result.abuse = abuse.value;
            if (vt.status === 'fulfilled') result.vt = vt.value;
          } else if (isHash(target)) {
            result.type = 'hash';
            result.vt = await vtGetFile(target);
          } else {
            result.type = 'domain';
            result.vt = await vtGetDomain(target);
          }
          result.classification = classifyResult({ vt: result.vt, abuse: result.abuse });
          return res.json(result);
        } catch (err) {
          console.error('VMIntelligence /analyze error:', err.message || err);
          return res.status(500).json({ error: 'internal_error', details: err.message || String(err) });
        }
      });

      // Endpoint batch
      app.post('/batch', authMiddleware, async (req, res) => {
        const targets = Array.isArray(req.body.targets) ? req.body.targets : [];
        if (!targets.length) return res.status(400).json({ error: 'Provide JSON body with targets array' });

        const results = [];
        for (const raw of targets) {
          const t = String(raw).trim();
          if (!t) continue;
          try {
            const cached = getCache(`analyzed:${t}`);
            if (cached) { results.push(cached); continue; }

            const entry = { target: t, type: 'unknown', vt: null, abuse: null, classification: null };
            if (isIP(t)) {
              entry.type = 'ip';
              const [abuse, vt] = await Promise.allSettled([abuseCheckIP(t), vtGetIP(t)]);
              if (abuse.status === 'fulfilled') entry.abuse = abuse.value;
              if (vt.status === 'fulfilled') entry.vt = vt.value;
            } else if (isHash(t)) {
              entry.type = 'hash';
              entry.vt = await vtGetFile(t);
            } else {
              entry.type = 'domain';
              entry.vt = await vtGetDomain(t);
            }
            entry.classification = classifyResult({ vt: entry.vt, abuse: entry.abuse });
            setCache(`analyzed:${t}`, entry);
            results.push(entry);

            // pequeno delay para reduzir chance de rate-limit
            await new Promise(r => setTimeout(r, 350));
          } catch (err) {
            results.push({ target: t, error: err.message || String(err) });
          }
        }

        const malicious = results.filter(r => r.classification && r.classification.malicious);
        const clean = results.filter(r => r.classification && !r.classification.malicious);
        return res.json({ total: results.length, maliciousCount: malicious.length, cleanCount: clean.length, malicious, clean, all: results });
      });

      global.VMIntelligence.routesAdded = true;
    }

    console.log('VMIntelligence module loaded (routes added if not present).');
    return { vtKey: VT_API_KEY, abuseKey: ABUSE_API_KEY };
  })();
} else {
  console.log('VMIntelligence already loaded, skipping duplicate injection.');
}

// --- INICIALIZAÇÃO ---
app.listen(PORT, () => console.log(`🚀 VM Security API Unificada rodando na porta ${PORT}`));
