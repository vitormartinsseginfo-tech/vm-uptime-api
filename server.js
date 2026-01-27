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

// --- CONFIGURAÇÃO DE CORS (Aceita subdomínios de vmblue e vm-security) ---
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Permite qualquer host que termine com vmblue.com.br ou vm-security.com
  const isAllowed = origin && (
    origin.endsWith('.vmblue.com.br') ||
    origin === 'https://vmblue.com.br' ||
    origin.endsWith('.vm-security.com') ||
    origin === 'https://vm-security.com'
  );

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

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
    const WORKER_URL = 'https://uptime24x7.vmblue.com.br'; // URL do seu worker

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

// --- VMIntelligence module (safe insert v2) ---
(function () {
    if (typeof app === 'undefined' || typeof axios === 'undefined') {
        console.error('VMIntelligence: app ou axios não definidos.');
        return;
    }

    // Inicializa o objeto global se não existir
    if (!global.VMIntelligence) {
        global.VMIntelligence = { routesAdded: false };
    }

    if (global.VMIntelligence.routesAdded) {
        console.log('VMIntelligence já carregado.');
        return;
    }

    const VT_API_KEY = process.env.VT_API_KEY || '';
    const ABUSE_API_KEY = process.env.ABUSE_API_KEY || '';
    const cache = new Map();

    const isIP = s => /^(?:\d{1,3}\.){3}\d{1,3}$/.test((s || '').trim());
    const isHash = s => /^[a-fA-F0-9]{32,64}$/.test((s || '').trim());

    async function vtGetIP(ip) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function vtGetDomain(domain) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function vtGetFile(hash) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function abuseCheckIP(ip) {
        const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { Key: ABUSE_API_KEY, Accept: 'application/json' }
        });
        return res.data.data;
    }

    function classifyResult({ vt, abuse }) {
        let malicious = false;
        const reasons = [];
        if (abuse && Number(abuse.abuseConfidenceScore || 0) >= 10) {
            malicious = true;
            reasons.push(`AbuseIPDB score ${abuse.abuseConfidenceScore}`);
        }
        if (vt && vt.data && vt.data.attributes && vt.data.attributes.last_analysis_stats) {
            const s = vt.data.attributes.last_analysis_stats;
            if (Number(s.malicious || 0) > 0) {
                malicious = true;
                reasons.push(`VirusTotal: ${s.malicious} detections`);
            }
        }
        return { malicious, reasons };
    }

    // Endpoints
    app.get('/analyze', async (req, res) => {
        const target = (req.query.target || '').trim();
        if (!target) return res.status(400).json({ error: 'Alvo necessário' });
        try {
            let result = { target, type: 'unknown', vt: null, abuse: null };
            if (isIP(target)) {
                result.type = 'ip';
                const [a, v] = await Promise.allSettled([abuseCheckIP(target), vtGetIP(target)]);
                if (a.status === 'fulfilled') result.abuse = a.value;
                if (v.status === 'fulfilled') result.vt = v.value;
            } else if (isHash(target)) {
                result.type = 'hash';
                result.vt = await vtGetFile(target);
            } else {
                result.type = 'domain';
                result.vt = await vtGetDomain(target);
            }
            result.classification = classifyResult({ vt: result.vt, abuse: result.abuse });
            res.json(result);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    app.post('/batch', async (req, res) => {
        const targets = Array.isArray(req.body.targets) ? req.body.targets : [];
        const results = [];
        for (const t of targets) {
            try {
                let entry = { target: t, classification: { malicious: false } };
                if (isIP(t)) {
                    const [a, v] = await Promise.allSettled([abuseCheckIP(t), vtGetIP(t)]);
                    entry.classification = classifyResult({ vt: v.value, abuse: a.value });
                }
                results.push(entry);
                await new Promise(r => setTimeout(r, 400));
            } catch (e) { results.push({ target: t, error: e.message }); }
        }
        res.json({ 
            malicious: results.filter(r => r.classification?.malicious),
            clean: results.filter(r => !r.classification?.malicious),
            all: results 
        });
    });

    global.VMIntelligence.routesAdded = true;
    console.log('✅ VMIntelligence carregado com sucesso.');
})();

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

// --- CONFIGURAÇÃO DE CORS (Aceita subdomínios de vmblue e vm-security) ---
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Permite qualquer host que termine com vmblue.com.br ou vm-security.com
  const isAllowed = origin && (
    origin.endsWith('.vmblue.com.br') ||
    origin === 'https://vmblue.com.br' ||
    origin.endsWith('.vm-security.com') ||
    origin === 'https://vm-security.com'
  );

  if (isAllowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

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
    const WORKER_URL = 'https://uptime24x7.vmblue.com.br'; // URL do seu worker

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

// --- VMIntelligence module (safe insert v2) ---
(function () {
    if (typeof app === 'undefined' || typeof axios === 'undefined') {
        console.error('VMIntelligence: app ou axios não definidos.');
        return;
    }

    // Inicializa o objeto global se não existir
    if (!global.VMIntelligence) {
        global.VMIntelligence = { routesAdded: false };
    }

    if (global.VMIntelligence.routesAdded) {
        console.log('VMIntelligence já carregado.');
        return;
    }

    const VT_API_KEY = process.env.VT_API_KEY || '';
    const ABUSE_API_KEY = process.env.ABUSE_API_KEY || '';
    const cache = new Map();

    const isIP = s => /^(?:\d{1,3}\.){3}\d{1,3}$/.test((s || '').trim());
    const isHash = s => /^[a-fA-F0-9]{32,64}$/.test((s || '').trim());

    async function vtGetIP(ip) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function vtGetDomain(domain) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function vtGetFile(hash) {
        const res = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': VT_API_KEY } });
        return res.data;
    }
    async function abuseCheckIP(ip) {
        const res = await axios.get('https://api.abuseipdb.com/api/v2/check', {
            params: { ipAddress: ip, maxAgeInDays: 90 },
            headers: { Key: ABUSE_API_KEY, Accept: 'application/json' }
        });
        return res.data.data;
    }

    function classifyResult({ vt, abuse }) {
        let malicious = false;
        const reasons = [];
        if (abuse && Number(abuse.abuseConfidenceScore || 0) >= 10) {
            malicious = true;
            reasons.push(`AbuseIPDB score ${abuse.abuseConfidenceScore}`);
        }
        if (vt && vt.data && vt.data.attributes && vt.data.attributes.last_analysis_stats) {
            const s = vt.data.attributes.last_analysis_stats;
            if (Number(s.malicious || 0) > 0) {
                malicious = true;
                reasons.push(`VirusTotal: ${s.malicious} detections`);
            }
        }
        return { malicious, reasons };
    }

    // Endpoints
    app.get('/analyze', async (req, res) => {
        const target = (req.query.target || '').trim();
        if (!target) return res.status(400).json({ error: 'Alvo necessário' });
        try {
            let result = { target, type: 'unknown', vt: null, abuse: null };
            if (isIP(target)) {
                result.type = 'ip';
                const [a, v] = await Promise.allSettled([abuseCheckIP(target), vtGetIP(target)]);
                if (a.status === 'fulfilled') result.abuse = a.value;
                if (v.status === 'fulfilled') result.vt = v.value;
            } else if (isHash(target)) {
                result.type = 'hash';
                result.vt = await vtGetFile(target);
            } else {
                result.type = 'domain';
                result.vt = await vtGetDomain(target);
            }
            result.classification = classifyResult({ vt: result.vt, abuse: result.abuse });
            res.json(result);
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    app.post('/batch', async (req, res) => {
        const targets = Array.isArray(req.body.targets) ? req.body.targets : [];
        const results = [];
        for (const t of targets) {
            try {
                let entry = { target: t, classification: { malicious: false } };
                if (isIP(t)) {
                    const [a, v] = await Promise.allSettled([abuseCheckIP(t), vtGetIP(t)]);
                    entry.classification = classifyResult({ vt: v.value, abuse: a.value });
                }
                results.push(entry);
                await new Promise(r => setTimeout(r, 400));
            } catch (e) { results.push({ target: t, error: e.message }); }
        }
        res.json({ 
            malicious: results.filter(r => r.classification?.malicious),
            clean: results.filter(r => !r.classification?.malicious),
            all: results 
        });
    });

    global.VMIntelligence.routesAdded = true;
    console.log('✅ VMIntelligence carregado com sucesso.');
})();

// ===== STRESSER (adicionar abaixo das rotas existentes, antes do app.listen) =====
const { RateLimiterMemory } = require('rate-limiter-flexible');

// Config via env
const STRESS_MAX_VOLUME = parseInt(process.env.STRESS_MAX_VOLUME || '1000', 10);
const STRESS_RATE_POINTS = parseInt(process.env.STRESS_RATE_POINTS || '2', 10);
const STRESS_RATE_DURATION = parseInt(process.env.STRESS_RATE_DURATION || '3600', 10);
const STRESS_ALLOWED_HOSTS = process.env.STRESS_ALLOWED_HOSTS
  ? process.env.STRESS_ALLOWED_HOSTS.split(',').map(s => s.trim()).filter(Boolean)
  : [];

// rate limiter (por UID)
const stressLimiter = new RateLimiterMemory({
  points: STRESS_RATE_POINTS,
  duration: STRESS_RATE_DURATION,
});

// helper para checar host permitido (se ALLOWED_HOSTS configurado)
function isStressHostAllowed(targetUrl) {
  if (!STRESS_ALLOWED_HOSTS.length) return true;
  try {
    const host = new URL(targetUrl).hostname;
    return STRESS_ALLOWED_HOSTS.includes(host);
  } catch (e) {
    return false;
  }
}

// execução controlada em batches usando seu client axios e UserAgent
async function runRequestsInBatches(target, total, batchSize = 20, timeoutMs = 8000) {
  const results = [];
  let remaining = total;
  while (remaining > 0) {
    const currentBatch = Math.min(batchSize, remaining);
    const promises = [];
    for (let i = 0; i < currentBatch; i++) {
      const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
      promises.push(
        client.get(target, { headers: { 'User-Agent': ua }, timeout: timeoutMs })
          .then(r => ({ ok: true, status: r.status }))
          .catch(e => ({ ok: false, status: e.response ? e.response.status : 'TIMEOUT' }))
      );
    }
    const batchResults = await Promise.all(promises);
    results.push(...batchResults);
    remaining -= currentBatch;
    // pequeno atraso entre batches para reduzir pressão
    await new Promise(r => setTimeout(r, 50));
  }
  return results;
}

// ROTA PROTEGIDA para rodar o stresser
// Usa o middleware verifyFirebaseToken que você já definiu acima
app.get('/api/stresser', verifyFirebaseToken, async (req, res) => {
  try {
    const target = (req.query.url || '').trim();
    let volume = parseInt(req.query.volume || '10', 10);

    if (!target) return res.status(400).json({ error: 'target_missing' });
    if (!/^https?:\/\//i.test(target)) return res.status(400).json({ error: 'target_must_start_with_http' });

    // host whitelist check (opcional)
    if (!isStressHostAllowed(target)) {
      return res.status(400).json({ error: 'target_not_allowed' });
    }

    if (isNaN(volume) || volume < 1) volume = 1;
    if (volume > STRESS_MAX_VOLUME) volume = STRESS_MAX_VOLUME; // enforce hard cap

    // rate limit por UID (usando uid do token)
    const uid = req.user?.uid || req.user?.sub || 'anonymous';
    try {
      await stressLimiter.consume(uid);
    } catch (rlRejected) {
      return res.status(429).json({ error: 'rate_limited' });
    }

    // audit log mínimo
    const requesterIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[STRESS START] uid=${uid} email=${req.user?.email} ip=${requesterIp} target=${target} volume=${volume}`);

    const start = Date.now();
    const results = await runRequestsInBatches(target, volume, 20, 8000);
    const success = results.filter(r => r.ok).length;
    const fail = results.length - success;
    const elapsed = Date.now() - start;

    const resultado = fail > Math.floor(volume * 0.3) ? 'VULNERÁVEL' : 'ESTÁVEL';

    // log resultado (ideal: enviar para serviço de logging)
    console.log({
      event: 'stress_result',
      uid,
      email: req.user?.email || null,
      ip: requesterIp,
      target,
      volume,
      success,
      fail,
      elapsed_ms: elapsed,
      ts: new Date().toISOString()
    });

    return res.json({
      alvo: target,
      requisicoes: volume,
      sucessos: success,
      falhas: fail,
      tempo_total_ms: elapsed,
      resultado
    });
  } catch (err) {
    console.error('STRESS ERROR', err);
    return res.status(500).json({ error: 'internal_error', details: err.message });
  }
});

// --- INICIALIZAÇÃO ---
app.listen(PORT, () => console.log(`🚀 VM Security API Unificada rodando na porta ${PORT}`));
