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

// --------- CONFIG (env vars with sane defaults) ----------
const STRESS_MAX_VOLUME = parseInt(process.env.STRESS_MAX_VOLUME || '1000', 10);
const STRESS_BATCH_SIZE = parseInt(process.env.STRESS_BATCH_SIZE || '20', 10);
const STRESS_REQUEST_TIMEOUT = parseInt(process.env.STRESS_REQUEST_TIMEOUT || '8000', 10);
const STRESS_BATCH_DELAY = parseInt(process.env.STRESS_BATCH_DELAY || '100', 10); // ms
const STRESS_RATE_POINTS = parseInt(process.env.STRESS_RATE_POINTS || '3', 10);
const STRESS_RATE_DURATION = parseInt(process.env.STRESS_RATE_DURATION || '3600', 10); // seconds
const STRESS_ALLOWED_HOSTS = process.env.STRESS_ALLOWED_HOSTS ? process.env.STRESS_ALLOWED_HOSTS.split(',').map(s => s.trim()).filter(Boolean) : []; // empty = allow all

// --------- Firebase Admin init (service account JSON in env) ----------
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.warn('FIREBASE_SERVICE_ACCOUNT not set — auth verification will fail.');
} else {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } catch (e) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT:', e.message);
  }
}

// --------- Rate limiter (memory) ----------
const limiter = new RateLimiterMemory({
  points: STRESS_RATE_POINTS,
  duration: STRESS_RATE_DURATION,
});

// --------- Express setup ----------
const app = express();
app.use(cors());
app.use(express.json());

// Helper: verify Firebase ID token (from Authorization Bearer or token query param)
async function verifyTokenFromReq(req) {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];
  if (!token && req.query && req.query.token) token = req.query.token;
  if (!token) throw new Error('No token provided');

  if (!admin.apps.length) throw new Error('Firebase admin not initialized on server');

  const decoded = await admin.auth().verifyIdToken(token);
  return decoded; // contains uid, email, etc
}

// Helper: validate target URL and allowed hosts
function validateTargetUrl(targetUrl) {
  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid protocol');
    if (STRESS_ALLOWED_HOSTS.length > 0) {
      const hostname = parsed.hostname.toLowerCase();
      const ok = STRESS_ALLOWED_HOSTS.some(h => hostname === h || hostname.endsWith('.' + h));
      if (!ok) throw new Error('Host not allowed');
    }
    return parsed;
  } catch (e) {
    throw new Error('Invalid URL: ' + e.message);
  }
}

// Core runner with progress callback
async function runRequestsInBatches(target, total, opts = {}, progressCb = () => {}) {
  const batchSize = opts.batchSize || STRESS_BATCH_SIZE;
  const timeoutMs = opts.timeoutMs || STRESS_REQUEST_TIMEOUT;
  const batchDelay = opts.batchDelay != null ? opts.batchDelay : STRESS_BATCH_DELAY;

  const client = axios.create({ timeout: timeoutMs, validateStatus: null });
  let remaining = total;
  let sent = 0;
  let successes = 0;
  let fails = 0;
  const details = []; // small array of last N results for final reporting (optional)

  while (remaining > 0) {
    const currentBatch = Math.min(batchSize, remaining);
    const promises = [];

    for (let i = 0; i < currentBatch; i++) {
      const ua = new UserAgent().toString();
      const p = client.get(target, {
        headers: {
          'User-Agent': ua,
          'Accept': '*/*',
          'Cache-Control': 'no-cache',
        },
      })
        .then(res => {
          sent++;
          const ok = res.status >= 200 && res.status < 400;
          if (ok) successes++; else fails++;
          const out = { idx: sent, ok, status: res.status, time_ms: null };
          progressCb(out);
          details.push(out);
          return out;
        })
        .catch(err => {
          sent++;
          fails++;
          const out = { idx: sent, ok: false, status: err.code || 'ERR', err: err.message };
          progressCb(out);
          details.push(out);
          return out;
        });

      promises.push(p);
    }

    // wait for batch to finish (parallel)
    await Promise.all(promises);

    remaining -= currentBatch;
    if (remaining > 0) await new Promise(r => setTimeout(r, batchDelay));
  }

  return { sent, successes, fails, details };
}

// Endpoint: config (frontend can fetch to show limits)
app.get('/api/stresser/config', (req, res) => {
  res.json({
    max_volume: STRESS_MAX_VOLUME,
    batch_size: STRESS_BATCH_SIZE,
    request_timeout_ms: STRESS_REQUEST_TIMEOUT,
    batch_delay_ms: STRESS_BATCH_DELAY,
    rate_points: STRESS_RATE_POINTS,
    rate_duration_seconds: STRESS_RATE_DURATION,
    allowed_hosts: STRESS_ALLOWED_HOSTS,
  });
});

// Endpoint: POST /api/stresser -> executes test and returns final result (non-stream)
app.post('/api/stresser', async (req, res) => {
  try {
    const { url: targetUrl, volume } = req.body || {};
    if (!targetUrl) return res.status(400).json({ error: 'url required in body' });

    const parsed = validateTargetUrl(targetUrl);

    // auth & rate-limit
    const decoded = await verifyTokenFromReq(req);
    const key = decoded.uid || decoded.sub || decoded.email || 'anonymous';

    // consume 1 point for this run
    try {
      await limiter.consume(key, 1);
    } catch (rl) {
      return res.status(429).json({ error: 'rate_limited', message: 'Too many runs, try later' });
    }

    let vol = parseInt(volume || 0, 10) || 0;
    if (vol <= 0) return res.status(400).json({ error: 'invalid_volume' });
    if (vol > STRESS_MAX_VOLUME) vol = STRESS_MAX_VOLUME;

    const start = Date.now();
    const result = await runRequestsInBatches(parsed.toString(), vol);
    const end = Date.now();

    return res.json({
      sent: result.sent,
      sucessos: result.successes,
      falhas: result.fails,
      tempo_total_ms: end - start,
      resultado: result.fails > 0 ? 'POTENCIALLY IMPACTED' : 'ESTÁVEL',
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message || 'internal_error' });
  }
});

// Endpoint: SSE stream -> GET /api/stresser/stream?url=...&volume=...&token=...
// Streams progress events as they occur, then final event 'done'
app.get('/api/stresser/stream', async (req, res) => {
  // Set SSE headers
  res.set({
    'Cache-Control': 'no-cache',
    'Content-Type': 'text/event-stream',
    Connection: 'keep-alive',
  });
  res.flushHeaders();

  let decoded;
  try {
    decoded = await verifyTokenFromReq(req);
  } catch (err) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: 'auth_failed', message: err.message })}\n\n`);
    return res.end();
  }

  const key = decoded.uid || decoded.sub || decoded.email || 'anonymous';
  try {
    await limiter.consume(key, 1);
  } catch (rl) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: 'rate_limited', message: 'Too many runs, try later' })}\n\n`);
    return res.end();
  }

  let targetUrl = req.query.url;
  let volume = parseInt(req.query.volume || '0', 10);
  if (!targetUrl || !volume) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: 'missing_params' })}\n\n`);
    return res.end();
  }

  try {
    const parsed = validateTargetUrl(targetUrl);
    if (volume > STRESS_MAX_VOLUME) volume = STRESS_MAX_VOLUME;

    // keep connection open while running
    const start = Date.now();
    let sentSoFar = 0;
    let successes = 0;
    let fails = 0;

    // progress callback sends SSE for each packet
    const progressCb = (packet) => {
      // packet = { idx, ok, status, err? }
      if (packet.ok) successes++; else fails++;
      sentSoFar = packet.idx;
      const data = { idx: packet.idx, ok: packet.ok, status: packet.status, err: packet.err || null, sentSoFar, successes, fails };
      res.write(`event: packet\ndata: ${JSON.stringify(data)}\n\n`);
    };

    // also send periodic heartbeat/progress if desired
    const heartbeat = setInterval(() => {
      res.write(`event: heartbeat\ndata: ${JSON.stringify({ sentSoFar, successes, fails })}\n\n`);
    }, 2000);

    const final = await runRequestsInBatches(parsed.toString(), volume, {}, progressCb);
    clearInterval(heartbeat);
    const end = Date.now();

    const finalData = {
      sent: final.sent,
      sucessos: final.successes,
      falhas: final.fails,
      tempo_total_ms: end - start,
      resultado: final.fails > 0 ? 'POTENCIALMENTE IMPACTADO' : 'ESTÁVEL',
    };

    res.write(`event: done\ndata: ${JSON.stringify(finalData)}\n\n`);
    return res.end();
  } catch (e) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: e.message })}\n\n`);
    return res.end();
  }
});

// --- INICIALIZAÇÃO ---
app.listen(PORT, () => console.log(`🚀 VM Security API Unificada rodando na porta ${PORT}`));
