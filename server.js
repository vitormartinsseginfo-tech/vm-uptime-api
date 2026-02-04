const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const net = require('net');
const UserAgent = require('user-agents');
const adminModuleName = 'firebase-admin'; // require só se configurado


const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');


app.get('/', (req, res) => {
  res.status(200).send('API de Monitoramento Online ✅');
});

// --- CONFIGURAÇÃO DE CORS (Aceita subdomínios de vmblue e vm-security) ---
app.use((req, res, next) => {
  const origin = req.headers.origin;

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

  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ============================================================
// 1. FERRAMENTA: HUNTER (CONTATOS)
// ============================================================
app.all('/hunt', async (req, res) => {
  const target = (req.query.url || req.body.url || '').trim();
  if (!target) return res.status(400).json({ error: 'URL missing' });
  try {
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    const url = target.startsWith('http') ? target : 'http://' + target;
    const resp = await client.get(url, { headers: { 'User-Agent': ua } });
    const html = resp.data || '';
    const emails = [...new Set((html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []))];
    const phones = [...new Set((html.match(/(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g) || []))];
    res.json({ emails, phones, socials: [] });
  } catch (e) {
    res.status(500).json({ error: e.message || 'fetch_error' });
  }
});

// ============================================================
// 2. FERRAMENTA: VULNERABILITY (SCANNER)
// ============================================================
app.all(['/scan', '/api/scan'], async (req, res) => {
  const target = (req.query.url || req.body.url || '').trim();
  if (!target) return res.status(400).json({ error: 'URL missing' });
  try {
    const url = target.startsWith('http') ? target : 'http://' + target;
    const resp = await client.get(url, { headers: { 'User-Agent': new UserAgent().toString() }, validateStatus: () => true });
    const h = resp.headers || {};
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
  } catch (e) {
    res.status(500).json({ error: e.message || 'scan_error' });
  }
});

// --- NOVA FERRAMENTA: PORT SCANNER ---
app.get('/api/portcheck', async (req, res) => {
  try {
    let target = (req.query.target || '').trim();
    if (!target) return res.json({ error: 'Alvo ausente', results: [] });

    const cleanTarget = target.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].split(':')[0];

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

    const checkPort = (port, host) => new Promise(resolve => {
      const socket = new net.Socket();
      socket.setTimeout(2000);
      socket.on('connect', () => { socket.destroy(); resolve('Aberta'); });
      socket.on('timeout', () => { socket.destroy(); resolve('Fechada/Filtrada'); });
      socket.on('error', () => { socket.destroy(); resolve('Fechada'); });
      socket.connect(port, host);
    });

    const results = [];
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
let admin = null;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    admin = require(adminModuleName);
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('Firebase Admin init ok');
  } else {
    console.warn('FIREBASE_SERVICE_ACCOUNT não configurado (Firebase Admin não inicializado)');
  }
} catch (err) {
  console.warn('firebase-admin não inicializado:', err.message);
}

// middleware para validar token Firebase (expect: Authorization: Bearer <idToken>)
async function verifyFirebaseToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'NO_TOKEN' });
  const idToken = auth.split(' ')[1];
  if (!admin || !admin.apps || !admin.apps.length) return res.status(500).json({ error: 'FIREBASE_NOT_CONFIGURED' });
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

  const deEmail = process.env.DEHASHED_EMAIL;
  const deKey = process.env.DEHASHED_API_KEY;
  if (!deEmail || !deKey) {
    return res.status(503).json({
      error: 'DEHASHED_NOT_CONFIGURED',
      message: 'Adicione DEHASHED_EMAIL e DEHASHED_API_KEY nas Environment Variables e redeploy.'
    });
  }

  const cacheKey = `dehashed:${type}:${query.toLowerCase()}`;
  const cached = dehashedCache.get(cacheKey);
  if (cached && (Date.now() - cached.ts) < CACHE_TTL_MS) return res.json(cached.data);

  try {
    const auth = Buffer.from(`${deEmail}:${deKey}`).toString('base64');
    const url = `https://api.dehashed.com/light?query=${encodeURIComponent(query)}`;
    const resp = await client.get(url, {
      headers: { 'Accept': 'application/json', 'Authorization': `Basic ${auth}` },
      timeout: 15000
    });

    const entries = resp.data?.entries || resp.data?.records || (Array.isArray(resp.data) ? resp.data : []);
    const total = resp.data?.total || entries.length || 0;
    const out = { total, entries };
    dehashedCache.set(cacheKey, { ts: Date.now(), data: out });
    return res.json(out);
  } catch (err) {
    console.error('Dehashed API error', err.response ? err.response.data : err.message);
    const status = err.response?.status || 500;
    return res.status(status).json({ error: 'DEHASHED_ERROR', details: err.response?.data || err.message });
  }
});

// --- VMIntelligence module (safe insert v2) ---
(function () {
  if (typeof app === 'undefined' || typeof axios === 'undefined') {
    console.error('VMIntelligence: app ou axios não definidos.');
    return;
  }
  if (!global.VMIntelligence) global.VMIntelligence = { routesAdded: false };
  if (global.VMIntelligence.routesAdded) { console.log('VMIntelligence já carregado.'); return; }

  const VT_API_KEY = process.env.VT_API_KEY || '';
  const ABUSE_API_KEY = process.env.ABUSE_API_KEY || '';
  const cacheLocal = new Map();

  const isIP = s => /^(?:\d{1,3}\.){3}\d{1,3}$/.test((s || '').trim());
  const isHash = s => /^[a-fA-F0-9]{32,64}$/.test((s || '').trim());

  async function vtGetIP(ip) {
    const res = await client.get(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': VT_API_KEY } });
    return res.data;
  }
  async function vtGetDomain(domain) {
    const res = await client.get(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { 'x-apikey': VT_API_KEY } });
    return res.data;
  }
  async function vtGetFile(hash) {
    const res = await client.get(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': VT_API_KEY } });
    return res.data;
  }
  async function abuseCheckIP(ip) {
    const res = await client.get('https://api.abuseipdb.com/api/v2/check', {
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
    } catch (err) {
      res.status(500).json({ error: err.message || 'vmint_error' });
    }
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
      } catch (e) {
        results.push({ target: t, error: e.message });
      }
    }
    res.json({ malicious: results.filter(r => r.classification?.malicious), clean: results.filter(r => !r.classification?.malicious), all: results });
  });

  global.VMIntelligence.routesAdded = true;
  console.log('✅ VMIntelligence carregado com sucesso.');
})();

// --- STRESSER (inlined safe module) ---
(function registerStresserInline() {
  let RateLimiterMemory;
  try {
    RateLimiterMemory = require('rate-limiter-flexible').RateLimiterMemory;
  } catch (e) {
    console.warn('rate-limiter-flexible não disponível. Instale: npm install rate-limiter-flexible');
    RateLimiterMemory = null;
  }

  const axiosClient = (typeof client !== 'undefined' && client) ? client : require('axios').create({ timeout: 15000 });
  const UserAgent = (() => {
    try { return require('user-agents'); } catch { return null; }
  })();

  // Configs (env override)
const STRESS_MAX_VOLUME = parseInt(process.env.STRESS_MAX_VOLUME || '1000', 10);
const STRESS_RATE_POINTS = parseInt(process.env.STRESS_RATE_POINTS || '100', 10);   // 100 requisições
const STRESS_RATE_DURATION = parseInt(process.env.STRESS_RATE_DURATION || '60', 10); // por 60 segundos (1 minuto)
const STRESS_BATCH_SIZE = parseInt(process.env.STRESS_BATCH_SIZE || '20', 10);
const STRESS_BATCH_INTERVAL_MS = parseInt(process.env.STRESS_BATCH_INTERVAL_MS || '1000', 10);
const STRESS_MAX_CONCURRENCY = parseInt(process.env.STRESS_MAX_CONCURRENCY || '5', 10);

  // Allowlist (CSV)
  const ALLOWED_HOSTS = (process.env.STRESS_ALLOWED_HOSTS || 'localhost,127.0.0.1')
    .split(',').map(s => s.trim()).filter(Boolean);

  const ALLOW_STRESS = (process.env.ALLOW_STRESS === 'yes');

  // Rate limiter (in-memory)
  const stressLimiter = RateLimiterMemory ? new RateLimiterMemory({
    points: STRESS_RATE_POINTS,
    duration: STRESS_RATE_DURATION
  }) : null;

  function isHostAllowed(urlStr) {
    try {
      const u = new URL(urlStr);
      const host = u.hostname.toLowerCase();
      if (ALLOWED_HOSTS.includes('*')) return true;
      return ALLOWED_HOSTS.some(ah => {
        ah = ah.toLowerCase();
        if (ah.startsWith('*.')) {
          return host === ah.slice(2) || host.endsWith('.' + ah.slice(2));
        }
        return host === ah || host.endsWith('.' + ah);
      });
    } catch (e) {
      return false;
    }
  }

  async function runRequestsInBatches(target, total, batchSize = STRESS_BATCH_SIZE, timeoutMs = 8000) {
    const results = [];
    const rounds = Math.ceil(total / batchSize);

    for (let r = 0; r < rounds; r++) {
      const startIndex = r * batchSize;
      const currentBatchSize = Math.min(batchSize, total - startIndex);
      const tasks = [];

      for (let i = 0; i < currentBatchSize; i++) {
        const idx = startIndex + i;
        const task = (async () => {
          const start = Date.now();
          try {
            const resp = await axiosClient.request({
              url: target,
              method: 'GET',
              timeout: timeoutMs,
              headers: {
                'User-Agent': (UserAgent ? new UserAgent({ deviceCategory: 'desktop' }).toString() : 'vm-security-stresser/1.0'),
                'Accept': '*/*'
              },
              validateStatus: () => true
            });
            const ms = Date.now() - start;
            return { index: idx, status: resp.status, ok: resp.status >= 200 && resp.status < 400, ms };
          } catch (err) {
            const ms = Date.now() - start;
            return { index: idx, error: err.message || 'request_error', ms };
          }
        })();
        tasks.push(task);

        // If we reached concurrency limit, await a chunk to avoid huge parallel bursts
        if (tasks.length >= STRESS_MAX_CONCURRENCY) {
          const settled = await Promise.allSettled(tasks.splice(0, tasks.length));
          settled.forEach(s => {
            if (s.status === 'fulfilled') results.push(s.value);
            else results.push({ error: s.reason?.message || 'task_rejected' });
          });
        }
      }

      // flush remaining tasks
      if (tasks.length) {
        const settled = await Promise.allSettled(tasks);
        settled.forEach(s => {
          if (s.status === 'fulfilled') results.push(s.value);
          else results.push({ error: s.reason?.message || 'task_rejected' });
        });
      }

      // interval between batches
      if (r < rounds - 1) {
        await new Promise(resolve => setTimeout(resolve, STRESS_BATCH_INTERVAL_MS));
      }
    }

    return results;
  }

  // Health/info (no auth)
  app.get('/api/stresser/health', (req, res) => {
    return res.json({
      ok: true,
      allowStress: ALLOW_STRESS,
      allowedHosts: ALLOWED_HOSTS,
      maxVolume: STRESS_MAX_VOLUME,
      ratePoints: STRESS_RATE_POINTS,
      rateDuration: STRESS_RATE_DURATION
    });
  });

  // Main endpoint (supports GET and POST). Requires verifyFirebaseToken to be present in server.js scope.
  app.all('/api/stresser', async (req, res) => {
    // verifyFirebaseToken must run before allowing the action; if it's defined, call it
    if (typeof verifyFirebaseToken === 'function') {
      let tokenOk = false, nextCalled = false, tokenErr = null;
      await new Promise(resolve => {
        try {
          verifyFirebaseToken(req, res, (err) => {
            nextCalled = true;
            if (err) tokenErr = err;
            else tokenOk = true;
            resolve();
          });
        } catch (e) {
          tokenErr = e;
          resolve();
        }
      });
      if (!tokenOk && tokenErr) {
        // verifyFirebaseToken already sent a response (401/500) in most implementations
        if (!res.headersSent) return res.status(401).json({ error: 'INVALID_TOKEN' });
        return;
      }
    }

    if (!ALLOW_STRESS) return res.status(403).json({ error: 'STRESS_DISABLED', message: 'Stress tests are disabled on this instance (set ALLOW_STRESS=yes).' });

    const source = req.method === 'GET' ? req.query : req.body || {};
    let target = (source.url || source.target || '').trim();
    let volume = parseInt(source.volume || source.requests || '10', 10);

    if (!target) return res.status(400).json({ error: 'target_missing' });
    if (!/^https?:\/\//i.test(target)) return res.status(400).json({ error: 'target_must_start_with_http' });

    if (isNaN(volume) || volume < 1) volume = 1;
    if (volume > STRESS_MAX_VOLUME) volume = STRESS_MAX_VOLUME;

    // Rate limit per user (req.user may be set by verifyFirebaseToken)
    const uid = (req.user && req.user.uid) ? req.user.uid : (req.ip || 'unknown');
    if (stressLimiter) {
      try {
        await stressLimiter.consume(uid);
      } catch (e) {
        return res.status(429).json({ error: 'rate_limited' });
      }
    }

    // Allowlist check
    if (!isHostAllowed(target)) {
      return res.status(403).json({ error: 'host_not_allowed', message: `Host não permitido. Allowed: ${ALLOWED_HOSTS.join(', ')}` });
    }

    console.log(`[STRESS] uid=${uid} target=${target} volume=${volume}`);

    try {
      const t0 = Date.now();
      const results = await runRequestsInBatches(target, volume, STRESS_BATCH_SIZE, 8000);
      const t1 = Date.now();
      const success = results.filter(r => r.ok).length;
      const fail = results.length - success;
      const resultado = fail > Math.floor(volume * 0.3) ? 'VULNERÁVEL' : 'ESTÁVEL';
      const tempo_total_ms = t1 - t0;

      return res.json({
        alvo: target,
        requisicoes: volume,
        sucessos: success,
        falhas: fail,
        resultado,
        tempo_total_ms,
        sample: results.slice(0, 200)
      });
    } catch (err) {
      console.error('STRESS ERROR', err);
      return res.status(500).json({ error: 'internal_error', details: err.message });
    }
  });

  console.log('Stresser inline registered (ALLOW_STRESS=' + (ALLOW_STRESS ? 'yes' : 'no') + ').');
})();

// --- INICIALIZAÇÃO ---
app.listen(PORT, () => console.log(`🚀 VM Security API Unificada rodando na porta ${PORT}`));
