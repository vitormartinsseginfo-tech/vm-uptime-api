// server.js - SUPER SERVIDOR VM SECURITY (UNIFICADO) - v5 TURBO
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000');
const MASTER_KEY = process.env.MASTER_KEY || null;

// CORS REFLEXIVO
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 25000, // Aumentado para sites lentos
    maxRedirects: 5
});

// BANCO DE DADOS JSON
let DB = { sites: [] };
function loadData() {
    if (fs.existsSync(DATA_FILE)) {
        try { DB = JSON.parse(fs.readFileSync(DATA_FILE)); } catch (e) {}
    }
}
function saveData() { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2)); }
loadData();

// AUTH MIDDLEWARE
async function requireAuth(req, res, next) {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
    const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
    if (MASTER_KEY && mk === MASTER_KEY) return next();
    next();
}

// --- ROTAS ---

// ROTA DO VULNERABILITY (DETECÇÃO AVANÇADA)
const analyzeHandler = async (req, res) => {
    let targetUrl = req.query.url || (req.body && req.body.url);
    if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
    if (!targetUrl.startsWith('http')) targetUrl = 'http://' + targetUrl;

    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const resp = await client.get(targetUrl, { headers: { 'User-Agent': ua }, validateStatus: () => true });
        const h = resp.headers || {};
        
        // Lógica de detecção melhorada
        const server = h['server'] || h['via'] || (h['x-cache'] ? 'Cache/CDN' : 'Não detectado');
        const tech = h['x-powered-by'] || h['x-aspnet-version'] || h['x-generator'] || (h['set-cookie'] && h['set-cookie'].some(c => c.includes('PHPSESSID')) ? 'PHP' : 'Não detectada');

        res.json({
            status: resp.status,
            server: server,
            technology: tech,
            securityHeaders: {
                'x-frame-options': h['x-frame-options'] || 'MISSING',
                'strict-transport-security': h['strict-transport-security'] || 'MISSING',
                'content-security-policy': h['content-security-policy'] || 'MISSING',
                'x-content-type-options': h['x-content-type-options'] || 'MISSING'
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
};
app.get('/api/scan', requireAuth, analyzeHandler);
app.post('/api/scan', requireAuth, analyzeHandler);

// ROTAS DO 24x7
app.get('/api/sites', requireAuth, (req, res) => {
    res.json(DB.sites.map(s => ({ id: s.id, url: s.url, name: s.name, lastCheck: s.lastCheck })));
});

app.post('/api/sites', requireAuth, async (req, res) => {
    const { url, name } = req.body;
    const site = { id: Date.now().toString(36), url, name: name || url, lastCheck: null };
    DB.sites.push(site);
    await checkSite(site);
    saveData();
    res.json(site);
});

app.post('/api/check-now', requireAuth, async (req, res) => {
    await runChecks();
    res.json({ ok: true, summary: DB.sites.map(s => ({ id: s.id, url: s.url, lastCheck: s.lastCheck })) });
});

// FUNÇÃO DE CHECAGEM (COM USER-AGENT REAL)
async function checkSite(site) {
    const start = Date.now();
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const resp = await client.get(site.url, { 
            headers: { 'User-Agent': ua },
            validateStatus: () => true 
        });
        site.lastCheck = { 
            at: new Date().toISOString(), 
            up: resp.status < 400, 
            status: resp.status, 
            latency: Date.now() - start 
        };
    } catch (e) {
        site.lastCheck = { at: new Date().toISOString(), up: false, error: e.message };
    }
}

async function runChecks() {
    for (const s of DB.sites) await checkSite(s);
    saveData();
}
setInterval(runChecks, MONITOR_INTERVAL);

app.get('/', (req, res) => res.json({ status: 'online' }));
app.listen(PORT, () => console.log(`🚀 Servidor na porta ${PORT}`));
