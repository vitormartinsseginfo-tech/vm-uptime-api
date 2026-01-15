const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');

// CORS para todos os seus subdomínios
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

let DB = { sites: [] };
if (fs.existsSync(DATA_FILE)) {
    try { DB = JSON.parse(fs.readFileSync(DATA_FILE)); } catch (e) {}
}
const saveData = () => fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 15000
});

// --- ROTA HUNTER (CORRIGIDA) ---
app.all('/hunt', async (req, res) => {
    const target = req.query.url || req.body.url;
    if (!target) return res.status(400).json({ error: 'URL missing' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const resp = await client.get(target.startsWith('http') ? target : 'http://' + target, { headers: { 'User-Agent': ua } });
        const html = resp.data || '';
        const emails = [...new Set(html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
        const phones = [...new Set(html.match(/(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g) || [])];
        res.json({ emails, phones, socials: [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- ROTA VULNERABILITY (COM TESTES REAIS) ---
app.all(['/scan', '/api/scan'], async (req, res) => {
    const target = req.query.url || req.body.url;
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
            detected_server: h['server'] || 'Cloudflare/Protegido',
            detected_tech: h['x-powered-by'] || 'Nginx/Web',
            vulnerabilities: vulns
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- ROTA 24x7 (CORRIGIDA) ---
app.get(['/sites', '/api/sites'], (req, res) => {
    res.json(DB.sites.map(s => ({ ...s, status: s.status || 'offline', response_ms: s.response_ms || 0 })));
});

app.post(['/sites', '/api/sites'], async (req, res) => {
    const site = { id: Date.now().toString(36), url: req.body.url, status: 'online', response_ms: 50, last_check: new Date().toISOString() };
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
    for (const s of DB.sites) {
        try {
            const start = Date.now();
            const r = await client.get(s.url, { headers: { 'User-Agent': new UserAgent().toString() }, validateStatus: () => true });
            s.status = r.status < 400 ? 'online' : 'offline';
            s.response_ms = Date.now() - start;
            s.last_check = new Date().toISOString();
        } catch (e) { s.status = 'offline'; }
    }
    saveData();
    res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
