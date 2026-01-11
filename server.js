const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';

app.use(cors({
    origin: true, // Permite seu domínio do Pages
    credentials: true
}));

// Tabela de sites
pool.query(`
    CREATE TABLE IF NOT EXISTS monitor_sites (
        id SERIAL PRIMARY KEY,
        url TEXT NOT NULL,
        status TEXT DEFAULT 'pendente',
        last_check TIMESTAMP
    )
`);

// Login
app.post('/login', (req, res) => {
    if (req.body.password === PANEL_PASSWORD) {
        res.cookie('vm_uptime_auth', 'true', { httpOnly: true, secure: true, sameSite: 'none', maxAge: 86400000 });
        return res.json({ success: true });
    }
    res.status(401).json({ error: 'Incorreto' });
});

// Listar sites
app.get('/sites', async (req, res) => {
    if (req.cookies.vm_uptime_auth !== 'true') return res.status(401).send();
    const result = await pool.query('SELECT * FROM monitor_sites ORDER BY id DESC');
    res.json(result.rows);
});

// Adicionar site
app.post('/sites', async (req, res) => {
    if (req.cookies.vm_uptime_auth !== 'true') return res.status(401).send();
    const { url } = req.body;
    await pool.query('INSERT INTO monitor_sites (url) VALUES ($1)', [url]);
    res.json({ success: true });
});

// Função de Checagem Automática
async function checkAll() {
    const sites = await pool.query('SELECT * FROM monitor_sites');
    for (let site of sites.rows) {
        try {
            await axios.get(site.url, { timeout: 10000 });
            await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['online', site.id]);
        } catch (err) {
            await pool.query('UPDATE monitor_sites SET status = $1, last_check = NOW() WHERE id = $2', ['offline', site.id]);
        }
    }
}

// Checa a cada 5 minutos
setInterval(checkAll, 5 * 60 * 1000);

app.listen(process.env.PORT || 3000);
