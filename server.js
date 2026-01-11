<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>VM Security | Uptime Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0b0e14; --card: #151921; --primary: #FF7A18; --text: #f8fafc; --online: #22c55e; --offline: #ef4444; --warning: #eab308; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; margin: 0; padding: 20px; display: flex; justify-content: center; }
        .container { width: 100%; max-width: 900px; }
        
        #login-screen { text-align: center; margin-top: 100px; }
        .login-box { background: var(--card); padding: 40px; border-radius: 20px; border: 1px solid #2d3748; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        
        #main-panel { display: none; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { font-weight: 800; font-size: 1.8rem; margin: 0; }
        
        .controls { display: flex; gap: 12px; margin-bottom: 30px; background: var(--card); padding: 20px; border-radius: 16px; border: 1px solid #2d3748; }
        input { flex: 1; padding: 14px; border-radius: 10px; border: 1px solid #2d3748; background: #000; color: #fff; font-size: 1rem; }
        
        button { padding: 14px 24px; border: none; border-radius: 10px; font-weight: 700; cursor: pointer; transition: 0.2s; }
        .btn-add { background: var(--primary); color: #000; }
        .btn-refresh { background: #2d3748; color: #fff; }
        .btn-refresh:hover { background: #4a5568; }
        
        .site-card { background: var(--card); padding: 20px; border-radius: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; border: 1px solid #2d3748; transition: 0.3s; }
        .site-card:hover { transform: translateX(5px); border-color: #4a5568; }
        .site-card.online { border-left: 6px solid var(--online); }
        .site-card.offline { border-left: 6px solid var(--offline); }
        
        .site-info h3 { margin: 0; font-size: 1.1rem; display: flex; align-items: center; gap: 8px; }
        .metrics { display: flex; gap: 20px; margin-top: 10px; font-size: 0.8rem; color: #94a3b8; }
        .metric-item { display: flex; align-items: center; gap: 5px; }
        
        .status-badge { padding: 6px 14px; border-radius: 30px; font-size: 0.75rem; font-weight: 800; letter-spacing: 0.5px; }
        .status-online { background: rgba(34, 197, 94, 0.15); color: var(--online); }
        .status-offline { background: rgba(239, 68, 68, 0.15); color: var(--offline); }
        
        .btn-del { background: transparent; color: #4a5568; font-size: 1.2rem; border: none; cursor: pointer; padding: 5px; }
        .btn-del:hover { color: var(--offline); }

        .loading-bar { height: 3px; background: var(--primary); width: 0%; position: fixed; top: 0; left: 0; transition: 0.4s; z-index: 100; }
    </style>
</head>
<body>
    <div id="loading" class="loading-bar"></div>

    <div id="login-screen" class="container">
        <div class="login-box">
            <img src="https://cdn.abacus.ai/images/dc529c8e-179f-41fe-b4d9-b97bb317831e.png" width="60">
            <h2 style="margin: 20px 0;">VM Security Monitor</h2>
            <input type="password" id="passInput" placeholder="Sua senha mestra">
            <button class="btn-add" onclick="login()" style="width: 100%; margin-top: 20px;">ENTRAR NO DASHBOARD</button>
        </div>
    </div>

    <div id="main-panel" class="container">
        <div class="header">
            <div>
                <h1>Uptime Monitor</h1>
                <p id="update-timer" style="color: #64748b; margin: 5px 0 0 0; font-size: 0.85rem;"></p>
            </div>
            <button onclick="location.reload()" style="background:none; color:#64748b; font-weight: normal;">Sair</button>
        </div>

        <div class="controls">
            <input type="text" id="newSite" placeholder="https://www.cliente.com.br">
            <button class="btn-add" onclick="addSite()">MONITORAR</button>
            <button class="btn-refresh" id="refreshBtn" onclick="forceUpdate()">🔄 ATUALIZAR</button>
        </div>

        <div id="siteList"></div>
    </div>

    <script>
        const API_URL = 'https://vm-uptime-api.onrender.com';
        let timer = 30;

        async function login() {
            const password = document.getElementById('passInput').value;
            const resp = await fetch(`${API_URL}/api/login`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                credentials: 'include', body: JSON.stringify({ password })
            });
            if (resp.ok) {
                document.getElementById('login-screen').style.display = 'none';
                document.getElementById('main-panel').style.display = 'block';
                loadSites();
                setInterval(() => {
                    timer--;
                    document.getElementById('update-timer').innerText = `Próxima atualização em ${timer}s`;
                    if(timer <= 0) loadSites();
                }, 1000);
            } else { alert("Acesso negado!"); }
        }

        async function loadSites() {
            document.getElementById('loading').style.width = '40%';
            const resp = await fetch(`${API_URL}/api/sites`, { credentials: 'include' });
            const sites = await resp.json();
            
            const list = document.getElementById('siteList');
            list.innerHTML = '';
            sites.forEach(site => {
                const isOnline = site.status === 'online';
                const isHttps = site.url.startsWith('https');
                const ms = site.response_ms || 0;
                let msColor = '#22c55e';
                if(ms > 600) msColor = '#eab308';
                if(ms > 1500) msColor = '#ef4444';

                list.innerHTML += `
                    <div class="site-card ${site.status}">
                        <div class="site-info">
                            <h3>
                                <span title="${isHttps ? 'SSL Protegido' : 'Inseguro'}">${isHttps ? '🛡️' : '⚠️'}</span>
                                ${site.url}
                            </h3>
                            <div class="metrics">
                                <div class="metric-item">⚡ <b style="color:${msColor}">${ms}ms</b></div>
                                <div class="metric-item">🕒 ${site.last_check ? new Date(site.last_check).toLocaleTimeString() : '---'}</div>
                                <div class="metric-item">${isHttps ? '🔒 HTTPS' : '🔓 HTTP'}</div>
                            </div>
                        </div>
                        <div style="display:flex; align-items:center; gap:20px;">
                            <span class="status-badge ${isOnline ? 'status-online' : 'status-offline'}">
                                ${isOnline ? '● ONLINE' : '○ OFFLINE'}
                            </span>
                            <button class="btn-del" onclick="deleteSite(${site.id})">🗑️</button>
                        </div>
                    </div>
                `;
            });
            document.getElementById('loading').style.width = '100%';
            setTimeout(() => document.getElementById('loading').style.width = '0%', 400);
            timer = 30;
        }

        async function forceUpdate() {
            const btn = document.getElementById('refreshBtn');
            btn.innerText = '⌛...';
            await fetch(`${API_URL}/api/check-now`, { method: 'POST', credentials: 'include' });
            await loadSites();
            btn.innerText = '🔄 ATUALIZAR';
        }

        async function addSite() {
            const url = document.getElementById('newSite').value;
            if(!url) return;
            await fetch(`${API_URL}/api/sites`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                credentials: 'include', body: JSON.stringify({ url })
            });
            document.getElementById('newSite').value = '';
            loadSites();
        }

        async function deleteSite(id) {
            if(!confirm('Remover monitoramento?')) return;
            await fetch(`${API_URL}/api/sites/${id}`, { method: 'DELETE', credentials: 'include' });
            loadSites();
        }
    </script>
</body>
</html>
