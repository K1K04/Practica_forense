#!/usr/bin/env python3
"""
=============================================================
  RA2 - Visor / Analizador de capturas mitmproxy
  Genera informe HTML + resumen en terminal
  Curso: GS Ciberseguridad | Análisis Forense
=============================================================

USO:
  python3 forense_viewer.py captura_app1.mitm
  python3 forense_viewer.py captura_app1.mitm --output informe.html
  python3 forense_viewer.py captura_app1.mitm --filter google
  python3 forense_viewer.py captura_app1.mitm --show-bodies

DEPENDENCIAS:
  pip install mitmproxy
"""

import argparse
import sys
import json
import html as html_mod
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

# ─── mitmproxy reader ────────────────────────────────────────────────────────

def load_flows(path: str):
    try:
        from mitmproxy.io import FlowReader
        from mitmproxy.http import HTTPFlow
    except ImportError:
        print("[!] mitmproxy no está instalado: pip install mitmproxy")
        sys.exit(1)

    flows = []
    with open(path, "rb") as f:
        reader = FlowReader(f)
        for flow in reader.stream():
            if isinstance(flow, HTTPFlow):
                flows.append(flow)
    return flows

# ─── Colores terminal ─────────────────────────────────────────────────────────

class C:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def col(color: str, text: str) -> str:
    return f"{color}{text}{C.RESET}"

def status_color(code: int) -> str:
    if code < 300:   return C.GREEN
    if code < 400:   return C.CYAN
    if code < 500:   return C.YELLOW
    return C.RED

# ─── Análisis ─────────────────────────────────────────────────────────────────

def analyze(flows, filter_host: str = None):
    stats = {
        "total": 0,
        "https": 0,
        "http": 0,
        "intercepted": 0,
        "blocked": 0,
        "hosts": Counter(),
        "methods": Counter(),
        "content_types": Counter(),
        "status_codes": Counter(),
        "sensitive_keywords": [],
        "cleartext_data": [],
        "https_intercepted": [],   # HTTPS que sí pudimos descifrar
        "pinning_detected": [],    # hosts que bloquearon el proxy
    }

    filtered = []
    for flow in flows:
        host = flow.request.pretty_host
        if filter_host and filter_host.lower() not in host.lower():
            continue
        filtered.append(flow)

        stats["total"] += 1
        scheme = flow.request.scheme
        stats[scheme] += 1
        stats["hosts"][host] += 1
        stats["methods"][flow.request.method] += 1

        if flow.response:
            stats["intercepted"] += 1
            stats["status_codes"][flow.response.status_code] += 1
            ct = flow.response.headers.get("content-type", "unknown").split(";")[0]
            stats["content_types"][ct] += 1

            # Buscar datos sensibles en cuerpo de respuesta
            try:
                body = flow.response.get_text(strict=False) or ""
                keywords = ["password", "token", "api_key", "secret", "auth",
                            "email", "user", "login", "session", "Bearer", "access_token"]
                found = [k for k in keywords if k.lower() in body.lower()]
                if found:
                    stats["sensitive_keywords"].append({
                        "host": host,
                        "url": flow.request.pretty_url,
                        "keywords": found,
                    })
            except Exception:
                pass

            # Tráfico en claro (HTTP sin cifrar)
            if scheme == "http":
                try:
                    req_body = flow.request.get_text(strict=False) or ""
                    if req_body.strip():
                        stats["cleartext_data"].append({
                            "host": host,
                            "method": flow.request.method,
                            "url": flow.request.pretty_url,
                            "body_snippet": req_body[:300],
                        })
                except Exception:
                    pass
            # HTTPS interceptado en claro
            if scheme == "https":
                try:
                    resp_body = flow.response.get_text(strict=False) or ""
                    req_body  = flow.request.get_text(strict=False) or ""
                    ct = flow.response.headers.get("content-type", "-").split(";")[0]
                    stats["https_intercepted"].append({
                        "host":      host,
                        "method":    flow.request.method,
                        "url":       flow.request.pretty_url,
                        "status":    flow.response.status_code,
                        "ct":        ct,
                        "req_body":  req_body[:400],
                        "resp_body": resp_body[:400],
                    })
                except Exception:
                    pass
        else:
            stats["blocked"] += 1
            # Posible certificate pinning
            stats["pinning_detected"].append({
                "host":   host,
                "url":    flow.request.pretty_url,
                "scheme": scheme,
            })

    return filtered, stats

# ─── Resumen terminal ─────────────────────────────────────────────────────────

def print_summary(flows, stats):
    print(f"\n{C.BOLD}{C.CYAN}{'═'*60}")
    print(f"  RESUMEN DE CAPTURA")
    print(f"{'═'*60}{C.RESET}")
    print(f"  Total flows       : {C.BOLD}{stats['total']}{C.RESET}")
    print(f"  HTTPS             : {C.GREEN}{stats['https']}{C.RESET}")
    print(f"  HTTP (claro)      : {C.RED}{stats['http']}{C.RESET}")
    print(f"  Interceptados OK  : {C.GREEN}{stats['intercepted']}{C.RESET}")
    print(f"  Bloqueados/Error  : {C.YELLOW}{stats['blocked']}{C.RESET}  ← posible certificate pinning")

    print(f"\n{C.BOLD}  Top 10 hosts contactados:{C.RESET}")
    for host, count in stats["hosts"].most_common(10):
        bar = "█" * min(count, 40)
        print(f"  {C.CYAN}{host:<45}{C.RESET}  {count:>4}  {C.DIM}{bar}{C.RESET}")

    print(f"\n{C.BOLD}  Métodos HTTP:{C.RESET}")
    for method, count in stats["methods"].most_common():
        print(f"    {C.YELLOW}{method:<8}{C.RESET}  {count}")

    print(f"\n{C.BOLD}  Content-Types en respuestas:{C.RESET}")
    for ct, count in stats["content_types"].most_common(8):
        print(f"    {ct:<40}  {count}")

    if stats["sensitive_keywords"]:
        print(f"\n{C.RED}{C.BOLD}  ⚠ POSIBLES DATOS SENSIBLES DETECTADOS:{C.RESET}")
        for item in stats["sensitive_keywords"][:10]:
            print(f"  {C.RED}→ {item['host']}{C.RESET}")
            print(f"    URL: {item['url']}")
            print(f"    Keywords: {', '.join(item['keywords'])}")

    if stats["cleartext_data"]:
        print(f"\n{C.RED}{C.BOLD}  ⚠ DATOS EN CLARO (HTTP):{C.RESET}")
        for item in stats["cleartext_data"][:5]:
            print(f"  {C.RED}→ [{item['method']}] {item['url']}{C.RESET}")
            print(f"    Body: {item['body_snippet'][:150]}")

    if stats["https_intercepted"]:
        print(f"\n{C.GREEN}{C.BOLD}  ✓ HTTPS INTERCEPTADOS EN CLARO ({len(stats['https_intercepted'])} flows):{C.RESET}")
        for item in stats["https_intercepted"][:8]:
            print(f"  {C.GREEN}→ [{item['method']}] {item['url']}{C.RESET}")
            print(f"    Status: {item['status']}  |  Content-Type: {item['ct']}")
            if item["resp_body"].strip():
                snippet = item["resp_body"][:200].replace("\n", " ")
                print(f"    {C.DIM}Respuesta: {snippet}{C.RESET}")

    if stats["pinning_detected"]:
        hosts_pin = list({i["host"] for i in stats["pinning_detected"]})
        print(f"\n{C.YELLOW}{C.BOLD}  🔒 CERTIFICATE PINNING DETECTADO ({len(hosts_pin)} hosts):{C.RESET}")
        for h in hosts_pin[:10]:
            print(f"  {C.YELLOW}→ {h}{C.RESET}  (bloqueó el proxy)")

    print()

def print_flows(flows, show_bodies: bool = False):
    print(f"{C.BOLD}{C.CYAN}{'═'*60}")
    print("  FLUJOS DETALLADOS")
    print(f"{'═'*60}{C.RESET}\n")

    for i, flow in enumerate(flows, 1):
        scheme = flow.request.scheme.upper()
        method = flow.request.method
        url    = flow.request.pretty_url

        scheme_col = C.GREEN if scheme == "HTTPS" else C.RED
        print(f"  {C.DIM}[{i:03d}]{C.RESET} {scheme_col}{scheme}{C.RESET}  "
              f"{C.YELLOW}{method:<7}{C.RESET}  {url}")

        if flow.response:
            code = flow.response.status_code
            ct   = flow.response.headers.get("content-type", "-").split(";")[0]
            size = len(flow.response.content) if flow.response.content else 0
            print(f"         {status_color(code)}← {code}{C.RESET}  "
                  f"{ct:<35}  {size:>7} bytes")

            if show_bodies and flow.response.content:
                try:
                    body = flow.response.get_text(strict=False) or ""
                    snippet = body[:400].replace("\n", " ")
                    print(f"         {C.DIM}Body: {snippet}{C.RESET}")
                except Exception:
                    pass
        else:
            print(f"         {C.RED}← SIN RESPUESTA (posible pinning / error TLS){C.RESET}")

        # Headers de request relevantes
        headers_of_interest = ["authorization", "cookie", "x-api-key", "x-auth-token"]
        for h in headers_of_interest:
            val = flow.request.headers.get(h)
            if val:
                print(f"         {C.RED}⚠ Header sensible [{h}]: {val[:80]}{C.RESET}")

    print()

# ─── Informe HTML ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Informe Forense · RA2</title>
<style>
  :root {{
    --bg: #0f1117;
    --bg2: #1a1d27;
    --bg3: #242736;
    --accent: #7c6af7;
    --accent2: #4fc3f7;
    --green: #4caf7d;
    --red: #f26d6d;
    --yellow: #f5c842;
    --text: #e2e4ef;
    --dim: #7b7f9e;
    --border: #2e3248;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    line-height: 1.6;
  }}
  header {{
    background: linear-gradient(135deg, #1a1d27 0%, #242736 100%);
    border-bottom: 1px solid var(--accent);
    padding: 24px 40px;
    display: flex;
    align-items: center;
    gap: 16px;
  }}
  header h1 {{ font-size: 1.4rem; color: var(--accent2); }}
  header p {{ color: var(--dim); font-size: 0.85rem; margin-top: 4px; }}
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: .5px;
  }}
  .badge-https {{ background: #1b3a2a; color: var(--green); }}
  .badge-http  {{ background: #3a1b1b; color: var(--red); }}
  .badge-warn  {{ background: #3a2e1b; color: var(--yellow); }}

  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}

  /* Stats cards */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 36px;
  }}
  .stat-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 16px;
    text-align: center;
  }}
  .stat-card .num {{
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
  }}
  .stat-card .label {{
    color: var(--dim);
    font-size: 0.8rem;
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: .5px;
  }}
  .num-green {{ color: var(--green); }}
  .num-red   {{ color: var(--red); }}
  .num-yellow{{ color: var(--yellow); }}
  .num-blue  {{ color: var(--accent2); }}
  .num-white {{ color: var(--text); }}

  /* Secciones */
  section {{ margin-bottom: 40px; }}
  section h2 {{
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 16px;
  }}

  /* Tabla de hosts */
  .host-list {{ display: flex; flex-direction: column; gap: 6px; }}
  .host-row {{
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--bg2);
    border-radius: 8px;
    padding: 8px 14px;
    border: 1px solid var(--border);
  }}
  .host-name {{ flex: 1; font-family: monospace; color: var(--accent2); }}
  .host-count {{
    font-weight: 700;
    min-width: 40px;
    text-align: right;
    color: var(--text);
  }}
  .host-bar {{
    height: 6px;
    border-radius: 3px;
    background: var(--accent);
    min-width: 4px;
  }}

  /* Tabla de flujos */
  .flows-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }}
  .flows-table th {{
    background: var(--bg3);
    color: var(--dim);
    text-align: left;
    padding: 10px 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .5px;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
  }}
  .flows-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    font-family: monospace;
  }}
  .flows-table tr:hover td {{ background: var(--bg3); }}

  .method {{ font-weight: 700; }}
  .m-GET {{ color: var(--green); }}
  .m-POST {{ color: var(--yellow); }}
  .m-PUT {{ color: #f5a142; }}
  .m-DELETE {{ color: var(--red); }}
  .m-OTHER {{ color: var(--dim); }}

  .s-2xx {{ color: var(--green); }}
  .s-3xx {{ color: var(--accent2); }}
  .s-4xx {{ color: var(--yellow); }}
  .s-5xx {{ color: var(--red); }}
  .s-err {{ color: var(--red); font-style: italic; }}

  .url-cell {{
    max-width: 500px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
  }}
  .url-cell:hover {{ white-space: normal; word-break: break-all; }}

  /* Alertas */
  .alert {{
    background: var(--bg2);
    border-left: 4px solid var(--red);
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    margin-bottom: 10px;
    font-family: monospace;
    font-size: 0.83rem;
  }}
  .alert .alert-host {{ color: var(--red); font-weight: 700; }}
  .alert .alert-url  {{ color: var(--dim); word-break: break-all; }}
  .alert .alert-kw   {{ color: var(--yellow); margin-top: 4px; }}

  /* Filtro */
  .filter-bar {{
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }}
  .filter-bar input {{
    flex: 1;
    min-width: 220px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 14px;
    color: var(--text);
    font-size: 0.9rem;
    outline: none;
  }}
  .filter-bar input:focus {{ border-color: var(--accent); }}
  .filter-bar select {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
    color: var(--text);
    font-size: 0.9rem;
    outline: none;
  }}
  .filter-bar select:focus {{ border-color: var(--accent); }}

  /* Scroll table */
  .table-scroll {{ max-height: 600px; overflow-y: auto; border-radius: 10px; border: 1px solid var(--border); }}

  /* Pie */
  footer {{
    text-align: center;
    color: var(--dim);
    font-size: 0.8rem;
    padding: 24px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }}

  /* Grafico mini donut (canvas) */
  .charts-row {{
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    margin-bottom: 36px;
  }}
  .chart-card {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    flex: 1;
    min-width: 220px;
  }}
  .chart-card h3 {{
    color: var(--dim);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-bottom: 14px;
  }}
  .legend {{ display: flex; flex-direction: column; gap: 6px; margin-top: 12px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; font-size: 0.83rem; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🔍 Informe Forense de Comunicaciones Móviles · RA2</h1>
    <p>Módulo: Análisis Forense · GS Ciberseguridad · Prof. Carlos Basulto Pardo</p>
    <p>Generado: {generated_at} · Archivo: {capture_file}</p>
  </div>
</header>

<div class="container">

  <!-- Stats cards -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="num num-white">{total}</div>
      <div class="label">Total Flows</div>
    </div>
    <div class="stat-card">
      <div class="num num-green">{https_count}</div>
      <div class="label">HTTPS</div>
    </div>
    <div class="stat-card">
      <div class="num num-red">{http_count}</div>
      <div class="label">HTTP (claro)</div>
    </div>
    <div class="stat-card">
      <div class="num num-green">{intercepted}</div>
      <div class="label">Interceptados</div>
    </div>
    <div class="stat-card">
      <div class="num num-yellow">{blocked}</div>
      <div class="label">Bloqueados</div>
    </div>
    <div class="stat-card">
      <div class="num num-blue">{unique_hosts}</div>
      <div class="label">Hosts únicos</div>
    </div>
    <div class="stat-card">
      <div class="num num-red">{sensitive_count}</div>
      <div class="label">Alertas</div>
    </div>
  </div>

  <!-- Gráficos -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>Protocolo</h3>
      <canvas id="protoChart" width="140" height="140"></canvas>
      <div class="legend" id="protoLegend"></div>
    </div>
    <div class="chart-card">
      <h3>Métodos HTTP</h3>
      <canvas id="methodChart" width="140" height="140"></canvas>
      <div class="legend" id="methodLegend"></div>
    </div>
    <div class="chart-card">
      <h3>Códigos de estado</h3>
      <canvas id="statusChart" width="140" height="140"></canvas>
      <div class="legend" id="statusLegend"></div>
    </div>
    <div class="chart-card">
      <h3>Content-Types</h3>
      <canvas id="ctChart" width="140" height="140"></canvas>
      <div class="legend" id="ctLegend"></div>
    </div>
  </div>

  <!-- Hosts -->
  <section>
    <h2>📡 Hosts contactados</h2>
    <div class="host-list">
      {hosts_html}
    </div>
  </section>

  <!-- Alertas -->
  {alerts_html}

  <!-- Tráfico en claro -->
  {cleartext_html}

  <!-- HTTPS interceptado -->
  {https_intercepted_html}

  <!-- Pinning detectado -->
  {pinning_html}

  <!-- Flujos -->
  <section>
    <h2>📋 Todos los flujos</h2>
    <div class="filter-bar">
      <input type="text"   id="searchInput"  placeholder="Filtrar por URL, host, método…"  oninput="filterTable()">
      <select id="schemeFilter" onchange="filterTable()">
        <option value="">Todos los protocolos</option>
        <option value="HTTPS">Solo HTTPS</option>
        <option value="HTTP">Solo HTTP</option>
      </select>
      <select id="statusFilter" onchange="filterTable()">
        <option value="">Todos los estados</option>
        <option value="2">2xx OK</option>
        <option value="3">3xx Redirect</option>
        <option value="4">4xx Error cliente</option>
        <option value="5">5xx Error servidor</option>
        <option value="0">Sin respuesta</option>
      </select>
    </div>
    <div class="table-scroll">
      <table class="flows-table" id="flowsTable">
        <thead>
          <tr>
            <th>#</th>
            <th>Protocolo</th>
            <th>Método</th>
            <th>Host</th>
            <th>URL</th>
            <th>Estado</th>
            <th>Content-Type</th>
            <th>Tamaño</th>
          </tr>
        </thead>
        <tbody>
          {flows_html}
        </tbody>
      </table>
    </div>
  </section>

</div>

<footer>
  RA2 · Análisis Forense de Comunicaciones Móviles · GS Ciberseguridad · {year}
</footer>

<script>
// ─── Datos para gráficos ──────────────────────────────────────────────────
const CHART_DATA = {chart_data_json};

// ─── Mini donut chart ─────────────────────────────────────────────────────
function drawDonut(canvasId, legendId, data) {{
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const cx = W/2, cy = H/2, r = Math.min(W,H)/2 - 8, inner = r*0.55;
  const colors = ['#7c6af7','#4fc3f7','#4caf7d','#f5c842','#f26d6d','#f5a142','#a78bfa','#34d399'];
  const total = data.reduce((s,d) => s + d.value, 0);
  let angle = -Math.PI/2;
  ctx.clearRect(0,0,W,H);
  data.forEach((d,i) => {{
    const sweep = (d.value/total) * 2*Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,angle,angle+sweep);
    ctx.closePath();
    ctx.fillStyle = colors[i % colors.length];
    ctx.fill();
    angle += sweep;
  }});
  // inner hole
  ctx.beginPath();
  ctx.arc(cx,cy,inner,0,2*Math.PI);
  ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--bg2') || '#1a1d27';
  ctx.fill();
  // legend
  const legend = document.getElementById(legendId);
  if (legend) {{
    legend.innerHTML = data.map((d,i) =>
      `<div class="legend-item">
         <span class="legend-dot" style="background:${{colors[i%colors.length]}}"></span>
         <span>${{d.label}} (${{d.value}})</span>
       </div>`
    ).join('');
  }}
}}

document.addEventListener('DOMContentLoaded', () => {{
  drawDonut('protoChart',  'protoLegend',  CHART_DATA.proto);
  drawDonut('methodChart', 'methodLegend', CHART_DATA.methods);
  drawDonut('statusChart', 'statusLegend', CHART_DATA.status);
  drawDonut('ctChart',     'ctLegend',     CHART_DATA.ct);
}});

// ─── Filtro de tabla ──────────────────────────────────────────────────────
function filterTable() {{
  const search = document.getElementById('searchInput').value.toLowerCase();
  const scheme = document.getElementById('schemeFilter').value.toUpperCase();
  const status = document.getElementById('statusFilter').value;
  const rows   = document.querySelectorAll('#flowsTable tbody tr');
  rows.forEach(row => {{
    const text    = row.textContent.toLowerCase();
    const rowScheme = row.dataset.scheme || '';
    const rowStatus = row.dataset.status || '';
    const matchText   = !search || text.includes(search);
    const matchScheme = !scheme || rowScheme === scheme;
    const matchStatus = !status || (status === '0' ? rowStatus === '0' : rowStatus.startsWith(status));
    row.style.display = (matchText && matchScheme && matchStatus) ? '' : 'none';
  }});
}}
</script>
</body>
</html>
"""

def build_html(flows, stats, capture_file: str) -> str:
    max_count = max(stats["hosts"].values()) if stats["hosts"] else 1

    # Hosts HTML
    hosts_html_parts = []
    for host, count in stats["hosts"].most_common(30):
        width = int((count / max_count) * 200)
        hosts_html_parts.append(
            f'<div class="host-row">'
            f'<span class="host-name">{html_mod.escape(host)}</span>'
            f'<div class="host-bar" style="width:{width}px"></div>'
            f'<span class="host-count">{count}</span>'
            f'</div>'
        )
    hosts_html = "\n".join(hosts_html_parts)

    # Alertas
    alerts_parts = []
    if stats["sensitive_keywords"]:
        alerts_parts.append('<section><h2>⚠️ Posibles datos sensibles detectados</h2>')
        for item in stats["sensitive_keywords"]:
            kw = ", ".join(f"<code>{k}</code>" for k in item["keywords"])
            alerts_parts.append(
                f'<div class="alert">'
                f'<div class="alert-host">🔴 {html_mod.escape(item["host"])}</div>'
                f'<div class="alert-url">{html_mod.escape(item["url"])}</div>'
                f'<div class="alert-kw">Keywords: {kw}</div>'
                f'</div>'
            )
        alerts_parts.append('</section>')
    alerts_html = "\n".join(alerts_parts)

    # Tráfico en claro
    cleartext_parts = []
    if stats["cleartext_data"]:
        cleartext_parts.append('<section><h2>🔓 Tráfico HTTP en claro (cuerpo de petición)</h2>')
        for item in stats["cleartext_data"]:
            cleartext_parts.append(
                f'<div class="alert" style="border-color:var(--red)">'
                f'<div class="alert-host">[{html_mod.escape(item["method"])}] {html_mod.escape(item["host"])}</div>'
                f'<div class="alert-url">{html_mod.escape(item["url"])}</div>'
                f'<pre style="color:var(--yellow);margin-top:6px;font-size:0.8rem;white-space:pre-wrap">'
                f'{html_mod.escape(item["body_snippet"])}</pre>'
                f'</div>'
            )
        cleartext_parts.append('</section>')
    cleartext_html = "\n".join(cleartext_parts)

    # Filas de flujos
    rows = []
    for i, flow in enumerate(flows, 1):
        scheme = flow.request.scheme.upper()
        method = flow.request.method
        host   = html_mod.escape(flow.request.pretty_host)
        url    = html_mod.escape(flow.request.pretty_url)

        scheme_badge = (
            f'<span class="badge badge-https">HTTPS</span>'
            if scheme == "HTTPS"
            else f'<span class="badge badge-http">HTTP</span>'
        )
        m_class = f"m-{method}" if method in ("GET","POST","PUT","DELETE") else "m-OTHER"
        method_html = f'<span class="method {m_class}">{method}</span>'

        if flow.response:
            code = flow.response.status_code
            s_class = f"s-{str(code)[0]}xx"
            status_html = f'<span class="{s_class}">{code}</span>'
            ct   = html_mod.escape(flow.response.headers.get("content-type","-").split(";")[0])
            size = f"{len(flow.response.content):,} B" if flow.response.content else "-"
            status_data = str(code)
        else:
            status_html = '<span class="s-err">Sin respuesta</span>'
            ct   = "-"
            size = "-"
            status_data = "0"

        rows.append(
            f'<tr data-scheme="{scheme}" data-status="{status_data}">'
            f'<td>{i}</td>'
            f'<td>{scheme_badge}</td>'
            f'<td>{method_html}</td>'
            f'<td style="color:var(--accent2);font-family:monospace">{host}</td>'
            f'<td class="url-cell" title="{url}">{url}</td>'
            f'<td>{status_html}</td>'
            f'<td style="color:var(--dim)">{ct}</td>'
            f'<td style="color:var(--dim)">{size}</td>'
            f'</tr>'
        )
    flows_html = "\n".join(rows)

    # Datos para gráficos
    proto_data = [
        {"label": "HTTPS", "value": stats["https"]},
        {"label": "HTTP",  "value": stats["http"]},
    ]
    method_data = [{"label": k, "value": v} for k, v in stats["methods"].most_common(6)]
    status_data = [
        {"label": str(k), "value": v}
        for k, v in sorted(stats["status_codes"].items())
    ]
    ct_data = [{"label": k, "value": v} for k, v in stats["content_types"].most_common(6)]
    chart_data = json.dumps({
        "proto":   proto_data,
        "methods": method_data,
        "status":  status_data,
        "ct":      ct_data,
    })

    # HTTPS interceptado en claro
    https_int_parts = []
    if stats["https_intercepted"]:
        https_int_parts.append(
            f'''<section>
<h2>✅ HTTPS interceptado en claro ({len(stats["https_intercepted"])} flows)</h2>
<p style="color:var(--dim);margin-bottom:16px;font-size:0.85rem">
  Estas peticiones HTTPS fueron descifradas por el proxy. La app <strong style="color:var(--red)">no implementa
  certificate pinning</strong> o no valida correctamente el certificado — sus comunicaciones son
  interceptables en un entorno MITM controlado.</p>'''
        )
        for item in stats["https_intercepted"][:20]:
            req_b  = html_mod.escape(item["req_body"])  if item["req_body"].strip()  else ""
            resp_b = html_mod.escape(item["resp_body"]) if item["resp_body"].strip() else ""
            https_int_parts.append(
                f'''<div class="alert" style="border-color:var(--green);margin-bottom:10px">
  <div style="color:var(--green);font-weight:700">[{html_mod.escape(item["method"])}] {html_mod.escape(item["url"])}</div>
  <div style="color:var(--dim);font-size:0.8rem">Status: {item["status"]} &nbsp;|&nbsp; {html_mod.escape(item["ct"])}</div>
  {f'<pre style="color:var(--yellow);margin-top:6px;font-size:0.78rem;white-space:pre-wrap">REQ: {req_b}</pre>' if req_b else ""}
  {f'<pre style="color:var(--text);margin-top:4px;font-size:0.78rem;white-space:pre-wrap">RESP: {resp_b}</pre>' if resp_b else ""}
</div>'''
            )
        https_int_parts.append("</section>")
    https_intercepted_html = "\n".join(https_int_parts)

    # Pinning detectado
    pinning_parts = []
    if stats["pinning_detected"]:
        unique_pin = list({i["host"] for i in stats["pinning_detected"]})
        pinning_parts.append(
            f'''<section>
<h2>🔒 Certificate Pinning detectado ({len(unique_pin)} hosts)</h2>
<p style="color:var(--dim);margin-bottom:16px;font-size:0.85rem">
  Estos hosts no devolvieron respuesta a través del proxy. La app <strong style="color:var(--green)">implementa
  certificate pinning</strong> o validación estricta del certificado — el tráfico no es interceptable.</p>'''
        )
        for h in unique_pin[:20]:
            count = sum(1 for i in stats["pinning_detected"] if i["host"] == h)
            pinning_parts.append(
                f'''<div class="alert" style="border-color:var(--yellow)">
  <div style="color:var(--yellow);font-weight:700">🔒 {html_mod.escape(h)}</div>
  <div style="color:var(--dim);font-size:0.8rem">{count} peticiones bloqueadas</div>
</div>'''
            )
        pinning_parts.append("</section>")
    pinning_html = "\n".join(pinning_parts)

    return HTML_TEMPLATE.format(
        generated_at           = datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        capture_file           = html_mod.escape(capture_file),
        total                  = stats["total"],
        https_count            = stats["https"],
        http_count             = stats["http"],
        intercepted            = stats["intercepted"],
        blocked                = stats["blocked"],
        unique_hosts           = len(stats["hosts"]),
        sensitive_count        = len(stats["sensitive_keywords"]),
        hosts_html             = hosts_html,
        alerts_html            = alerts_html,
        cleartext_html         = cleartext_html,
        https_intercepted_html = https_intercepted_html,
        pinning_html           = pinning_html,
        flows_html             = flows_html,
        chart_data_json        = chart_data,
        year                   = datetime.now().year,
    )

# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="RA2 · Visor y analizador de capturas mitmproxy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("capture",       help="Fichero .mitm de captura")
    p.add_argument("--output",  "-o", default=None,
                   help="Fichero HTML de salida (default: <capture>.html)")
    p.add_argument("--filter",  "-f", default=None,
                   help="Filtrar por host (ej: google, api.whatsapp)")
    p.add_argument("--show-bodies", action="store_true",
                   help="Mostrar snippet del body en terminal")
    p.add_argument("--no-html",     action="store_true",
                   help="Solo terminal, no generar HTML")
    return p.parse_args()

def main():
    args = parse_args()

    capture = args.capture
    if not Path(capture).exists():
        print(f"[!] No existe el fichero: {capture}")
        sys.exit(1)

    print(col(C.CYAN + C.BOLD, f"\n[*] Cargando captura: {capture}"))
    flows = load_flows(capture)
    print(col(C.GREEN, f"[+] {len(flows)} flujos cargados."))

    flows, stats = analyze(flows, filter_host=args.filter)
    if args.filter:
        print(col(C.YELLOW, f"[*] Filtro activo: '{args.filter}' → {len(flows)} flujos."))

    print_summary(flows, stats)
    print_flows(flows, show_bodies=args.show_bodies)

    if not args.no_html:
        out_path = args.output or Path(capture).with_suffix(".html")
        html_content = build_html(flows, stats, capture)
        Path(out_path).write_text(html_content, encoding="utf-8")
        print(col(C.GREEN + C.BOLD,
              f"[✓] Informe HTML generado: {out_path}"))
        print(col(C.DIM,
              f"    Abre en el navegador: firefox {out_path}  (o xdg-open {out_path})"))

if __name__ == "__main__":
    main()
