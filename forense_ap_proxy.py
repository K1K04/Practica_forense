#!/usr/bin/env python3
"""
=============================================================
  RA2 - Análisis Forense de Comunicaciones Móviles
  Script: AP WiFi + Proxy Inverso (MITM controlado)
  Curso: GS Ciberseguridad | Análisis Forense
  Uso EXCLUSIVO en entorno de laboratorio autorizado
=============================================================

DEPENDENCIAS:
  pip install mitmproxy

HERRAMIENTAS DEL SISTEMA NECESARIAS:
  hostapd, dnsmasq, iptables

INSTALACIÓN RÁPIDA (Debian/Ubuntu/Kali):
  sudo apt install hostapd dnsmasq iptables iproute2 -y
  pip install mitmproxy

USO:
  sudo python3 forense_ap_proxy.py --iface wlan0 --ssid LabForense --password Lab12345!

  Opciones:
    --iface       Interfaz WiFi (default: wlan0)
    --ssid        Nombre de la red (default: LabForense)
    --password    Contraseña WPA2 (default: Lab12345!)
    --channel     Canal WiFi (default: 6)
    --proxy-port  Puerto del proxy (default: 8080)
    --output      Fichero de captura (default: trafico_captura.mitm)
    --uplink      Interfaz de internet (default: autodetectada)
"""

import argparse
import os
import sys
import signal
import subprocess
import threading
import logging
import time
import textwrap
from pathlib import Path
from datetime import datetime

# ─── Colores ANSI ────────────────────────────────────────────────────────────

class C:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

NO_COLOR = False

def col(color, text):
    return f"{color}{text}{C.RESET}" if not NO_COLOR else text

def banner():
    print(col(C.CYAN + C.BOLD, """
╔══════════════════════════════════════════════════════════╗
║     RA2 · Análisis Forense de Comunicaciones Móviles     ║
║          AP WiFi + Proxy MITM Controlado                 ║
║       Solo para uso en laboratorio autorizado            ║
╚══════════════════════════════════════════════════════════╝
"""))

# ─── Logging ──────────────────────────────────────────────────────────────────

def setup_logging(output_file: str) -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(output_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    return logging.getLogger("forense")

# ─── Comprobaciones previas ───────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        print(col(C.RED, "[!] Este script debe ejecutarse con sudo / root."))
        sys.exit(1)

def check_tool(name: str) -> bool:
    ok = subprocess.run(["which", name], capture_output=True).returncode == 0
    status = col(C.GREEN, "OK") if ok else col(C.RED, "NO ENCONTRADO")
    mark = "[✓]" if ok else "[✗]"
    print(f"    {mark} {name:<15} {status}")
    return ok

def check_dependencies():
    print(col(C.BOLD, "\n[*] Comprobando dependencias del sistema:"))
    tools = ["hostapd", "dnsmasq", "iptables", "ip", "mitmdump"]
    missing = [t for t in tools if not check_tool(t)]
    if missing:
        print(col(C.YELLOW, f"\n[!] Faltan: {', '.join(missing)}"))
        print("    Instala con:")
        print("      sudo apt install hostapd dnsmasq iptables iproute2 -y")
        print("      pip install mitmproxy")
        sys.exit(1)
    print(col(C.GREEN, "[+] Todas las dependencias presentes.\n"))

# ─── Autodetección de interfaz de internet ───────────────────────────────────

def detect_uplink() -> str:
    """Devuelve la interfaz con ruta por defecto (la que tiene internet)."""
    result = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        parts = line.split()
        # formato: default via <gw> dev <iface> ...
        if "dev" in parts:
            idx = parts.index("dev")
            return parts[idx + 1]
    return "eth0"  # fallback

# ─── Configuraciones temporales ──────────────────────────────────────────────

HOSTAPD_CONF = Path("/tmp/hostapd_forense.conf")
DNSMASQ_CONF = Path("/tmp/dnsmasq_forense.conf")
AP_IP        = "192.168.99.1"
DHCP_START   = "192.168.99.10"
DHCP_END     = "192.168.99.50"
SUBNET       = "255.255.255.0"

def write_hostapd_conf(iface: str, ssid: str, password: str, channel: int):
    HOSTAPD_CONF.write_text(textwrap.dedent(f"""\
        interface={iface}
        driver=nl80211
        ssid={ssid}
        hw_mode=g
        channel={channel}
        wmm_enabled=0
        macaddr_acl=0
        auth_algs=1
        ignore_broadcast_ssid=0
        wpa=2
        wpa_passphrase={password}
        wpa_key_mgmt=WPA-PSK
        wpa_pairwise=TKIP
        rsn_pairwise=CCMP
    """))

def write_dnsmasq_conf(iface: str):
    DNSMASQ_CONF.write_text(textwrap.dedent(f"""\
        interface={iface}
        bind-interfaces
        dhcp-range={DHCP_START},{DHCP_END},{SUBNET},12h
        dhcp-option=3,{AP_IP}
        dhcp-option=6,8.8.8.8,8.8.4.4
        log-queries
        log-dhcp
        no-resolv
        server=8.8.8.8
    """))

# ─── Red: IP + iptables ───────────────────────────────────────────────────────

def setup_network(iface: str, uplink: str, proxy_port: int, log: logging.Logger):
    log.info(f"Interfaz WiFi   : {iface}  →  {AP_IP}/24")
    log.info(f"Interfaz uplink : {uplink} (salida a internet)")

    for cmd in [
        ["ip", "link", "set", iface, "up"],
        ["ip", "addr", "flush", "dev", iface],
        ["ip", "addr", "add", f"{AP_IP}/24", "dev", iface],
    ]:
        _run(cmd, log)

    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    log.info("IP forwarding habilitado.")

    log.info(f"Redirigiendo HTTP(80) y HTTPS(443) → proxy:{proxy_port}")
    for rule in [
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(proxy_port)],
        ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(proxy_port)],
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"],
        # Permitir forward entre wlan0 y uplink
        ["iptables", "-A", "FORWARD", "-i", iface, "-o", uplink, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-i", uplink, "-o", iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]:
        _run(rule, log)

def teardown_network(iface: str, uplink: str, proxy_port: int, log: logging.Logger):
    log.info("Limpiando reglas iptables...")
    for rule in [
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(proxy_port)],
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(proxy_port)],
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", iface, "-o", uplink, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-i", uplink, "-o", iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]:
        _run(rule, log, check=False)

    Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    log.info("IP forwarding deshabilitado.")

# ─── Procesos ─────────────────────────────────────────────────────────────────

procs: dict[str, subprocess.Popen] = {}

def start_hostapd(log: logging.Logger):
    log.info("Iniciando hostapd (Access Point)...")
    # Matar instancia previa si existe
    subprocess.run(["pkill", "-f", "hostapd_forense"], capture_output=True)
    time.sleep(0.5)
    p = subprocess.Popen(
        ["hostapd", str(HOSTAPD_CONF)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    procs["hostapd"] = p
    _stream_log(p, "hostapd", log)

def start_dnsmasq(log: logging.Logger):
    log.info("Iniciando dnsmasq (DHCP/DNS)...")
    # Matar instancia previa
    subprocess.run(["pkill", "-f", "dnsmasq_forense"], capture_output=True)
    time.sleep(0.5)
    p = subprocess.Popen(
        ["dnsmasq", "-C", str(DNSMASQ_CONF), "--no-daemon", "--pid-file=/tmp/dnsmasq_forense.pid"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    procs["dnsmasq"] = p
    _stream_log(p, "dnsmasq", log)

def start_mitmproxy(port: int, output_file: str, log: logging.Logger):
    log.info(f"Iniciando mitmdump (proxy transparente) en puerto {port}...")
    log.info(f"Certificado CA : ~/.mitmproxy/mitmproxy-ca-cert.pem")
    log.info(f"  → Instálalo en el móvil para ver tráfico HTTPS.")
    log.info(f"  → O accede a http://mitm.it desde el móvil (con proxy configurado).")
    p = subprocess.Popen(
        [
            "mitmdump",
            "--mode", "transparent",
            "--listen-host", "0.0.0.0",
            "--listen-port", str(port),
            "--ssl-insecure",
            "-w", output_file,
            "--flow-detail", "3",
        ],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    procs["mitmdump"] = p
    _stream_log(p, "mitmdump", log)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list, log: logging.Logger, check: bool = True):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=check)
        if r.returncode != 0 and r.stderr.strip():
            log.warning(f"  {' '.join(cmd)}: {r.stderr.strip()}")
    except subprocess.CalledProcessError as e:
        log.error(f"Error: {' '.join(cmd)}: {e}")

def _stream_log(proc: subprocess.Popen, name: str, log: logging.Logger):
    def _reader():
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log.info(f"[{name}] {line}")
    threading.Thread(target=_reader, daemon=True).start()

def stop_all(log: logging.Logger):
    log.info("Deteniendo todos los servicios...")
    for name, proc in procs.items():
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.info(f"  [✓] {name} detenido.")

def watch_procs(log: logging.Logger):
    """Monitoriza que los subprocesos siguen vivos."""
    while True:
        time.sleep(2)
        for name, proc in list(procs.items()):
            if proc.poll() is not None:
                log.warning(f"[!] '{name}' ha terminado inesperadamente (código {proc.returncode}).")

# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="RA2 · AP WiFi + Proxy MITM para laboratorio forense",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--iface",      default="wlan0",                 help="Interfaz WiFi (AP)")
    p.add_argument("--ssid",       default="LabForense",            help="SSID de la red WiFi")
    p.add_argument("--password",   default="Lab12345!",             help="Contraseña WPA2 (mín. 8 chars)")
    p.add_argument("--channel",    default=6,    type=int,          help="Canal WiFi 1-11")
    p.add_argument("--proxy-port", default=8080, type=int,          help="Puerto del proxy MITM")
    p.add_argument("--output",     default="trafico_captura.mitm",  help="Fichero de captura mitmproxy")
    p.add_argument("--uplink",     default=None,                    help="Interfaz con internet (autodetectada si no se indica)")
    p.add_argument("--no-color",   action="store_true",             help="Desactiva colores ANSI")
    return p.parse_args()

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global NO_COLOR
    args = parse_args()
    NO_COLOR = args.no_color

    banner()
    check_root()
    check_dependencies()

    # Autodetectar uplink si no se pasó
    uplink = args.uplink or detect_uplink()
    print(col(C.CYAN, f"[*] Interfaz de internet (uplink): {uplink}"))
    print(col(C.CYAN, f"[*] Interfaz WiFi (AP):            {args.iface}\n"))

    log_file = f"forense_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log = setup_logging(log_file)

    log.info(f"SSID={args.ssid} | Canal={args.channel} | AP={args.iface} | Uplink={uplink}")
    log.info(f"Proxy={args.proxy_port} | Captura={args.output}")

    # Escribir configs
    write_hostapd_conf(args.iface, args.ssid, args.password, args.channel)
    write_dnsmasq_conf(args.iface)

    # Configurar red
    setup_network(args.iface, uplink, args.proxy_port, log)

    # Señal para limpieza ordenada
    def _shutdown(sig, frame):
        print(col(C.YELLOW, "\n[!] Señal recibida. Cerrando entorno..."))
        stop_all(log)
        teardown_network(args.iface, uplink, args.proxy_port, log)
        log.info("Entorno limpiado correctamente. Hasta luego.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Arrancar servicios
    start_hostapd(log)
    time.sleep(3)           # hostapd necesita unos segundos
    start_dnsmasq(log)
    time.sleep(1)
    start_mitmproxy(args.proxy_port, args.output, log)
    time.sleep(1)

    print(col(C.GREEN + C.BOLD, f"""
╔══════════════════════════════════════════════════════════════╗
║  ✓ Entorno activo                                            ║
║                                                              ║
║  Red WiFi  : {args.ssid:<47} ║
║  Password  : {args.password:<47} ║
║  Gateway   : {AP_IP:<47} ║
║                                                              ║
║  Certificado CA del proxy:                                   ║
║    ~/.mitmproxy/mitmproxy-ca-cert.pem                        ║
║    O accede desde el móvil a: http://mitm.it                 ║
║                                                              ║
║  Captura   : {args.output:<47} ║
║  Log       : {log_file:<47} ║
║                                                              ║
║  Ctrl+C para detener y limpiar todo                          ║
╚══════════════════════════════════════════════════════════════╝
"""))

    # Hilo de monitorización de procesos
    threading.Thread(target=watch_procs, args=(log,), daemon=True).start()

    # Mantener vivo el proceso principal
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
