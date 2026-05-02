#!/usr/bin/env python3
"""
=============================================================
  RA2 - Script de limpieza del entorno forense
  Para todo lo que levantó forense_ap_proxy.py
=============================================================
USO:
  sudo python3 forense_stop.py
  sudo python3 forense_stop.py --iface wlo1 --uplink enp7s0 --proxy-port 8080
"""

import argparse
import os
import sys
import subprocess
from pathlib import Path

class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def p(color, msg): print(f"{color}{msg}{C.RESET}")

def run(cmd: list, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, check=check)
    return r.returncode == 0

def kill_proc(name: str) -> bool:
    r = subprocess.run(["pkill", "-f", name], capture_output=True)
    return r.returncode == 0

def parse_args():
    ap = argparse.ArgumentParser(
        description="RA2 · Limpieza del entorno forense",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--iface",      default="wlo1",    help="Interfaz WiFi usada como AP")
    ap.add_argument("--uplink",     default="enp7s0",  help="Interfaz de internet")
    ap.add_argument("--proxy-port", default=8080, type=int, help="Puerto del proxy")
    return ap.parse_args()

def main():
    if os.geteuid() != 0:
        p(C.RED, "[!] Ejecuta con sudo.")
        sys.exit(1)

    args = parse_args()
    iface = args.iface
    uplink = args.uplink
    port = str(args.proxy_port)

    print(f"""
{C.BOLD}╔══════════════════════════════════════════════╗
║   RA2 · Limpieza del entorno forense         ║
╚══════════════════════════════════════════════╝{C.RESET}
""")

    # ─── 1. Matar procesos ───────────────────────────────────────────────
    p(C.BOLD, "[1/4] Deteniendo procesos...")

    procs = {
        "mitmdump":          "mitmdump",
        "hostapd":           "hostapd_forense",
        "dnsmasq (forense)": "dnsmasq_forense",
    }
    for name, pattern in procs.items():
        ok = kill_proc(pattern)
        icon = "✓" if ok else "·"
        color = C.GREEN if ok else C.DIM
        print(f"  {color}[{icon}] {name}{C.RESET}")

    # dnsmasq genérico por si acaso
    kill_proc("dnsmasq")

    # ─── 2. Limpiar iptables ─────────────────────────────────────────────
    p(C.BOLD, "\n[2/4] Limpiando reglas iptables...")

    rules = [
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", port],
        ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", iface,
         "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", port],
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", uplink, "-j", "MASQUERADE"],
        ["iptables", "-D", "FORWARD", "-i", iface, "-o", uplink, "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-i", uplink, "-o", iface,
         "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
    ]
    for rule in rules:
        ok = run(rule)
        desc = " ".join(rule[3:7]) + "..."
        icon = "✓" if ok else "·"
        color = C.GREEN if ok else C.DIM
        print(f"  {color}[{icon}] {desc}{C.RESET}")

    # ─── 3. IP forwarding ────────────────────────────────────────────────
    p(C.BOLD, "\n[3/4] Deshabilitando IP forwarding...")
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
        p(C.GREEN, "  [✓] IP forwarding deshabilitado.")
    except Exception as e:
        p(C.YELLOW, f"  [!] {e}")

    # ─── 4. Limpiar interfaz WiFi ────────────────────────────────────────
    p(C.BOLD, f"\n[4/4] Limpiando interfaz {iface}...")
    cmds = [
        (["ip", "addr", "flush", "dev", iface],        f"Flush IPs de {iface}"),
        (["ip", "link", "set", iface, "down"],          f"{iface} → DOWN"),
        (["nmcli", "device", "set", iface, "managed", "yes"], "Devolver iface a NetworkManager"),
    ]
    for cmd, desc in cmds:
        ok = run(cmd)
        icon = "✓" if ok else "·"
        color = C.GREEN if ok else C.DIM
        print(f"  {color}[{icon}] {desc}{C.RESET}")

    # Limpiar ficheros temporales
    for f in ["/tmp/hostapd_forense.conf",
              "/tmp/dnsmasq_forense.conf",
              "/tmp/dnsmasq_forense.pid"]:
        try:
            Path(f).unlink(missing_ok=True)
            print(f"  {C.GREEN}[✓] Eliminado {f}{C.RESET}")
        except Exception:
            pass

    print(f"""
{C.GREEN}{C.BOLD}╔══════════════════════════════════════════════╗
║  ✓ Entorno limpiado correctamente            ║
╚══════════════════════════════════════════════╝{C.RESET}
""")

if __name__ == "__main__":
    main()
