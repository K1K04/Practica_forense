# Practica_forense
Análisis forense de comunicaciones de una aplicación móvil en un entorno WiFi controlado

# RA2 · Análisis Forense de Comunicaciones Móviles
**GS Ciberseguridad · Análisis Forense · Prof. Carlos Basulto Pardo**

> Uso exclusivo en entorno de laboratorio autorizado. No usar fuera de redes propias.

---

## Requisitos

```bash
# Sistema
sudo apt install hostapd dnsmasq iptables iproute2 -y

# Python (en virtualenv recomendado)
pip install mitmproxy
```

Comprueba que tu tarjeta WiFi soporta modo AP:
```bash
iw list | grep -A 5 "Supported interface modes"
# Debe aparecer: * AP
```

---

## Los tres scripts

### 1. `forense_ap_proxy.py` — Levanta el entorno
Crea el punto de acceso WiFi, configura el DHCP y lanza el proxy MITM.

```bash
sudo python3 forense_ap_proxy.py \
  --iface wlo1 \        # tu interfaz WiFi
  --uplink enp7s0 \     # tu interfaz con internet
  --ssid LabForense \
  --password Lab12345! \
  --output captura.mitm
```

| Opción | Default | Descripción |
|--------|---------|-------------|
| `--iface` | `wlan0` | Interfaz WiFi para el AP |
| `--uplink` | autodetectada | Interfaz con internet |
| `--ssid` | `LabForense` | Nombre de la red WiFi |
| `--password` | `Lab12345!` | Contraseña WPA2 |
| `--channel` | `6` | Canal WiFi (1-11) |
| `--proxy-port` | `8080` | Puerto del proxy |
| `--output` | `trafico_captura.mitm` | Fichero de captura |

Una vez activo, conecta el móvil a la red y **instala el certificado CA**:
- Accede desde el móvil a **http://mitm.it** y descarga el certificado
- O cópialo manualmente desde `~/.mitmproxy/mitmproxy-ca-cert.pem`
- En Android: Ajustes → Seguridad → Instalar certificado → CA

> Si usas virtualenv, lanza con la ruta completa al Python del entorno:
> `sudo /ruta/a/mi_entorno/bin/python3 forense_ap_proxy.py ...`

---

### 2. `forense_stop.py` — Para y limpia todo
Mata los procesos, elimina las reglas iptables y devuelve la interfaz WiFi a NetworkManager.

```bash
sudo python3 forense_stop.py
```

Si usaste opciones distintas a las por defecto:
```bash
sudo python3 forense_stop.py \
  --iface wlo1 \
  --uplink enp7s0 \
  --proxy-port 8080
```

Siempre ejecuta este script al terminar la sesión para dejar el sistema limpio.

---

### 3. `forense_viewer.py` — Analiza la captura
Lee el fichero `.mitm` generado y produce un resumen en terminal + informe HTML interactivo.

```bash
python3 forense_viewer.py captura.mitm
```

Opciones:
```bash
# Filtrar por host
python3 forense_viewer.py captura.mitm --filter google

# Ver snippet del body en terminal
python3 forense_viewer.py captura.mitm --show-bodies

# Nombre personalizado para el HTML
python3 forense_viewer.py captura.mitm -o informe_app1.html

# Solo terminal, sin generar HTML
python3 forense_viewer.py captura.mitm --no-html
```

Abrir el informe HTML:
```bash
xdg-open captura.html
# o
firefox captura.html
```

El informe incluye: estadísticas, gráficos, hosts contactados, HTTPS interceptado en claro, certificate pinning detectado, alertas de datos sensibles y tabla filtrable de todos los flujos.

---

## Flujo de trabajo típico

```
1. sudo python3 forense_ap_proxy.py --iface wlo1 --uplink enp7s0 --ssid LabForense --password Lab12345!
2. [Conectar el móvil a LabForense]
3. [Instalar el certificado desde http://mitm.it]
4. [Usar las apps a analizar]
5. Ctrl+C para detener
6. sudo python3 forense_stop.py
7. python3 forense_viewer.py trafico_captura.mitm
```

---

## Problemas frecuentes

| Problema | Solución |
|----------|----------|
| `mitmdump not found` con sudo | Usar `sudo /ruta/venv/bin/python3 forense_ap_proxy.py` |
| `Address already in use` en puerto 8080 | `sudo fuser -k 8080/tcp` |
| hostapd falla al arrancar | `sudo nmcli device set wlo1 managed no && sudo rfkill unblock all` |
| Sin internet en el móvil | Verificar que `--uplink` es la interfaz correcta (`ip route show default`) |
| App no carga con proxy | La app tiene certificate pinning — tráfico no interceptable por diseño |

---

## Estructura de ficheros generados

```
practica_forense/
├── forense_ap_proxy.py       # Script principal
├── forense_stop.py           # Script de limpieza
├── forense_viewer.py         # Analizador / visor
├── trafico_captura.mitm      # Captura de tráfico
├── trafico_captura.html      # Informe HTML generado
└── forense_YYYYMMDD_HHMMSS.log  # Log de sesión
```
