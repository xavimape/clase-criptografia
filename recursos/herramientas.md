# 🛠️ Herramientas para Criptografía en SOC

---

## Análisis y Decodificación

| Herramienta | URL | Uso | Tipo |
|-------------|-----|-----|------|
| **CyberChef** | gchq.github.io/CyberChef | Swiss army knife: decode, hash, cifrado, análisis | Online / Self-hosted |
| **de4js** | de4js.kshift.me | Deofuscación de JavaScript | Online |
| **Any.run** | any.run | Sandbox con análisis de tráfico TLS | Online |
| **Hybrid Analysis** | hybrid-analysis.com | Sandbox gratuito | Online |

### CyberChef — Recetas útiles para SOC

```
# Decodificar PowerShell -enc:
"From Base64" → "Decode text (UTF-16LE)"

# Analizar un hash:
"SHA256" de un input para comparar

# Multi-layer decode:
"From Base64" → "From Base64" → "From Base64" (capas de ofuscación)

# Detectar encoding:
"Magic" (CyberChef detecta automáticamente el encoding)
```

---

## Hash y Verificación de IOCs

| Herramienta | URL | Uso |
|-------------|-----|-----|
| **VirusTotal** | virustotal.com | Buscar hashes, URLs, IPs contra 70+ engines |
| **MalwareBazaar** | bazaar.abuse.ch | Samples de malware, búsqueda por hash |
| **Any.run** | any.run | Sandbox + IOC extraction |
| **OTX AlienVault** | otx.alienvault.com | Threat intel comunitaria, IOCs |
| **MISP** | misp-project.org | Plataforma de threat sharing (self-hosted) |

### Calcular hashes rápido

```bash
# Linux
sha256sum archivo.exe
md5sum archivo.exe
sha1sum archivo.exe

# PowerShell (Windows)
Get-FileHash archivo.exe -Algorithm SHA256
Get-FileHash archivo.exe -Algorithm MD5

# Python
python -c "import hashlib; print(hashlib.sha256(open('archivo.exe','rb').read()).hexdigest())"
```

---

## Análisis de TLS y Red

| Herramienta | URL/Comando | Uso |
|-------------|-------------|-----|
| **Wireshark** | wireshark.org | Captura y análisis de tráfico TLS/red |
| **Zeek (Bro)** | zeek.org | NSM: extrae JA3, certs, DNS, logs |
| **JA3 lookup** | ja3er.com | Identificar herramienta por fingerprint JA3 |
| **SSL Labs** | ssllabs.com/ssltest | Test de configuración TLS de servidor |
| **testssl.sh** | testssl.sh | Test TLS desde CLI |
| **nmap** | nmap.org | `nmap --script ssl-enum-ciphers -p 443 host` |

### Filtros Wireshark útiles

```
# Ver todo el tráfico TLS
tls

# Ver solo ClientHello (para JA3)
tls.handshake.type == 1

# Ver certificados del servidor
tls.handshake.type == 11

# Filtrar por SNI específico
tls.handshake.extensions_server_name == "malicious.com"

# Ver certificados autofirmados (básico)
# Requiere correlación: issuer = subject
```

---

## Análisis de Binarios / Malware

| Herramienta | Uso |
|-------------|-----|
| **strings** / **floss** | Extraer strings de binarios (incluye strings ofuscados) |
| **binwalk** | Análisis de firmware y entropía (`binwalk -E archivo`) |
| **PEStudio** | Análisis estático de PE (Windows) |
| **Ghidra** | Decompilador (NSA, gratuito) |
| **IDA Free** | Decompilador/disassembler |
| **x64dbg** | Debugger de Windows |
| **ent** | Calcular entropía de Shannon de archivos |

### Detectar cifrado por entropía

```bash
# Linux — ent
sudo apt install ent
ent archivo.bin
# Entropy = 7.9xx → probablemente cifrado/comprimido
# Entropy = 4-6   → archivo de texto/datos normales

# binwalk
binwalk -E archivo.bin  # genera gráfico de entropía

# Python
python -c "
import math, collections
data = open('archivo.bin','rb').read()
freq = collections.Counter(data)
entropy = -sum(c/len(data)*math.log2(c/len(data)) for c in freq.values())
print(f'Entropía: {entropy:.4f} bits/byte')
"
```

---

## Forense y Respuesta a Incidentes

| Herramienta | Uso |
|-------------|-----|
| **FTK Imager** | Adquisición forense, cálculo de hashes |
| **Autopsy** | Análisis forense de discos |
| **Volatility 3** | Análisis de dumps de memoria (buscar claves AES) |
| **WinPmem** | Dump de memoria RAM en Windows |
| **Velociraptor** | DFIR platform (hunting, colección de evidencia) |
| **KAPE** | Recolección rápida de artefactos forenses |

### Buscar claves AES en memoria (Volatility)

```bash
# Ver procesos activos
vol.py -f memory.dmp windows.pslist

# Buscar strings en proceso específico (PID del ransomware)
vol.py -f memory.dmp windows.memmap --pid 4821 --dump

# Buscar estructuras de claves AES (patrones de bytes específicos)
vol.py -f memory.dmp windows.strings --pid 4821
```

---

## Ransomware — Recursos de Respuesta

| Recurso | URL | Uso |
|---------|-----|-----|
| **No More Ransom** | nomoreransom.org | Decryptors gratuitos oficiales |
| **ID Ransomware** | id-ransomware.malwarehunterteam.com | Identificar familia por nota/extensión |
| **Ransomware.live** | ransomware.live | Monitor de víctimas publicadas en dark web |
| **CISA Ransomware** | cisa.gov/ransomware | Alertas y guías oficiales del gobierno |

---

## Certificados y PKI

```bash
# Ver certificado de un sitio web
openssl s_client -connect example.com:443 </dev/null

# Extraer info del certificado
openssl s_client -connect example.com:443 </dev/null | openssl x509 -noout -text

# Verificar cadena de certificados
openssl verify -CAfile chain.pem certificado.pem

# Windows: ver cert de ejecutable
Get-AuthenticodeSignature "C:\ruta\archivo.exe" | Format-List *

# Ver certificados instalados en Windows
certmgr.msc
```
