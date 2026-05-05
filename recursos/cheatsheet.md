# 📋 Cheatsheet — Criptografía para SOC Analyst

Referencia rápida para usar durante análisis de incidentes.

---

## Identificación rápida

| Observación | Tipo | Acción |
|-------------|------|--------|
| 32 chars hex | MD5 | Buscar en VirusTotal |
| 40 chars hex | SHA-1 | Buscar en VirusTotal |
| 64 chars hex | SHA-256 | Buscar en VirusTotal |
| 128 chars hex | SHA-512 | Buscar en VirusTotal |
| Termina en `=` o `==`, chars A-Za-z0-9+/ | Base64 | Decodificar (CyberChef) |
| Solo 0-9 A-F, longitud par | Hex | Decodificar |
| `%XX` en URL | URL encoding | URL decode |
| `$2b$` o `$2a$` al inicio | bcrypt | No crackeable fácil |
| `$argon2` al inicio | Argon2 | No crackeable fácil |
| `\x41\x42` | Hex escapado (shellcode) | Decodificar |
| Alta entropía, no legible | Cifrado o comprimido | Analizar cabecera |

---

## PowerShell — Detección de encoding

```
powershell -enc <base64>          → ALERTA ALTA
powershell -EncodedCommand <b64>  → ALERTA ALTA
FromBase64String(...)             → ALERTA ALTA
IEX o Invoke-Expression           → ALERTA ALTA
DownloadString('http://...')      → ALERTA ALTA
-NoProfile -NonInteractive        → Sospechoso
ExecutionPolicy Bypass            → Sospechoso
```

**Decodificar:**
```python
import base64
base64.b64decode(payload).decode('utf-16-le')
```

---

## LOLBins — Binarios legítimos abusados

| Binario | Uso malicioso | MITRE |
|---------|---------------|-------|
| `certutil.exe -decode` | Decodificar Base64, descargar archivos | T1140, T1105 |
| `mshta.exe http://...` | Ejecutar HTA remoto | T1218.005 |
| `regsvr32.exe /s /u /i:http://...` | Cargar DLL remota (Squiblydoo) | T1218.010 |
| `rundll32.exe` | Ejecutar DLL | T1218.011 |
| `wmic.exe process call create` | Ejecución de proceso | T1047 |
| `bitsadmin.exe /transfer` | Descarga de archivos | T1197 |

---

## Hash — Referencia rápida

| Algoritmo | Bits | Chars hex | Estado |
|-----------|------|-----------|--------|
| MD5 | 128 | 32 | ❌ Roto (colisiones) |
| SHA-1 | 160 | 40 | ❌ Deprecated (SHAttered) |
| SHA-256 | 256 | 64 | ✅ Seguro — usar esto |
| SHA-512 | 512 | 128 | ✅ Muy seguro |
| bcrypt | — | ~60 chars | ✅ Contraseñas |
| Argon2id | — | variable | ✅ Contraseñas (mejor) |

---

## Cifrado — Referencia rápida

| Algoritmo | Tipo | Bits clave | Estado | Uso típico |
|-----------|------|-----------|--------|------------|
| AES-128-CBC | Simétrico | 128 | ✅ | TLS legacy, ransomware antiguo |
| AES-256-GCM | Simétrico | 256 | ✅✅ | TLS 1.3, VPNs modernas |
| RSA-2048 | Asimétrico | 2048 | ✅ | Firmas, intercambio de clave |
| RSA-4096 | Asimétrico | 4096 | ✅✅ | Alta seguridad |
| ECC P-256 | Asimétrico | 256 | ✅✅ | TLS 1.3, móviles |
| ChaCha20 | Simétrico | 256 | ✅✅ | TLS 1.3 alt, IoT |
| DES | Simétrico | 56 | ❌ Roto | No usar |
| 3DES | Simétrico | 168 | ❌ Deprecated | No usar |
| RC4 | Simétrico | variable | ❌ Roto | No usar |

---

## TLS — Red Flags

```
❌ CRÍTICO:
  - Certificado autofirmado (issuer == subject)
  - JA3 de herramienta ofensiva conocida (Cobalt Strike, Metasploit)
  - Beaconing regular (stddev del intervalo < 5s)
  - Puerto no estándar para TLS (no 443/8443)

⚠️ SOSPECHOSO:
  - Certificado Let's Encrypt para dominio random o reciente
  - SNI sin historial DNS o con typosquatting
  - Tamaño de paquetes muy uniforme (padding)
  - Conexiones fuera de horario laboral a IPs desconocidas
  - Tráfico TLS desde proceso que no debería hacer TLS

✅ NORMAL:
  - Certificado firmado por CA conocida (DigiCert, Let's Encrypt, etc.)
  - SNI coincide con el dominio esperado del servicio
  - Tráfico variable en horario laboral
```

---

## Ransomware — Indicadores

```
DETECCIÓN TEMPRANA:
  □ CPU alta + I/O de disco sostenidos en proceso desconocido
  □ Extensiones de archivos cambiando masivamente
  □ vssadmin / wbadmin ejecutándose (eliminar shadow copies)
  □ Proceso accediendo a >100 archivos/minuto
  □ HOW_TO_DECRYPT.txt / README_LOCKED.txt creados

ANÁLISIS FORENSE:
  □ ¿Qué proceso inició el cifrado? (process tree)
  □ ¿Cuándo comenzó? (primera extensión .locked)
  □ ¿Hubo exfiltración previa? (tráfico grande al exterior)
  □ ¿Qué vector usó? (Sysmon Event ID 1 chain)
  □ ¿Hay backups limpios disponibles?

RESPUESTA INMEDIATA:
  1. AISLAR DE LA RED (antes de apagar)
  2. NO APAGAR → dump de RAM primero
  3. Verificar alcance: otros sistemas afectados
  4. Consultar nomoreransom.org para decryptors
  5. Contactar IR team / management
```

---

## Comandos forenses rápidos

```powershell
# Hash de archivo
Get-FileHash archivo.exe -Algorithm SHA256

# Ver firma digital
Get-AuthenticodeSignature archivo.exe | Format-List *

# Ver conexiones activas
netstat -ano | findstr ESTABLISHED

# Ver procesos con red
Get-NetTCPConnection | Where State -eq Established | 
  ForEach { $p = Get-Process -Id $_.OwningProcess; 
            "$($_.RemoteAddress):$($_.RemotePort) ← $($p.Name) (PID $($p.Id))" }

# Buscar archivos modificados recientemente
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | 
  Where LastWriteTime -gt (Get-Date).AddHours(-1) |
  Sort LastWriteTime -Descending | Select -First 50

# Ver shadow copies
vssadmin list shadows
```

```bash
# Linux — equivalentes
sha256sum archivo
strings binario | grep -i "key\|crypt\|aes\|rsa"
netstat -tulnp
lsof -i -n -P | grep ESTABLISHED
find / -newer /tmp/referencia -mmin -60 2>/dev/null
```

---

## Plataformas de práctica

| Plataforma | URL | Nivel |
|------------|-----|-------|
| CryptoHack | cryptohack.org | Principiante → Avanzado |
| Cryptopals | cryptopals.com | Intermedio → Avanzado |
| PicoCTF | picoctf.org | Principiante |
| HackTheBox | hackthebox.com | Intermedio → Avanzado |
| TryHackMe | tryhackme.com | Principiante → Intermedio |
| SANS Holiday Hack | holidayhackchallenge.com | Todos los niveles |
