# 🔴 Nivel 3 — Difícil

Ejercicios de análisis profundo. Requieren Python y conocimiento integrado de todos los temas.

---

## Ejercicio 3.1 — Romper un cifrado débil (XOR)

Interceptaste comunicación C2. El tráfico está "cifrado" con XOR de clave de 1 byte.

```python
# Datos interceptados (bytes en hex):
datos = bytes.fromhex(
    "1b1b1a1e0b1b041e1b070b1e081f1e1b1b0b041e"
    "1b0b1e1b071e041e1b1b07040b1b041e"
)
```

**Preguntas:**
1. ¿Por qué XOR de 1 byte es un cifrado terrible?
2. Encontrá la clave y decodificá el mensaje (brute force de 256 posibilidades)
3. ¿Cómo mejorarías este esquema para que fuera más difícil de romper?

<details>
<summary>💡 Pistas</summary>

```python
# Brute force XOR de 1 byte
for clave in range(256):
    resultado = bytes(b ^ clave for b in datos)
    if resultado.isascii() and resultado.isprintable():
        print(f"Clave {clave} ({hex(clave)}): {resultado.decode()}")
```

</details>

<details>
<summary>✅ Solución</summary>

```python
datos = bytes.fromhex(
    "1b1b1a1e0b1b041e1b070b1e081f1e1b1b0b041e"
    "1b0b1e1b071e041e1b1b07040b1b041e"
)

for clave in range(256):
    resultado = bytes(b ^ clave for b in datos)
    try:
        texto = resultado.decode('ascii')
        if texto.isprintable() and ' ' in texto:
            print(f"Clave: {hex(clave)} → {texto!r}")
    except:
        pass
```

**Resultado:** clave = 0x7f → mensaje legible

**¿Por qué XOR de 1 byte es terrible?**
- Solo 256 claves posibles → brute force instantáneo
- Frecuencia de bytes se mantiene (análisis de frecuencia)
- Si conocés cualquier parte del plaintext → conocés la clave entera

**Mejoras:**
- Usar AES-GCM (cifrado real + autenticación)
- Si se quiere XOR: Vernam cipher con clave tan larga como el mensaje y nunca reutilizada (one-time pad — teóricamente perfecto pero imprácticamente)

</details>

---

## Ejercicio 3.2 — Análisis forense de ransomware

Tenés acceso a la muestra de ransomware (en un sandbox) y a un archivo cifrado.

**Datos del análisis estático:**
```
Strings encontrados en el binario:
  - "AES-256-CBC"
  - "-----BEGIN PUBLIC KEY-----"
  - "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2q1..."  (truncado)
  - "HOW_TO_DECRYPT.txt"
  - ".LOCKED"
  - "vssadmin delete shadows /all /quiet"

Importaciones de Windows API:
  - CryptAcquireContext
  - CryptGenRandom
  - CryptEncrypt
  - CryptDestroyKey

El binario también contiene hardcodeada (¡error del atacante!) una clave XOR 
usada para ofuscar la clave AES ANTES de cifrarla con RSA:
  XOR key: 0xDEADBEEF (4 bytes, repetido)
```

**Archivo cifrado capturado:**
```
Header del archivo .LOCKED (primeros 512 bytes en hex):
4c4f434b45440000  ← magic "LOCKED\0\0"
00000100          ← versión 1.0
[256 bytes]       ← clave AES cifrada con RSA + XOR
[16 bytes]        ← IV de AES
[resto]           ← datos cifrados con AES-256-CBC
```

**Preguntas:**
1. ¿Cuál es el error crítico del atacante?
2. Dado que tenemos la clave RSA pública, ¿podemos recuperar la clave AES?
3. ¿Qué herramienta usarías para extraer la clave RSA del binario?
4. Escribí el pseudocódigo para el proceso de decryption completo
5. ¿Qué indica `CryptGenRandom` sobre la calidad del cifrado?

<details>
<summary>✅ Solución</summary>

**1. Error crítico del atacante:**
- Hardcodear la clave XOR en el binario es un error grave de OPSEC
- Si la clave XOR es conocida, la clave AES puede ser "pre-descifrada" antes del RSA
- Esto NO rompe el RSA (la clave AES sigue cifrada con RSA), pero muestra descuido general

**2. ¿Podemos recuperar la clave AES?**
- Con solo la clave pública RSA: **NO** — necesitamos la clave privada para descifrar
- El XOR debilitaría el esquema SOLO si hubiera otro fallo adicional
- Pero si el atacante almacena la clave privada en el C2 y ese C2 cae → sí

**3. Herramientas para extraer RSA del binario:**
```bash
# Extraer strings y buscar clave PEM
strings malware.exe | grep -A 30 "BEGIN PUBLIC KEY"

# Extraer con pefile (Python)
import pefile
pe = pefile.PE("malware.exe")

# YARA rule para encontrar claves RSA embebidas:
# rule find_rsa { strings: $pem = "-----BEGIN PUBLIC KEY-----" condition: $pem }
```

**4. Pseudocódigo de decryption:**
```python
# Dado que tenemos clave RSA privada (del C2 comprometido)
blob_xor_rsa = leer_header(archivo_locked)[8+4 : 8+4+256]  # 256 bytes
iv = leer_header(archivo_locked)[8+4+256 : 8+4+256+16]
datos_cifrados = leer_datos(archivo_locked)[8+4+256+16:]

# 1. Revertir XOR (sabemos la clave: 0xDEADBEEF)
xor_key = bytes([0xDE, 0xAD, 0xBE, 0xEF]) * 64  # repetido para 256 bytes
blob_rsa = xor(blob_xor_rsa, xor_key)

# 2. Descifrar con RSA privada
clave_aes = RSA.decrypt(blob_rsa, clave_privada_rsa)  # resultado: 32 bytes

# 3. Descifrar datos con AES-CBC
datos_originales = AES.decrypt(datos_cifrados, clave_aes, iv, modo=CBC)
```

**5. `CryptGenRandom`:**
- Es el CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) de Windows
- Indica que el ransomware genera claves AES verdaderamente aleatorias
- Esto es correcto desde el punto de vista del atacante
- Si usara `rand()` de C estándar: sería un RNG débil y predecible (como Hive ransomware)

</details>

---

## Ejercicio 3.3 — Diseñar un sistema de detección

Sos el nuevo analista de un SOC que no tiene reglas de detección para criptografía maliciosa. Tu jefe te pide que diseñes las reglas SIEM/EDR fundamentales.

**Diseñá reglas de detección para cada uno de estos escenarios:**

1. **PowerShell con encoding** — detección de comandos `-enc` en Sysmon Event ID 1
2. **Beaconing C2** — detección de conexiones periódicas a misma IP
3. **Ransomware en actividad** — detección de cifrado masivo en progreso
4. **LOLBin abusando crypto** — certutil.exe usado para decode

Formato esperado: pseudoSQL o lógica clara, con campos reales de Sysmon/Windows.

<details>
<summary>✅ Solución</summary>

```sql
-- REGLA 1: PowerShell Encoded Command
-- Fuente: Sysmon Event ID 1 (Process Creation)
SELECT *
FROM sysmon_process_creation
WHERE
  Image LIKE '%powershell.exe'
  AND (
    CommandLine ILIKE '%-enc %'
    OR CommandLine ILIKE '%-encodedcommand %'
    OR CommandLine ILIKE '%frombase64string%'
  )
  AND LENGTH(CommandLine) > 200  -- payloads codificados son largos
-- Severidad: HIGH
-- MITRE: T1059.001

-- REGLA 2: Beaconing detection (Zeek/SIEM de red)
SELECT
  src_ip, dst_ip, dst_port,
  COUNT(*) as conexiones,
  STDDEV(connection_interval) as jitter,
  AVG(bytes_sent) as avg_bytes
FROM network_connections
WHERE dst_port IN (80, 443, 8080, 8443)
GROUP BY src_ip, dst_ip, dst_port, time_bucket('1h', timestamp)
HAVING
  COUNT(*) >= 5                -- al menos 5 conexiones
  AND jitter < 10              -- muy regulares (segundos)
  AND AVG(bytes_sent) < 2000   -- beacons son pequeños
-- Severidad: MEDIUM (requiere correlación con reputación de IP)

-- REGLA 3: Ransomware en actividad
-- Fuente: Sysmon Event ID 11 (FileCreate) + Event ID 1
SELECT src_process, COUNT(*) as archivos_afectados
FROM sysmon_file_create
WHERE
  FileName LIKE '%.locked'
  OR FileName LIKE '%.encrypted'
  OR FileName LIKE '%.crypt'
  OR FileName = 'HOW_TO_DECRYPT.txt'
  OR FileName = 'README.txt'  -- validar con contexto
GROUP BY src_process
HAVING COUNT(*) > 20  -- más de 20 archivos en la ventana
-- Severidad: CRITICAL — ACTUAR INMEDIATAMENTE
-- MITRE: T1486

-- REGLA 4: certutil LOLBin abuse
-- Fuente: Sysmon Event ID 1
SELECT *
FROM sysmon_process_creation
WHERE
  Image LIKE '%certutil.exe'
  AND (
    CommandLine ILIKE '%-decode%'
    OR CommandLine ILIKE '%-urlcache%'
    OR CommandLine ILIKE '%-f http%'
    OR CommandLine ILIKE '%-encode%'
  )
-- Severidad: HIGH
-- MITRE: T1140, T1105
```

</details>

---

## Ejercicio 3.4 — Investigación integrada (caso completo)

Recibís un ticket escalado con la siguiente información:

```
TICKET #IR-2024-0042
Severidad: CRÍTICA
Afectado: CORP-DC-01 (Domain Controller)

Alert original: 
  - Sysmon E1: lsass.exe → accedido por mimikatz64.exe (renombrado como svchost.exe)
  - Sysmon E3: conexión HTTPS a 185.220.101.45:443 con JA3 72a589da586844d7f0818ce684948eea
  - Sysmon E11: creation of "readme_decrypt.txt" en C:\Users\Administrator\Desktop

Email recibido en info@corpxyz.com:
  "Hemos cifrado sus sistemas. Tienen 72hs para pagar 2BTC.
   Para prueba, adjuntamos archivo descifrado: proposal.docx"
```

**Construí una línea de tiempo del ataque, identificá qué criptografía se usó en cada fase y qué evidencia recopilarías.**

<details>
<summary>✅ Solución parcial (hay múltiples respuestas válidas)</summary>

**Línea de tiempo reconstruida:**

```
FASE 1 — ACCESO INICIAL
Desconocido. Posibles vectores: phishing, RDP expuesto, VPN vuln
Criptografía: probablemente payload ofuscado en Base64

FASE 2 — CREDENTIAL THEFT (crítico)
- lsass.exe accedido → volcado de credenciales (Mimikatz)
- Mimikatz extrae: NTLM hashes, Kerberos tickets, plaintext passwords de LSASS
- Criptografía relevante: NTLM hash (MD4 del password), Kerberos (AES-256)
- Con esto: lateral movement y escalada de privilegios

FASE 3 — C2 ESTABLECIDO
- JA3 72a589da586844d7f0818ce684948eea → asociado a Cobalt Strike Beacon
- IP 185.220.101.45 → nodo Tor exit o infrastructure de atacante
- Criptografía: TLS 1.2/1.3 (HTTPS cifrado)
- Beaconing encubierto como tráfico HTTPS legítimo

FASE 4 — EXFILTRACIÓN (doble extorsión)
- Email menciona "archivo descifrado" → tienen una copia de datos ANTES de cifrar
- Exfiltraron via HTTPS al C2 (los 2.4KB? — posiblemente solo las llaves)
- La exfiltración real fue mayor

FASE 5 — CIFRADO
- readme_decrypt.txt creado → post-cifrado, nota de rescate
- Criptografía: AES-256 para datos + RSA-2048/4096 para clave AES

EVIDENCIA A RECOPILAR:
□ Memory dump del DC (preservar antes de apagar)
□ Logs Sysmon completos (Event IDs 1,3,7,10,11,12,13)
□ Logs de seguridad de Windows (4624, 4625, 4648, 4688)
□ Netflow/PCAP de conexiones al C2
□ Muestra del ransomware (enviar a sandbox)
□ Nota de rescate y extensión de archivos cifrados
□ Lista de IPs contactadas (para hunting en otros sistemas)
□ Active Directory logs (¿cuándo se crearon cuentas nuevas?)
```

</details>

---

*¿Querés más desafíos? Probá en [CryptoHack.org](https://cryptohack.org) o [Cryptopals](https://cryptopals.com)*
