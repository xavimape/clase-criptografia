# 07 — Anatomía de un Ataque de Ransomware

> **Slides relacionados:** 09 y 10 de `crypto-soc-training.html`

---

## Visión general

El ransomware moderno es la aplicación práctica de **toda la criptografía vista** en este curso. Entender cómo funciona criptográficamente te permite:
- Detectarlo más rápido
- Evaluar si hay posibilidad de recuperación
- Responder al incidente correctamente

---

## Fases del ataque — MITRE ATT&CK

```
INITIAL ACCESS          EXECUTION            PERSISTENCE
──────────────          ─────────            ───────────
Phishing                PowerShell           Scheduled Task
RDP expuesto            WMI                  Registry Run Key
VPN vuln                LOLBins              Service Installation
Supply chain            Macro Office         Startup Folder
```

```
DISCOVERY               LATERAL MOVEMENT     EXFILTRATION
─────────               ────────────────     ────────────
Net discovery           PsExec               Antes de cifrar
AD enumeration          WMI remote           FTP/HTTPS a C2
Share mapping           SMB                  Rclone/MEGAsync
Backup discovery        RDP                  (doble extorsión)
```

```
IMPACT
──────
Cifrado AES-256 por archivo
Clave AES cifrada con RSA-2048
Ransomnote en cada carpeta
Shadow copies eliminadas
Backups destruidos
```

---

## Análisis criptográfico por fase

### Fase 1: Acceso inicial
```
Payload inicial frecuentemente en Base64:
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...
                ↑ decodifica a: IEX (New-Object Net.WebClient).DownloadString(...)

Por qué:
- Evade firmas de AV que buscan strings conocidos
- Bypasea filtros de email que bloquean .exe
- El script se ejecuta en memoria (fileless)
```

### Fase 2: Comunicación C2
```
Beaconing por TLS:
- Intervalo fijo (cada 5 minutos exactos)
- Certificado autofirmado o emitido recientemente
- SNI puede ser dominio legítimo (domain fronting)
- JA3 fingerprint de herramienta C2 conocida

En Zeek/Bro:
conn.log → same dest_ip:443, interval stddev < 2s → beaconing
ssl.log  → cert_issuer = cert_subject → autofirmado
```

### Fase 3: Pre-cifrado (exfiltración)
```
Doble extorsión (modelo actual):
1. Antes de cifrar → exfiltran datos sensibles
2. Cifran los datos
3. "Pagá o publicamos tus datos"

Herramientas comunes de exfiltración:
- rclone.exe (copia a Mega, Google Drive, etc.)
- WinSCP
- curl/wget a C2 propio
- Tráfico TLS legítimo a servicios cloud
```

### Fase 4: El cifrado
```
IMPLEMENTACIÓN TÍPICA:

for cada archivo en disco:
    1. generar_clave_aes() → 256 bits aleatorios
    2. aes_clave = bytes_aleatorios
    
    3. cifrar_archivo(archivo, aes_clave, modo=AES-CBC o CTR)
       → archivo.docx → archivo.docx.LOCKED
    
    4. cifrar_clave(aes_clave, rsa_publica_atacante)
       → aes_clave_cifrada (guardada en archivo header o ransomnote)
    
    5. borrar_aes_clave_de_memoria()

Al final:
- vssadmin delete shadows /all /quiet   (elimina shadow copies)
- wbadmin delete catalog -quiet          (elimina catálogos de backup)
- bcdedit /set {default} recoveryenabled No
```

### Fase 5: Post-cifrado
```
Ransomnote creada en cada carpeta:
README.txt / HOW_TO_DECRYPT.txt / RANSOMNOTE.html

Contenido típico:
- Explicación de qué pasó
- Proof of Life: ofrecen descifrar 1-3 archivos gratis
- Instrucciones para pagar (Tor + crypto)
- Amenaza de publicar datos (doble extorsión)
- Deadline (urgencia psicológica)
```

---

## Familias de ransomware y sus características criptográficas

| Familia | Cifrado | Características |
|---------|---------|-----------------|
| LockBit 3.0 | AES-256 + RSA-2048/4096 | Muy rápido, cifrado parcial de archivos grandes |
| BlackCat/ALPHV | AES-256 + ChaCha20 | Escrito en Rust, multi-plataforma |
| Cl0p | AES-128 (por víctima) | Exfiltración masiva antes de cifrar |
| Hive | AES + RSA | Tenía bug en RNG — CISA publicó decryptor |
| WannaCry (2017) | AES-128-CBC + RSA-2048 | Bug en implementación → decryptor disponible |

---

## ¿Cuándo es posible recuperar sin pagar?

```
Escenario A: RNG débil (generador de números aleatorios predecible)
→ Hive ransomware: el RNG tenía flaw → CISA publicó herramienta de descifrado
→ Lección: la seguridad del cifrado depende de la aleatoriedad de la clave

Escenario B: Bug en implementación de AES
→ WannaCry: en algunas versiones la clave quedaba en memoria
→ WannaKey/WanaKiwi: extraía la clave de la memoria RAM
→ Lección: NUNCA apagar la máquina antes de hacer dump de RAM

Escenario C: Clave hardcodeada
→ Raros, generalmente en ransomware amateur
→ Análisis estático del binario puede revelar la clave

Escenario D: La clave privada RSA del atacante filtrada
→ Ocurre cuando el C2 del atacante es comprometido o el grupo desaparece
→ Grupos como Conti tuvieron sus claves filtradas internamente
```

---

## Checklist de respuesta a incidente de ransomware

```
DETECCIÓN
□ Confirmar el scope: ¿cuántos sistemas afectados?
□ Identificar el vector inicial
□ ¿Está en progreso? → Aislar de red INMEDIATAMENTE
□ Preservar evidencia: snapshot de VMs, dump de RAM si es posible

CONTENCIÓN
□ Aislar segmento afectado
□ Bloquear C2 conocidos (IOCs de la familia)
□ Revocar credenciales comprometidas
□ Verificar si los backups están intactos y limpios

ANÁLISIS
□ Identificar la familia de ransomware
□ Buscar en NoMoreRansom.org → ¿hay decryptor disponible?
□ Extraer IOCs para hunting en el resto de la red
□ Determinar si hubo exfiltración previa (doble extorsión)

RECUPERACIÓN
□ Restaurar desde backup limpio (fecha anterior a compromiso)
□ Si no hay backup: evaluar opciones de descifrado (pago solo como último recurso)
□ Parchear el vector inicial antes de restaurar
□ Monitoreo intensivo post-recuperación
```

---

## Recursos para respuesta a ransomware

| Recurso | URL | Uso |
|---------|-----|-----|
| No More Ransom | nomoreransom.org | Decryptors gratuitos oficiales |
| ID Ransomware | id-ransomware.malwarehunterteam.com | Identificar familia por nota/extensión |
| Ransomware.live | ransomware.live | Monitoreo de víctimas publicadas |
| CISA Advisories | cisa.gov/ransomware | Alertas y guías oficiales |

---

## Takeaways finales del analista SOC

```
IDENTIFICA RÁPIDO:
Base64   → termina en =, chars A-Za-z0-9+/
Hex      → solo 0-9 A-F, longitud par
MD5      → 32 chars hex
SHA-256  → 64 chars hex
AES enc  → extensiones cambiadas, I/O alto, CPU alta
TLS C2   → beaconing regular, cert autofirmado, JA3 conocido

PREGUNTA SIEMPRE:
¿Tiene clave?         → Cifrado
¿Longitud fija?       → Hash
¿Reversible sin clave? → Codificación (Base64, Hex...)
¿Firmado = seguro?    → NO. Firma válida ≠ binario legítimo

NUNCA OLVIDES:
- Hashear la evidencia antes de tocarla
- Dump de RAM antes de apagar una máquina infectada
- Verificar backups ANTES de necesitarlos
- Base64 NO es cifrado
```
