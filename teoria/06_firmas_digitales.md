# 06 — Firmas Digitales y TTPs Reales

> **Slide relacionado:** 08 de `crypto-soc-training.html`

---

## ¿Qué es una firma digital?

Una firma digital garantiza dos cosas simultáneamente:
- **Autenticidad:** El archivo viene de quien dice ser
- **Integridad:** El archivo no fue modificado después de ser firmado

No es una imagen de firma — es criptografía pura.

---

## Cómo funciona

### Proceso de firma
```
[El firmante tiene su clave privada]

1. Calcula el hash del documento
   SHA-256(documento.exe) = "abc123..."

2. Cifra ese hash con su clave privada
   RSA_sign(hash, clave_privada) = firma_digital

3. Adjunta la firma al documento
   documento.exe + firma + certificado_público
```

### Proceso de verificación
```
[El verificador tiene la clave pública del firmante]

1. Descifra la firma con la clave pública del firmante
   RSA_verify(firma, clave_pública) = hash_original = "abc123..."

2. Calcula el hash del documento recibido
   SHA-256(documento_recibido.exe) = "abc123..."

3. Compara ambos hashes
   "abc123..." == "abc123..." → ✅ VÁLIDO
   "abc123..." != "xyz789..." → ❌ INVÁLIDO (modificado o falso)
```

---

## Cadena de confianza (PKI)

```
Certificado Raíz (Root CA)
    ↓ firma
Certificado Intermedio (Intermediate CA)
    ↓ firma
Certificado de entidad final (tu exe, tu web)
```

Los sistemas operativos incluyen una lista de Root CAs confiables. Si la cadena llega a una Root CA confiable, el certificado es válido.

**Root CAs conocidas:** DigiCert, Let's Encrypt, GlobalSign, Sectigo, Comodo

---

## Windows Authenticode — Firmas de binarios

Windows usa **Authenticode** para firmar ejecutables. Al ejecutar un .exe firmado:

```
Firma válida + CA conocida → se ejecuta (con o sin aviso)
Firma válida + CA desconocida → SmartScreen puede alertar
Sin firma → SmartScreen alerta o bloquea
```

**Verificar firma en Windows:**
```powershell
# PowerShell
Get-AuthenticodeSignature .\archivo.exe

# Salida:
Status          : Valid
SignerCertificate : [Cert de Microsoft Corporation]
Path            : archivo.exe
```

---

## TTPs Reales — Cómo el malware abusa de firmas

### 1. Living off the Land (LOLBins)

Usar binarios legítimos **firmados por Microsoft** para ejecutar código malicioso.

```
Los atacantes usan binarios como:
- mshta.exe → ejecuta HTA (HTML Application)
- regsvr32.exe → puede cargar DLLs remotas
- certutil.exe → puede decodificar Base64 y descargar archivos
- wmic.exe → ejecución lateral
- rundll32.exe → cargar DLLs

Ventaja del atacante:
✓ Firmados por Microsoft → no disparan AV por firma
✓ Legítimos → difíciles de bloquear
✓ Presentes en todos los Windows
```

**Detección:** Comportamiento anómalo del proceso, no la firma:
```
certutil.exe -decode input.b64 output.exe
           ↑ uso anómalo de certutil para decodificar payload
```

### 2. Certificados robados de empresas comprometidas

Atacantes que comprometen empresas legítimas pueden robar sus certificados de firma de código y firmar malware con ellos.

**Casos reales:**
- **Stuxnet (2010):** Firmado con certificados robados de Realtek y JMicron
- **CCleaner (2017):** Supply chain — el instalador legítimo fue trojanizado y firmado con el cert real de Avast
- **3CX (2023):** Supply chain attack, binario oficial firmado por 3CX contenía malware

**Detección:**
```
Firma válida del certificado ≠ Binario legítimo

Acciones:
- Verificar hash SHA-256 del binario contra fuente oficial
- Revisar fecha de firma vs fecha de compilación
- Analizar el binario en sandbox aunque esté firmado
- Revisar si el certificado fue revocado (CRL, OCSP)
```

### 3. Self-signed certificates en tráfico interno

```
Red interna con cert autofirmado:
- Puede ser legacy legítimo
- Puede ser malware con cert propio para C2
- Puede ser herramienta de ataque (Cobalt Strike, etc.)

Regla práctica:
- Cert autofirmado + proceso inesperado haciendo conexiones = alerta
```

### 4. Timestamp forgery

Las firmas incluyen timestamp para probar cuándo se firmó. Algunos atacantes manipulan el timestamp para hacer que malware nuevo parezca firmado hace años (antes del incidente).

---

## Verificación práctica

```powershell
# Ver firma de un ejecutable
Get-AuthenticodeSignature "C:\Windows\System32\notepad.exe" | Format-List *

# Verificar si el certificado fue revocado
# (PowerShell verifica automáticamente por defecto)

# Calcular hash para comparar con fuente oficial
Get-FileHash "archivo.exe" -Algorithm SHA256
```

```bash
# Linux: verificar firma de paquetes
gpg --verify archivo.sig archivo
rpm -K paquete.rpm
dpkg-sig --verify paquete.deb
```

---

## Relevancia SOC 🔍

| Observación | Interpretación | Acción |
|-------------|---------------|--------|
| Binario firmado con SHA256 diferente al oficial | Supply chain attack | Aislar, analizar, escalar |
| certutil.exe decodificando archivos | LOLBin abuse | Investigar proceso padre |
| mshta.exe ejecutando URL remota | Ejecución remota vía HTA | Alta prioridad |
| Cert de empresa conocida pero dominio sospechoso | Cert robado o falso | Verificar con la empresa |
| Firma con timestamp muy antiguo en binario nuevo | Timestamp forgery | Analizar metadata de PE |

---

## Próximo tema
→ [07_ransomware.md](./07_ransomware.md) — Anatomía completa de un ataque de ransomware
