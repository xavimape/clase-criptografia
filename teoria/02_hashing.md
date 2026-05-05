# 02 — Hashing: La Huella Digital

> **Slide relacionado:** 04 de `crypto-soc-training.html`

---

## ¿Qué es una función hash?

Una función hash toma un input de cualquier tamaño y produce un output de **longitud fija** (el "digest" o "hash"). Es matemáticamente irreversible — no existe "deshacer" un hash.

```
SHA-256("Hello")  = 185f8db32921bd46d11b5c2d8f950e6b56e8d9b4d7b40aea3...
SHA-256("hello")  = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73...
                                       ↑
                          Un solo carácter diferente = hash completamente distinto
```

Esta propiedad se llama **efecto avalancha**.

---

## Propiedades de una función hash criptográfica

| Propiedad | Descripción |
|-----------|-------------|
| **Determinismo** | Mismo input → siempre mismo output |
| **Velocidad** | Rápido de calcular |
| **Efecto avalancha** | Cambio mínimo en input → cambio total en output |
| **Pre-imagen resistente** | Dado un hash H, imposible encontrar x tal que hash(x)=H |
| **Segunda pre-imagen resistente** | Dado x, imposible encontrar y≠x tal que hash(x)=hash(y) |
| **Resistencia a colisiones** | Imposible encontrar x,y tal que hash(x)=hash(y) |

---

## Algoritmos principales

### MD5 — 128 bits (32 chars hex)
```
MD5("clase-criptografia") = a3c2f1e9b7d4...  (32 caracteres hex)
```
- **Estado:** ❌ Roto criptográficamente (colisiones conocidas)
- **Velocidad:** Muy rápido
- **Uso actual en SOC:** IOCs de malware (VirusTotal lo acepta), verificación básica de integridad cuando no importa la seguridad
- **Por qué no usar para seguridad:** Se pueden generar dos archivos distintos con el mismo MD5

### SHA-1 — 160 bits (40 chars hex)
```
SHA-1("clase") = a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
```
- **Estado:** ❌ Deprecated (Google rompió SHA-1 en 2017 con SHAttered)
- **Uso actual:** Legacy únicamente. Algunos IOCs antiguos. Certificados viejos.
- **Nunca usar** para firmas nuevas o almacenamiento de contraseñas

### SHA-256 — 256 bits (64 chars hex)
```
SHA-256("clase") = ...64 caracteres hex...
```
- **Estado:** ✅ Seguro, estándar actual
- **Uso:** IOCs, hashes de evidencia forense, TLS, firmas digitales, Bitcoin
- **Este es el que vas a ver más en un SOC**

### SHA-512 — 512 bits (128 chars hex)
- **Estado:** ✅ Muy seguro
- **Uso:** Alta seguridad, almacenamiento de contraseñas (junto con sal)

---

## Uso en Forense: Cadena de Custodia

El hash garantiza que la evidencia no fue modificada. Es el pilar de la integridad forense.

```
1. Se obtiene el disco/imagen
         ↓
2. Se calcula el hash SHA-256 del original
   SHA-256(imagen_original) = "abc123..."
         ↓
3. Se trabaja con una COPIA, nunca el original
         ↓
4. Cualquier modificación rompe el hash
   SHA-256(imagen_modificada) = "xyz789..." ≠ "abc123..."
         ↓
5. Si los hashes coinciden, la evidencia es íntegra
```

**Herramientas de hashing forense:**
- `sha256sum archivo.img` (Linux)
- `Get-FileHash archivo.img -Algorithm SHA256` (PowerShell)
- `md5sum`, `sha1sum`
- FTK Imager, Autopsy (automático)

---

## Uso en Threat Intel: IOCs de malware

Los hashes son los IOCs más confiables porque son únicos por archivo.

```
# Estructura típica en un reporte de amenaza:
Indicadores de Compromiso (IOCs):
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  SHA-1:  da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Plataformas donde buscar hashes:**
- [VirusTotal](https://www.virustotal.com) — el más usado
- [MalwareBazaar](https://bazaar.abuse.ch) — malware samples
- [Any.run](https://any.run) — sandboxing
- [Hybrid Analysis](https://www.hybrid-analysis.com)

---

## HMAC — Hash con clave

HMAC (Hash-based Message Authentication Code) combina un hash con una clave secreta para verificar tanto **integridad** como **autenticidad**.

```
HMAC-SHA256(mensaje, clave_secreta) = hash_autenticado
```

Uso: APIs REST, JWT (JSON Web Tokens), verificación de webhooks.

---

## Ataques a funciones hash

### Rainbow Tables
- Tablas precomputadas de hash(contraseña) → contraseña
- **Defensa:** Usar **sal** (salt) — valor aleatorio único por contraseña
- `SHA-256(contraseña + sal)` hace inútiles las rainbow tables

### Fuerza Bruta
- Probar millones de combinaciones
- MD5 puede probarse a 10+ billones/segundo en GPU
- **Defensa:** Usar bcrypt, scrypt, Argon2 (lentos por diseño)

### Colisiones
- Dos inputs distintos con el mismo hash
- MD5 y SHA-1 son vulnerables
- SHA-256: ninguna colisión conocida

---

## Cómo identificar hashes a simple vista

| Hash | Longitud | Ejemplo |
|------|----------|---------|
| MD5 | 32 chars hex | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA-1 | 40 chars hex | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA-256 | 64 chars hex | `e3b0c44298fc1c149...` |
| SHA-512 | 128 chars hex | `cf83e1357eefb8bdf...` |
| bcrypt | ~60 chars, empieza con `$2b$` | `$2b$10$N9qo8uLOick...` |

---

## Relevancia SOC 🔍

- **Alert de AV:** Siempre extraer el hash SHA-256 del binario detectado y buscarlo en VT
- **Evidencia forense:** Hashear todo antes de manipular. Documentar.
- **Contraseñas en DB comprometida:** Si son MD5 sin sal, están rotas. Si son bcrypt, hay tiempo.
- **IOC sharing:** Siempre incluir SHA-256 en los reportes, MD5 es opcional (legacy)

---

## Próximo tema
→ [03_cifrado_simetrico.md](./03_cifrado_simetrico.md) — AES y el ransomware
