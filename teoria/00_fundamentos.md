# 00 — Fundamentos: ¿Qué es Criptografía?

> **Slides relacionados:** 01 y 02 de `crypto-soc-training.html`

---

## ¿Por qué importa en un SOC?

Como analista vas a ver constantemente datos que "parecen" cifrados pero no lo son, o alerts que malinterpretan encoding como cifrado. Entender la diferencia no es opcional — es la base de todo análisis de malware, forense y detección de red.

---

## El triángulo que todo analista debe conocer

```
         CODIFICACIÓN
        (no hay clave)
              ↑
              |
    ¿Reversible sin clave?
              |
    SÍ ←-----+----→ NO
    |                  |
CODIFICACIÓN        ¿Longitud fija?
(Base64, Hex)          |
                  SÍ ←-+→ NO
                  |        |
                HASH    CIFRADO
             (SHA-256)   (AES, RSA)
```

### Codificación
- **Definición:** Transforma datos a otro formato para compatibilidad o transmisión.
- **Reversible:** Sí, siempre. Sin clave.
- **Seguridad:** Ninguna. No protege nada.
- **Ejemplos:** Base64, Hex, URL encoding, ASCII, UTF-8
- **Error común en SOC:** Ver Base64 y reportar "datos cifrados" ← crítico

### Hash (Función resumen)
- **Definición:** Función matemática de una sola vía. Entrada → huella de longitud fija.
- **Reversible:** No. Nunca. (Sin rainbow tables o fuerza bruta)
- **Seguridad:** Integridad, no confidencialidad.
- **Propiedad clave:** Efecto avalancha — un bit diferente = hash completamente distinto.
- **Ejemplos:** MD5 (128 bits), SHA-1 (160 bits), SHA-256 (256 bits)
- **Uso en SOC:** IOCs de malware, verificación de evidencia forense

### Cifrado
- **Definición:** Transforma datos con una clave. Requiere la clave para revertir.
- **Reversible:** Sí, pero solo con la clave correcta.
- **Seguridad:** Confidencialidad real.
- **Tipos:** Simétrico (misma clave) o Asimétrico (par de claves)
- **Ejemplos:** AES-256, RSA-2048, ChaCha20
- **Uso en SOC:** Comunicaciones C2 (TLS), ransomware, exfiltración

---

## Tabla comparativa rápida

| Propiedad | Codificación | Hash | Cifrado |
|-----------|:---:|:---:|:---:|
| Requiere clave | ❌ | ❌ | ✅ |
| Reversible | ✅ | ❌ | ✅ (con clave) |
| Longitud fija output | ❌ | ✅ | ❌ |
| Provee confidencialidad | ❌ | ❌ | ✅ |
| Provee integridad | ❌ | ✅ | ✅ (con AEAD) |
| Ejemplos | Base64, Hex | MD5, SHA-256 | AES, RSA |

---

## ⚠️ Errores críticos de analistas novatos

1. **"Esto está cifrado"** al ver Base64 → Base64 es decodificable en 2 segundos, no protege nada.
2. **"Hay que descifrar el hash"** → Los hashes no se descifran, se comparan o se atacan con fuerza bruta.
3. **"La contraseña está cifrada"** al ver un hash en una base de datos → está hasheada, no cifrada.
4. **Ignorar encoding** → El malware usa Base64 para ocultar payloads a simple vista y evadir AV.

---

## Relevancia SOC 🔍

| Situación | Qué es | Qué hacer |
|-----------|--------|-----------|
| PowerShell con `-enc AAAAAA==` | Comando en Base64 | Decodificar inmediatamente |
| Archivo con hash `d41d8cd98f00b204e9800998ecf8427e` | MD5 | Buscar en VirusTotal/MalwareBazaar |
| Tráfico HTTPS a IP desconocida | TLS (cifrado) | Analizar SNI, certificado, JA3 |
| `.encrypted` en extensiones de archivos | AES/RSA ransomware | Activar playbook de ransomware |

---

## Próximo tema
→ [01_codificacion.md](./01_codificacion.md) — Base64, Hex y detección en malware
