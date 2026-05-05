# 05 — TLS: El Canal Cifrado del C2

> **Slide relacionado:** 07 de `crypto-soc-training.html`

---

## ¿Qué es TLS?

TLS (Transport Layer Security) es el protocolo que cifra las comunicaciones en internet. Antes era SSL — TLS es su sucesor seguro.

```
Sin TLS:  [Browser] ──── texto plano ────→ [Servidor]  ← cualquiera puede leer
Con TLS:  [Browser] ── datos cifrados ──→ [Servidor]  ← solo las partes ven el contenido
```

HTTPS = HTTP sobre TLS. También: SMTPS, FTPS, IMAPS, etc.

---

## TLS Handshake simplificado (TLS 1.3)

```
Cliente                          Servidor
   |                                |
   |──── ClientHello ──────────────>|  (versiones TLS soportadas, cipher suites)
   |                                |
   |<─── ServerHello ──────────────|  (versión elegida, certificado, clave pública)
   |                                |
   |  [Verificación del certificado]|
   |                                |
   |──── Intercambio DH ──────────>|  (establecen clave de sesión AES sin enviarla)
   |<─── Intercambio DH ──────────|
   |                                |
   |  [Ambos derivan clave AES de sesión]
   |                                |
   |══════ Tráfico cifrado AES ════|  (datos de aplicación cifrados)
```

---

## Versiones de TLS

| Versión | Estado | Detalles |
|---------|--------|----------|
| SSL 2.0 | ❌ Roto | No usar bajo ningún concepto |
| SSL 3.0 | ❌ Roto (POODLE) | No usar |
| TLS 1.0 | ❌ Deprecated | Vulnerable a BEAST |
| TLS 1.1 | ❌ Deprecated | Mejor pero obsoleto |
| TLS 1.2 | ⚠️ Aceptable | Aún en uso, configurar bien |
| TLS 1.3 | ✅ Recomendado | Más rápido, más seguro, PFS obligatorio |

---

## Lo que sí podemos ver en TLS

Aunque el **contenido** está cifrado, el **metadata** es visible:

### SNI — Server Name Indication
El cliente anuncia el hostname al que se conecta **antes** de que se establezca el cifrado. Visible en texto plano en el handshake.

```
# En Wireshark:
tls.handshake.extensions_server_name == "malicious-c2.com"
```

### Certificado del servidor
- Quién lo emitió (CA)
- Para qué dominio
- Fechas de validez
- Si es autofirmado

### JA3 — Fingerprint del cliente TLS

JA3 es un hash MD5 calculado a partir de los parámetros del ClientHello:
- Versión TLS
- Cipher suites ofrecidas
- Extensiones
- Grupos de curvas elípticas

```
Cada cliente TLS tiene un JA3 "firma":
Chrome estándar:   abc123...
Cobalt Strike:     51c64c77e60f3980...
Metasploit:        5d41402abc4b2a76...
```

**Por qué importa:** Herramientas ofensivas tienen JA3 conocidos. Si ves ese JA3 en tu red, es una señal clara.

---

## Red flags de TLS en contexto SOC

### 🔴 Alerta alta
```
✗ Certificado autofirmado (self-signed)
  → Los servicios legítimos usan CAs conocidas
  
✗ Certificado con CN genérico ("localhost", "*", dominio random)
  → El C2 no invirtió en un cert válido
  
✗ JA3 hash de herramienta ofensiva conocida
  → Cobalt Strike, Metasploit, Sliver...
  
✗ Conexión periódica exacta (beaconing)
  → Ejemplo: conexión cada exactamente 300 segundos
  → El C2 implant está activo
```

### 🟡 Alerta media
```
⚠ SNI que no resuelve o tiene historial DNS mínimo
  → Dominio recién registrado (< 7 días) + HTTPS = sospechoso
  
⚠ Puerto no estándar (no 443)
  → TLS en puerto 8443, 4443, 8080... puede ser C2
  
⚠ Tamaño de paquetes muy uniforme
  → El malware puede usar padding para enmascarar beaconing
  
⚠ Certificado emitido por Let's Encrypt para dominio random
  → Let's Encrypt es gratis y automático — atacantes lo usan
```

---

## Técnicas de evasión del atacante mediante TLS

### Domain Fronting
```
Cliente → CDN (cloudfront.com) → C2 real
         ↑ SNI visible: cloudfront.com
         ↑ HTTP Host: malicious.com (cifrado, no visible)
```
La conexión parece ir a un CDN legítimo pero va al C2.

### HTTPS sobre proxy legítimo
Usar GitHub, Pastebin, Google Docs como canal C2. El tráfico parece legítimo porque lo es (los dominios son reales), pero el contenido contiene comandos.

### TLS mutual (mTLS)
Tanto cliente como servidor se autentican. Algunas familias de malware usan esto para verificar que el agente se comunica con el C2 real y no con un honeypot/sinkhole.

---

## Herramientas de análisis TLS

| Herramienta | Uso |
|-------------|-----|
| Wireshark | Captura y análisis de handshakes TLS |
| Zeek (Bro) | Extracción automática de JA3, certs, SNI |
| [ja3er.com](https://ja3er.com) | Lookup de JA3 conocidos |
| SSL Labs | Test de configuración TLS de servidores |
| testssl.sh | Test de configuración TLS desde CLI |

---

## Consultas útiles en SIEM/EDR

```sql
-- Conexiones TLS a IPs sin hostname (sospechoso)
WHERE dest_port = 443 AND NOT dns_resolved AND tls_enabled

-- JA3 de herramientas conocidas
WHERE ja3_hash IN ('51c64c77e60f3980...', '5d41402abc4b2a76...')

-- Certificados autofirmados
WHERE tls_cert_issuer = tls_cert_subject

-- Beaconing: conexiones a mismo destino con intervalo fijo
GROUP BY src_ip, dest_ip
HAVING stddev(connection_interval) < 5  -- muy regular = sospechoso
```

---

## Relevancia SOC 🔍

El análisis de TLS **no requiere descifrar el tráfico**. Con metadata visible podés:
- Identificar C2 activos por beaconing
- Detectar herramientas ofensivas por JA3
- Encontrar dominios maliciosos por SNI
- Detectar certs autofirmados en segmentos internos
- Correlacionar con threat intel de dominios/IPs

---

## Próximo tema
→ [06_firmas_digitales.md](./06_firmas_digitales.md) — Firmas digitales y TTPs reales
