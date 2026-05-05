# 03 — Cifrado Simétrico: AES y el Ransomware

> **Slide relacionado:** 05 de `crypto-soc-training.html`

---

## ¿Qué es el cifrado simétrico?

Una **sola clave** sirve para cifrar y descifrar. Quien tenga la clave puede hacer ambas cosas.

```
Texto plano + Clave → [AES] → Texto cifrado
Texto cifrado + Clave → [AES] → Texto plano
```

---

## AES — Advanced Encryption Standard

AES es el estándar de cifrado simétrico adoptado por NIST en 2001. Es el más usado en el mundo.

### Características

| Parámetro | Valores posibles |
|-----------|-----------------|
| Tamaño de clave | 128, 192 o 256 bits |
| Tamaño de bloque | 128 bits (fijo) |
| Velocidad | Muy alta (hardware acceleration en CPUs modernas) |
| Estado | ✅ Seguro — sin ataques prácticos conocidos |

### AES-128 vs AES-256

- **AES-128:** 128 bits de clave → 2^128 combinaciones posibles
- **AES-256:** 256 bits de clave → 2^256 combinaciones posibles
- Ambos son seguros para uso actual. AES-256 es preferido para datos sensibles.
- El ransomware usa AES-256 por velocidad y seguridad.

---

## Modos de operación

AES cifra bloques de 128 bits. Los modos determinan cómo se encadenan bloques.

### ECB — Electronic Codebook (❌ No usar)

```
Bloque 1 → AES(clave) → Bloque cifrado 1
Bloque 2 → AES(clave) → Bloque cifrado 2
```

**Problema:** Bloques iguales producen texto cifrado igual. Las imágenes cifradas con ECB muestran patrones (el famoso "ECB penguin").

### CBC — Cipher Block Chaining (✅ Común)

```
Bloque 1 XOR IV → AES(clave) → Bloque cifrado 1
Bloque 2 XOR Bloque cifrado 1 → AES(clave) → Bloque cifrado 2
```

Requiere un **IV (Initialization Vector)** aleatorio. El IV no es secreto pero sí debe ser único.

### CTR — Counter Mode (✅ Moderno)

Convierte AES en un stream cipher. Usa un contador incremental. Permite cifrado paralelo.

### GCM — Galois/Counter Mode (✅ Recomendado hoy)

CTR + autenticación. Provee **AEAD** (Authenticated Encryption with Associated Data). Detecta manipulación del texto cifrado. Usado en TLS 1.3.

---

## AES en Ransomware — Cómo funciona

El ransomware combina AES (velocidad) con RSA (distribución de clave). AES sola no alcanza porque requiere que la víctima tenga la clave para descifrar.

```
FLUJO TÍPICO DE RANSOMWARE:

[Atacante antes del ataque]
1. Genera par de claves RSA: pública (embebida en malware) + privada (guarda en C2)

[En la máquina víctima]
2. Malware genera clave AES-256 aleatoria única para esta víctima
3. Cifra todos los archivos con AES-256
   archivo.docx → archivo.docx.encrypted (en segundos)
4. Cifra la clave AES con la RSA pública del atacante
   clave_AES_256 → clave_cifrada_RSA (enviada al C2 o dejada en ransomnote)
5. Borra la clave AES de memoria

[Resultado]
Sin clave RSA privada → imposible recuperar clave AES → imposible descifrar archivos
```

### ¿Por qué AES y no RSA para cifrar archivos?

- RSA es **muy lento** para datos grandes (diseñado para cifrar datos pequeños)
- AES cifra 1 GB en milisegundos — necesario para cifrar miles de archivos rápido
- La combinación AES (velocidad) + RSA (distribución segura de clave) es óptima

---

## Indicadores de ransomware en actividad

```
# Comportamiento observable:
- CPU al 100% de forma sostenida (cifrado masivo)
- I/O de disco muy alto sin proceso conocido
- Extensiones de archivo cambiadas (.encrypted, .locked, .crypt)
- Archivos README o RANSOMNOTE.txt creados en cada carpeta
- Múltiples accesos a archivos en tiempo corto (un proceso tocando miles)
- Tráfico de red al C2 para entregar clave AES cifrada

# En el SIEM/EDR:
process → acceso masivo a archivos (>100 en <1 min)
process → modificación de extensiones
process → creación de archivos de texto en múltiples dirs
```

---

## ChaCha20 — Alternativa moderna a AES

Usado por malware en plataformas sin aceleración hardware para AES (IoT, algunos móviles).

- Stream cipher, muy rápido en software
- Usado en TLS 1.3 como alternativa a AES-GCM
- El ransomware moderno (ej. REvil) lo incorpora

---

## Relevancia SOC 🔍

| Situación | Análisis |
|-----------|----------|
| Proceso con I/O masivo y extensiones .encrypted | Ransomware activo — aislar inmediatamente |
| Binario con strings "AES", "CryptEncrypt" importando advapi32.dll | Capacidades de cifrado — alta sospecha |
| Clave AES hardcodeada en malware | Posible descifrado de datos — extraer clave para recovery |
| Archivo `.crypt` sin nota de rescate | Puede ser wiper disfrazado — verificar si hay clave válida |

---

## Próximo tema
→ [04_cifrado_asimetrico.md](./04_cifrado_asimetrico.md) — RSA y par de claves
