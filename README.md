🌐 English version: [README.en.md](README.en.md)

# Criptografía para Analistas SOC

## Descripción General

Este repositorio presenta una introducción práctica a la criptografía aplicada en contextos reales de análisis de seguridad. El material combina fundamentos conceptuales, implementaciones funcionales en Python y casos de análisis basados en situaciones que un analista SOC puede encontrar en su trabajo diario.

El enfoque es aplicado: cada tema está conectado a un escenario concreto, una técnica de detección o una decisión de respuesta real.

---

## Qué se busca desarrollar

- Identificar datos codificados y cifrados en escenarios reales de tráfico de red
- Comprender cómo se utilizan y se abusan los algoritmos de hashing en autenticación
- Reconocer prácticas criptográficas débiles o mal implementadas y su impacto en seguridad
- Analizar anomalías en sesiones TLS mediante fingerprinting JA3
- Interpretar el comportamiento de ransomware desde una perspectiva técnica y forense
- Relacionar técnicas ofensivas con el framework MITRE ATT&CK
- Desarrollar criterio analítico para clasificar y priorizar amenazas

---

## Estructura del Proyecto

```
/teoria           → Conceptos de criptografía explicados desde la perspectiva del analista SOC
/implementaciones → Scripts Python ejecutables que ilustran codificación, hashing, AES y RSA
/ejercicios       → Actividades prácticas organizadas en tres niveles de dificultad creciente
/tools            → Herramienta interactiva con consola de análisis, CTF lab y hoja de referencia
/cases            → Casos de análisis SOC con logs reales, mapeo MITRE ATT&CK y veredicto de analista
/lab              → Ejercicios adicionales con estructura guiada
```

---

## Escenarios de Análisis

Cada caso incluye un log de evento, un análisis técnico completo y una conclusión con veredicto de analista. El objetivo es practicar el proceso de investigación, no llegar a una respuesta predefinida.

### Case 01 — Base64 Exfiltration
Solicitud HTTP con parámetro codificado en Base64 hacia dominio sospechoso vía curl. Se trabaja la identificación de indicadores de exfiltración y el análisis de técnicas de evasión básica.

### Case 02 — Weak Hash Detection
Intento de autenticación con hash MD5 de contraseña trivial (`password`) desde IP interna. Se analiza el riesgo de algoritmos débiles en sistemas de autenticación y las alternativas recomendadas.

### Case 03 — TLS Anomaly
Sesión TLS con certificado autofirmado y JA3 fingerprint anómalo hacia infraestructura anónima. Se trabaja la detección de posibles canales C2 cifrados mediante análisis de metadatos TLS.

### Case 04 — Ransomware Activity
Evento de ransomware activo con cifrado masivo de archivos, eliminación de shadow copies, deshabilitación de AV y conexión saliente. Se analiza la cadena de comportamiento y las decisiones de contención y respuesta.

---

## Herramientas y Técnicas

| Área                     | Herramientas / Conceptos                          |
|--------------------------|---------------------------------------------------|
| Codificación             | Base64, Hex, URL encoding, CyberChef              |
| Hashing                  | MD5, SHA-1, SHA-256, HMAC, rainbow tables         |
| Cifrado simétrico        | AES-CBC, AES-GCM, IV reuse vulnerability          |
| Cifrado asimétrico       | RSA-2048, PKCS1_OAEP, firmas digitales PSS        |
| Inspección TLS           | JA3/JA3S fingerprinting, Wireshark, análisis SNI  |
| Auditoría de contraseñas | John the Ripper (contexto forense)                |
| Threat Intelligence      | MITRE ATT&CK, IOC classification, TIP integration |

---

## Cómo Usar

1. Abrir `index.html` en el navegador para acceder al panel principal.
2. Navegar a `/tools/crypto-demo.html` para la demo interactiva con consola y CTF lab.
3. Revisar los casos en `/cases/` — cada uno incluye logs, análisis completo y conclusión con veredicto de analista.
4. Ejecutar los scripts en `/implementaciones/` con Python 3 + pycryptodome.

```bash
pip install pycryptodome
python implementaciones/03_aes.py
```

---

## Perfiles Orientados

El material está pensado para quienes trabajan o se forman en roles como análisis SOC, inteligencia de amenazas y forense digital. También es útil para cualquier profesional de seguridad que quiera profundizar en la dimensión criptográfica del trabajo defensivo.

---

## Notas

- Proyecto educativo con enfoque en aplicabilidad real en entornos SOC.
- Todos los casos están basados en patrones de amenazas reales documentados en MITRE ATT&CK.
- Los scripts Python son funcionales y ejecutables en entorno local.

---

**Autor**: [@xavimape](https://github.com/xavimape)
