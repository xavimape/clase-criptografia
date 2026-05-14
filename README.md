# Criptografía Aplicada para Analistas SOC, Threat Intelligence y DFIR

🌐 English version: [README.en.md](README.en.md)

## Descripción General

Este repositorio reúne contenido educativo orientado a criptografía aplicada, análisis de tráfico, telemetría y detección en entornos reales de ciberseguridad.

El objetivo es conectar fundamentos técnicos con escenarios operativos concretos, permitiendo comprender cómo conceptos criptográficos impactan directamente en tareas de:

- SOC (Security Operations Center)
- Threat Intelligence
- DFIR / Forensia Digital
- Detection Engineering
- Análisis de tráfico TLS
- Hunting y correlación de eventos

El enfoque es práctico y progresivo: cada tema busca relacionar teoría, contexto operativo y aplicación real mediante laboratorios, visualizaciones, casos de análisis y ejercicios guiados.

---

## Qué se busca desarrollar

- Identificar datos codificados, cifrados y hasheados en escenarios reales
- Comprender el uso legítimo y abusivo de mecanismos criptográficos
- Detectar anomalías en tráfico TLS mediante análisis de fingerprints JA3/JA3S
- Interpretar eventos asociados a ransomware y canales cifrados de C2
- Comprender cómo la criptografía aparece en telemetría SOC y workflows defensivos
- Analizar sesiones TLS utilizando Wireshark, Zeek y herramientas SIEM
- Construir criterio analítico para clasificación y priorización de amenazas

---

## Estructura del Proyecto

```text
/assets
/cases
/ejercicios
/implementaciones
/laboratorios
/recursos
/teoria
/tools
```

---

# Ruta de Aprendizaje

El contenido está organizado de forma progresiva para facilitar tanto el autoaprendizaje como su utilización en entornos académicos y operativos.

## Módulos incluidos

00. Fundamentos
01. Codificación y representación
02. Hashing e integridad
03. Criptografía simétrica
04. Criptografía asimétrica
05. TLS y comunicaciones seguras
06. Firmas digitales y autenticación
07. Ransomware y uso ofensivo de criptografía
08. Password Cracking y auditoría de credenciales
09. TLS Fingerprinting (JA3/JA3S)
10. Detection Engineering y telemetría

La progresión busca conectar teoría, análisis y aplicación práctica en escenarios reales de ciberseguridad.

---

## Laboratorios Interactivos

### John The Ripper Lab

- auditoría de contraseñas
- cracking controlado
- análisis de hashes
- wordlists
- comprensión de malas prácticas

### TLS / JA3 Fingerprinting Lab

Incluye:

- generación de fingerprints JA3
- JA3 vs JA3S
- análisis de Client Hello
- Wireshark
- tshark
- Zeek
- Snort / Suricata
- QRadar
- FortiGate / FortiAnalyzer
- detection engineering
- hunting workflows
- evasión y spoofing

---

## Casos de Análisis

- Exfiltración mediante Base64
- Detección de hashes débiles
- Anomalías TLS
- Actividad ransomware
- Correlación de telemetría
- Indicadores de compromiso

---

## Enfoque del Proyecto

| Área | Aplicación |
|------|------|
| Criptografía | Fundamentos y mecanismos |
| SOC | Detección y monitoreo |
| Threat Intelligence | Contexto y atribución |
| DFIR | Integridad y evidencia |
| Detection Engineering | Correlación y reglas |

---

## Características

- HTML, CSS y JavaScript puro
- Compatible con GitHub Pages
- Diseño responsive
- Tema “dark cyber”
- Laboratorios interactivos
- Material orientado a autoaprendizaje

---

# Arquitectura Técnica

| Componente | Tecnología |
|------|------|
| Frontend | HTML, CSS y JavaScript puro |
| Backend | Ninguno (100% client-side) |
| Dependencias | Sin frameworks externos |
| Hosting | GitHub Pages / servidores estáticos |
| Compatibilidad | Navegadores modernos |

El proyecto prioriza:

- simplicidad
- portabilidad
- mantenibilidad
- facilidad de despliegue
- claridad visual y pedagógica

---

# Uso y Despliegue

El proyecto es completamente estático y puede utilizarse:

- directamente desde GitHub Pages
- clonando el repositorio localmente
- desde cualquier servidor web estático

No requiere:

- backend
- base de datos
- instalación de dependencias

Compatible con:

- Chrome
- Firefox
- Edge
- navegadores modernos con soporte ES6

También puede utilizarse como:
- material de apoyo docente
- plataforma de autoaprendizaje
- laboratorio offline
- entorno demostrativo para capacitaciones técnicas

---

## Orientado a

- estudiantes de ciberseguridad
- analistas SOC
- equipos DFIR
- Threat Intelligence
- docentes
- autodidactas

---

## Uso Responsable

Este proyecto tiene fines exclusivamente educativos y defensivos.

Los laboratorios, ejemplos y casos incluidos están diseñados para:

- formación técnica
- análisis autorizado
- investigación académica
- entornos controlados
- prácticas de detección y análisis

No deben utilizarse sobre:

- infraestructura ajena
- sistemas sin autorización
- entornos productivos
- objetivos reales sin consentimiento explícito

Algunos ejemplos, fingerprints, indicadores y escenarios pueden estar:
- simulados
- simplificados
- adaptados pedagógicamente

El objetivo del proyecto es promover comprensión técnica, pensamiento analítico y uso responsable de herramientas relacionadas con criptografía y ciberseguridad.

---

## Estado del Proyecto

Proyecto en evolución continua con:
- teoría aplicada
- laboratorios interactivos
- análisis TLS
- JA3/JA3S
- telemetría
- detection engineering
- hunting workflows

---

## Filosofía

```text
Criptografía
    ↓
Protocolos
    ↓
Telemetría
    ↓
Detección
    ↓
Análisis
    ↓
Operaciones SOC / DFIR
```

---

## Contribuciones

Consultar:
- CONTRIBUTING.md
- SECURITY.md

---

## Licencia

MIT License

---

**Autor**: @xavimape
