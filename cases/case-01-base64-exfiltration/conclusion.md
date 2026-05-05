## Resumen del Caso

El evento registrado muestra una solicitud HTTP GET con un parámetro `payload` codificado en Base64 hacia un dominio externo no categorizado, originado desde una herramienta de línea de comandos (curl). Aunque Base64 no constituye cifrado, su uso en este contexto representa una técnica de ofuscación orientada a evadir controles de inspección básica de tráfico.

## Hallazgos Clave

- El contenido decodificado (`SecretPayload`) sugiere datos con intención de ocultamiento deliberado.
- La combinación de herramienta (curl) + destino sospechoso + codificación establece un patrón de comportamiento anómalo.
- No existe evidencia de cifrado real, pero la técnica es funcional para evadir DLP de primera capa.

## Veredicto Final

**Estado**: Sospechoso — Requiere escalado y correlación  
**Clasificación MITRE**: T1027 (Obfuscation) + T1071.001 (C2 Web Protocols)  
**Acción recomendada**: Bloquear dominio destino, aislar host si se confirma reincidencia, e implementar regla SIEM para detección de patrones similares.

## Lección para el Analista SOC

> Base64 no es seguridad, es ofuscación. Un analista debe siempre decodificar el contenido visible antes de descartar un evento como benigno. La técnica es simple, pero efectiva contra controles que no inspeccionan capas de aplicación.
