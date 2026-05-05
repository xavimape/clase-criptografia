## Detection
Se identifica un parámetro `payload` con contenido codificado en Base64 dentro de una request HTTP.

## Decoding
U2VjcmV0UGF5bG9hZA== → SecretPayload

## Behavioral Analysis
El uso de Base64 en parámetros HTTP no es anómalo por sí solo, pero combinado con:
- uso de curl
- dominio sospechoso
- endpoint genérico

indica posible intento de exfiltración de datos.

## Threat Context
Técnica común en:
- malware ligero
- scripts de exfiltración
- C2 encubierto

## SOC Assessment
Severidad: Media-Alta  
Requiere correlación con:
- volumen de tráfico
- frecuencia
- origen del host

## Threat Classification
| Atributo         | Valor                                      |
|------------------|--------------------------------------------|
| Tipo             | Data Exfiltration / C2 Communication       |
| Severidad        | Media-Alta                                 |
| Confianza        | Media (requiere correlación adicional)     |
| Vector           | HTTP outbound / parámetro GET codificado   |
| Impacto potencial| Filtración de datos sensibles              |

## MITRE ATT&CK
| Táctica             | Técnica                        | ID          |
|---------------------|--------------------------------|-------------|
| Exfiltration        | Exfiltration Over Web Service  | T1567       |
| Command and Control | Web Protocols                  | T1071.001   |
| Defense Evasion     | Obfuscated Files or Information| T1027       |

El uso de Base64 en parámetros HTTP es una técnica de ofuscación básica (T1027) empleada para evadir detección por DLP o IDS que no inspeccionan contenido codificado.

## Analyst Verdict
**Sospechoso — Escalado para investigación.**

Los indicadores combinados (curl, dominio no reconocido, endpoint genérico, payload codificado) constituyen un patrón consistente con exfiltración ligera o beacon de C2. No es posible confirmar compromiso sin correlacionar con:
- historial de conexiones del host fuente
- registros DNS para `suspicious-domain.com`
- posible proceso padre de la llamada curl

Se recomienda no descartar como falso positivo hasta completar correlación.

## Recommended Actions
1. **Inmediato**: Bloquear dominio `suspicious-domain.com` en proxy/firewall y alertar al equipo de threat intel.
2. **Corto plazo**: Aislar el host origen para análisis forense si se confirman conexiones recurrentes.
3. **Investigación**: Revisar logs de EDR/endpoint para identificar el proceso que generó la solicitud curl.
4. **SIEM**: Crear regla de detección para peticiones HTTP GET con parámetros en Base64 hacia dominios externos no categorizados.
5. **Hardening**: Revisar políticas de egress filtering para bloquear herramientas de transferencia (curl, wget) desde hosts de usuario final.
