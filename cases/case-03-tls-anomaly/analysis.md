## Detection
Se detecta sesión TLS activa desde host interno (`10.0.0.87`) hacia IP externa (`185.220.101.42`) en el dominio `unknown-domain.xyz`. El certificado presentado es autofirmado, sin CA reconocida, y el fingerprint JA3 no coincide con patrones de navegadores o clientes legítimos conocidos.

## Technical Analysis
Características anómalas identificadas:

- **Certificado autofirmado**: sin cadena de confianza válida. Ningún servicio legítimo corporativo opera bajo estas condiciones.
- **Ausencia de CA reconocida**: descarta uso de servicios cloud o SaaS legítimos.
- **JA3 Fingerprint inusual**: `769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24,0` — patrón no asociado a navegadores estándar. Consistente con clientes TLS personalizados usados en frameworks C2 (Cobalt Strike, Metasploit, Sliver).
- **JA3S Fingerprint**: respuesta del servidor (`769,47,0`) indica configuración mínima, típica de servidores de C2 ligeros.
- **Duración de sesión**: 4 minutos 22 segundos con 142 KB transferidos — consistente con beaconing periódico.
- **IP destino**: `185.220.101.42` asociada históricamente a nodos Tor exit y hosting anónimo.

## Threat Classification
| Atributo         | Valor                                          |
|------------------|------------------------------------------------|
| Tipo             | Command and Control (C2) / Encrypted Channel   |
| Severidad        | Alta                                           |
| Confianza        | Alta (múltiples indicadores convergentes)      |
| Vector           | TLS outbound / certificado autofirmado / JA3   |
| Impacto potencial| Control remoto del endpoint, exfiltración      |

## MITRE ATT&CK
| Táctica              | Técnica                              | ID        |
|----------------------|--------------------------------------|-----------|
| Command and Control  | Application Layer Protocol: Web      | T1071.001 |
| Command and Control  | Encrypted Channel: Asymmetric Crypto | T1573.002 |
| Command and Control  | Non-Standard Port                    | T1571     |
| Defense Evasion      | Masquerading                         | T1036     |
| Exfiltration         | Exfiltration Over C2 Channel         | T1041     |

El canal TLS cifrado (T1573.002) es la técnica predilecta de frameworks C2 modernos para evadir inspección de tráfico. El uso de certificados autofirmados con JA3 fingerprints personalizados dificulta la detección por reglas de firma estáticas.

## Analyst Verdict
**Sospechoso alto — Escalar a Tier 2 / Threat Hunting inmediato.**

La convergencia de indicadores (certificado autofirmado + JA3 anómalo + IP asociada a infraestructura anónima + duración de sesión consistente con beaconing) configura un patrón de alta probabilidad de C2 activo. El host `10.0.0.87` debe considerarse comprometido hasta que se descarte con evidencia forense.

No se puede confirmar el payload sin inspección de memoria del proceso, pero el patrón de tráfico es suficiente para justificar contención.

## Recommended Actions
1. **Inmediato**: Aislar host `10.0.0.87` de la red — revocar acceso a recursos internos y bloquear egress hacia `185.220.101.42`.
2. **Inmediato**: Bloquear dominio `unknown-domain.xyz` y IP destino en firewall perimetral y proxy.
3. **Forense**: Capturar imagen de memoria RAM del endpoint antes de apagarlo — el implante C2 puede residir solo en memoria.
4. **Investigación**: Identificar el proceso responsable de la conexión TLS mediante EDR (revisar árbol de procesos, parent process, hash del ejecutable).
5. **Threat Hunting**: Buscar el mismo JA3 fingerprint en todos los hosts de la red durante los últimos 30 días.
6. **SIEM**: Crear regla de detección para sesiones TLS con certificados autofirmados + JA3 no whitelisted hacia destinos externos.
7. **Threat Intel**: Compartir IOCs (`185.220.101.42`, `unknown-domain.xyz`, JA3 hash) con plataforma TIP (MISP / OpenCTI).
