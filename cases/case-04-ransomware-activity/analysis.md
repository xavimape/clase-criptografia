## Detection
El sistema EDR genera alerta crítica sobre `WORKSTATION-14` por actividad masiva de modificación de archivos fuera de horario laboral (03:42 UTC). Un proceso no reconocido (`unknown.exe`) ejecutado desde `AppData\Roaming` está cifrando archivos en unidades locales y recursos compartidos de red, renombrando extensiones a `.locked` y eliminando las shadow copies del sistema.

## Behavioral Analysis
Indicadores de compromiso identificados:

- **Alta tasa de escritura**: 1,847 modificaciones de archivos en 60 segundos — imposible en uso legítimo.
- **Renombrado de extensiones**: `.locked` aplicado a documentos en unidades locales y shares de red (`Finance`, `HR`).
- **Proceso desde AppData**: `unknown.exe` ejecutado desde `C:\Users\jsmith\AppData\Roaming\` — ubicación típica de persistencia de malware (evita necesidad de privilegios elevados en escritura).
- **Parent process**: `explorer.exe` como padre sugiere ejecución manual, phishing con doble click, o inyección en proceso de shell.
- **Eliminación de shadow copies**: acción deliberada para impedir recuperación sin backup externo (confirma ransomware, no malware genérico).
- **Deshabilitación de Windows Defender**: modificación de clave de registro — indica presencia previa en el sistema o ejecución con privilegios de administrador.
- **Ransom note**: `README_DECRYPT.txt` distribuido en 23 directorios — patrón estándar de ransomware moderno.
- **Conexión saliente**: `91.108.4.200:8080` — posible exfiltración de datos previa al cifrado (ransomware de doble extorsión) o beacon de C2.

## Threat Classification
| Atributo         | Valor                                            |
|------------------|--------------------------------------------------|
| Tipo             | Ransomware / Double Extortion                    |
| Severidad        | Crítica                                          |
| Confianza        | Muy alta (comportamiento ransomware confirmado)  |
| Vector           | Probable phishing / ejecución manual             |
| Impacto potencial| Pérdida de datos, interrupción operacional, daño reputacional, multas regulatorias |

## MITRE ATT&CK
| Táctica              | Técnica                                    | ID        |
|----------------------|--------------------------------------------|-----------|
| Impact               | Data Encrypted for Impact                  | T1486     |
| Impact               | Inhibit System Recovery                    | T1490     |
| Defense Evasion      | Impair Defenses: Disable AV                | T1562.001 |
| Exfiltration         | Exfiltration Over C2 Channel               | T1041     |
| Persistence          | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Execution            | User Execution: Malicious File             | T1204.002 |
| Discovery            | File and Directory Discovery               | T1083     |
| Lateral Movement     | SMB/Windows Admin Shares                   | T1021.002 |

La secuencia táctica sigue el patrón clásico de ransomware moderno: acceso inicial → escalada → deshabilitación de defensas → exfiltración → cifrado → extorsión.

## Analyst Verdict
**Malicioso confirmado — Incidente activo en curso. Activar Plan de Respuesta a Incidentes.**

El host `WORKSTATION-14` está comprometido y el ransomware se encuentra en fase activa de cifrado. La afectación de shares de red (`Finance`, `HR`) indica propagación lateral ya en progreso. La conexión saliente a `91.108.4.200:8080` sugiere posible exfiltración previa de datos (modelo de doble extorsión).

**Tiempo crítico**: cada segundo sin contención incrementa el volumen de datos cifrados y el radio de afectación en la red.

## Recommended Actions
### Contención Inmediata (0-5 minutos)
1. **Aislar** `WORKSTATION-14` de la red (desconectar cable / bloquear puerto de switch) — NO apagar el equipo para preservar evidencia en memoria.
2. **Deshabilitar** acceso a shares afectados (`Finance`, `HR`) para todos los usuarios hasta evaluación.
3. **Bloquear** IP `91.108.4.200` en firewall perimetral y buscar otras conexiones activas hacia ese destino.

### Respuesta a Incidente (5-60 minutos)
4. **Activar** el equipo de IR y notificar a management según el plan de comunicación de incidentes.
5. **Capturar** imagen forense de memoria RAM antes de cualquier reinicio — el binario puede no estar en disco.
6. **Preservar** logs: EDR, SIEM, Active Directory, proxy, firewall — no modificar nada en el host afectado.
7. **Identificar** vector de acceso inicial revisando logs de email (phishing) y navegación web del usuario `jsmith` en las 48 horas previas.
8. **Evaluar** alcance: identificar todos los hosts que accedieron a `C:\Shares\Finance` y `C:\Shares\HR` recientemente.

### Recuperación y Post-Incident
9. **Restaurar** desde backup externo verificado — nunca desde shadow copies (ya eliminadas).
10. **Analizar** `unknown.exe` en sandbox aislado para identificar familia de ransomware, clave de cifrado usada y posibles IOCs adicionales.
11. **Notificación legal/regulatoria**: si se confirma exfiltración de datos de `HR` o `Finance`, evaluar obligaciones de notificación bajo GDPR/regulación local.
12. **Hardening post-incidente**: implementar regla de bloqueo de ejecución desde `AppData`, restringir acceso a VSS, monitoreo de tasa de escritura como alerta temprana.
