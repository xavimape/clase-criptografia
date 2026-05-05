## Resumen del Caso

A las 03:42 UTC se detectó actividad ransomware activa en `WORKSTATION-14`. El proceso malicioso `unknown.exe`, ejecutado desde `AppData\Roaming`, cifró 1,847 archivos en menos de 60 segundos, renombró extensiones a `.locked`, eliminó las shadow copies del sistema, deshabilitó Windows Defender y distribuyó una nota de rescate en 23 directorios. La conexión saliente detectada hacia `91.108.4.200:8080` sugiere un modelo de doble extorsión con exfiltración previa al cifrado.

## Hallazgos Clave

- **Cifrado masivo confirmado**: velocidad e indiscriminación de afectación descartan cualquier proceso legítimo.
- **Eliminación de VSS**: acción premeditada para bloquear recuperación nativa de Windows — el atacante conoce el entorno.
- **Shares de red afectados**: `Finance` y `HR` comprometidos — impacto operacional y regulatorio potencialmente severo.
- **Deshabilitación de AV**: indica elevación de privilegios o presencia prolongada en el sistema antes del evento.
- **Doble extorsión posible**: conexión saliente activa durante el cifrado es firma de ransomware moderno (LockBit, BlackCat/ALPHV, Cl0p).

## Veredicto Final

**Estado**: Incidente activo — Crítico  
**Clasificación MITRE**: T1486 + T1490 + T1562.001 + T1041  
**Acción recomendada**: Aislamiento inmediato del host, activación del plan de IR, preservación forense, evaluación de alcance lateral y análisis de obligaciones regulatorias de notificación.

## Lección para el Analista SOC

> El ransomware moderno no es un evento puntual — es el acto final de una cadena de compromiso que lleva días o semanas. Para cuando los archivos empiezan a cifrarse, el atacante ya exploró la red, escaló privilegios y exfiltró datos. El trabajo del analista SOC es detectar las fases anteriores (acceso inicial, persistencia, movimiento lateral) antes de llegar a este punto. Si llegamos al cifrado, fallamos en etapas previas — y el análisis post-incidente debe encontrar cuándo y dónde.
