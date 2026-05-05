## Resumen del Caso

Se detectó una sesión TLS activa y prolongada desde un host interno hacia una IP externa asociada a infraestructura anónima, utilizando un certificado autofirmado y un JA3 fingerprint no asociado a ningún cliente legítimo conocido. El patrón de tráfico — duración fija, volumen moderado, dominio no categorizado — es consistente con beaconing de C2.

## Hallazgos Clave

- JA3 fingerprint personalizado confirma uso de cliente TLS no estándar (probable implante o framework C2).
- Certificado autofirmado descarta origen legítimo; ningún servicio empresarial confiable opera sin CA válida.
- IP destino (`185.220.101.42`) con historial en listas de reputación negativa (Tor exit nodes, bullet-proof hosting).
- Duración y volumen de transferencia consistentes con patrón de heartbeat/beaconing cada N segundos.

## Veredicto Final

**Estado**: Malicioso — Alta confianza  
**Clasificación MITRE**: T1071.001 + T1573.002 + T1041  
**Acción recomendada**: Contención inmediata del host, captura forense de memoria, threat hunting en toda la red por JA3 fingerprint y dominio.

## Lección para el Analista SOC

> TLS cifra el contenido, pero no oculta el comportamiento. Un analista competente no necesita ver dentro del túnel para determinar si es malicioso: el fingerprint JA3, la validez del certificado, la reputación del destino y el patrón temporal son suficientes para tomar una decisión de contención. Aprender a leer metadatos de TLS es una habilidad diferenciadora en detección de C2 moderno.
