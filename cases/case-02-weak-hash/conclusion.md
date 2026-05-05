## Resumen del Caso

Se detectó un intento de autenticación de la cuenta `admin` con un hash MD5 correspondiente a la contraseña `password`, originado desde una IP interna (`192.168.1.45`). MD5 es un algoritmo de hash de propósito general, inadecuado para el almacenamiento de contraseñas, ya que puede ser revertido en segundos mediante rainbow tables o herramientas como John the Ripper.

## Hallazgos Clave

- El hash `5f4dcc3b5aa765d61d8327deb882cf99` es MD5 de `password` — contraseña de máxima debilidad.
- No se detecta uso de salt, lo que hace el hash directamente buscable en bases de datos públicas (e.g., crackstation.net).
- El origen interno sugiere acceso desde la red corporativa, ampliando el vector de amenaza.
- La combinación cuenta privilegiada + contraseña trivial + algoritmo obsoleto representa riesgo crítico compuesto.

## Veredicto Final

**Estado**: Crítico — Acción inmediata requerida  
**Clasificación MITRE**: T1110.002 (Password Cracking) + T1078 (Valid Accounts)  
**Acción recomendada**: Cambio inmediato de credenciales, migración a bcrypt/Argon2id, auditoría completa de hashes en la base de datos de autenticación.

## Lección para el Analista SOC

> Un hash no es una contraseña segura por el hecho de estar hasheado. MD5 fue diseñado para velocidad, no para seguridad. Un analista debe saber distinguir entre algoritmos de integridad (MD5, SHA-256) y algoritmos de derivación de contraseñas (bcrypt, Argon2). Solo los segundos son apropiados para autenticación.
