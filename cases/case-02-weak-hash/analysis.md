## Detection
Se detecta el uso de un hash MD5 en un proceso de autenticación.

## Technical Analysis
El hash corresponde a:

    password

MD5 es un algoritmo obsoleto y vulnerable a:
- ataques de diccionario
- rainbow tables

## Tool Validation
Herramientas como John the Ripper permiten recuperar contraseñas rápidamente si son débiles.

## Risk Assessment
Uso de MD5 en autenticación representa una debilidad crítica.

## SOC Impact
Posible:
- compromiso de credenciales
- acceso no autorizado

## Threat Classification
| Atributo         | Valor                                         |
|------------------|-----------------------------------------------|
| Tipo             | Credential Access / Weak Authentication       |
| Severidad        | Crítica                                       |
| Confianza        | Alta (hash identificado y crackeado)          |
| Vector           | Login attempt con hash MD5 de contraseña débil|
| Impacto potencial| Compromiso total de cuenta administrativa     |

## MITRE ATT&CK
| Táctica            | Técnica                              | ID        |
|--------------------|--------------------------------------|-----------|
| Credential Access  | Brute Force: Password Cracking       | T1110.002 |
| Credential Access  | OS Credential Dumping                | T1003     |
| Defense Evasion    | Use of Weak Cryptography             | T1600     |
| Initial Access     | Valid Accounts                       | T1078     |

MD5 sin salting permite el uso de rainbow tables precomputadas (T1110.002). El hash `5f4dcc3b5aa765d61d8327deb882cf99` corresponde a `password`, lo que implica política de contraseñas nula.

## Analyst Verdict
**Crítico — Acción inmediata requerida.**

La cuenta `admin` utiliza una contraseña trivial (`password`) almacenada como MD5 sin salt. El hash es universalmente conocido y figura en todas las rainbow tables públicas. Cualquier atacante con acceso al hash puede autenticarse sin necesidad de fuerza bruta activa.

La IP origen `192.168.1.45` es interna, lo que eleva la probabilidad de:
- insider threat o sesión comprometida en la red interna
- movimiento lateral post-compromiso inicial

## Recommended Actions
1. **Inmediato**: Deshabilitar o cambiar la contraseña de la cuenta `admin`. Forzar re-autenticación en todas las sesiones activas.
2. **Inmediato**: Investigar el host `192.168.1.45` — identificar propietario, revisar logs de acceso y procesos activos.
3. **Corto plazo**: Auditar todas las contraseñas almacenadas como MD5. Migrar a **bcrypt** (cost ≥ 12) o **Argon2id**.
4. **Hardening**: Implementar política de contraseñas mínimas (12+ caracteres, complejidad) y MFA para cuentas privilegiadas.
5. **SIEM**: Alertar sobre cualquier hash MD5 detectado en tráfico de autenticación como indicador de configuración insegura.
6. **Proceso**: Revisar si otros usuarios tienen hashes MD5 en la base de datos de autenticación.
