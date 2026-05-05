# 04 — Cifrado Asimétrico: RSA y Par de Claves

> **Slide relacionado:** 06 de `crypto-soc-training.html`

---

## ¿Qué es el cifrado asimétrico?

A diferencia del simétrico, usa **dos claves matemáticamente relacionadas**:
- Lo que una cifra, **solo la otra puede descifrar**
- Conocer la clave pública no permite calcular la privada

```
Clave Pública  → Cifrar / Verificar firmas
Clave Privada  → Descifrar / Firmar
```

---

## RSA — Rivest–Shamir–Adleman

El algoritmo asimétrico más usado históricamente. Basado en la dificultad de factorizar números primos grandes.

### ¿Por qué es difícil romperlo?

```
p = 61          (primo)
q = 53          (primo)
n = p × q = 3233   (fácil de calcular)

Pero dado n = 3233, encontrar p y q es "difícil"
Para claves RSA-2048: n tiene 617 dígitos decimales
Factorizar ese número con la computación actual: imposible en tiempo razonable
```

### Tamaños de clave RSA

| Bits | Estado | Uso |
|------|--------|-----|
| 512 | ❌ Roto | No usar |
| 1024 | ❌ Vulnerable | No usar |
| 2048 | ✅ Seguro | Mínimo recomendado hoy |
| 4096 | ✅ Muy seguro | Alta seguridad |

El ransomware moderno usa RSA-2048 o RSA-4096.

---

## Flujo de cifrado asimétrico

### Caso 1: Comunicación segura
```
[Alice quiere enviar mensaje secreto a Bob]

1. Bob publica su clave pública (cualquiera puede verla)
2. Alice cifra el mensaje con la clave pública de Bob
3. Solo Bob puede descifrar con su clave privada
```

### Caso 2: Firma digital
```
[Alice quiere probar que el mensaje es suyo]

1. Alice firma con su clave privada (solo ella puede hacerlo)
2. Cualquiera verifica con la clave pública de Alice
3. Si la firma es válida: el mensaje es auténtico y no fue alterado
```

---

## Curvas Elípticas (ECC) — El RSA moderno

ECC ofrece la misma seguridad que RSA con claves mucho más cortas:

| Seguridad equivalente | RSA | ECC |
|----------------------|-----|-----|
| 128 bits | 3072 bits | 256 bits |
| 192 bits | 7680 bits | 384 bits |
| 256 bits | 15360 bits | 521 bits |

**Ventajas de ECC:**
- Claves más pequeñas → más rápido → menos recursos
- Ideal para dispositivos con limitaciones (IoT, móviles, TLS)
- TLS 1.3 favorece curvas elípticas (P-256, X25519)

**Curvas comunes:**
- P-256 (NIST) — usada en TLS, iOS, Android
- Curve25519 — usada en SSH, WhatsApp, Signal
- secp256k1 — usada en Bitcoin

---

## Diffie-Hellman — Intercambio de claves

Permite que dos partes establezcan una clave compartida sobre un canal inseguro sin enviarse la clave nunca.

```
[Alice y Bob acuerdan parámetros públicos: p=23, g=5]

Alice elige secreto a=6:  A = g^a mod p = 5^6 mod 23 = 8   (envía a Bob)
Bob elige secreto b=15:   B = g^b mod p = 5^15 mod 23 = 19  (envía a Alice)

Alice calcula: s = B^a mod p = 19^6 mod 23 = 2
Bob calcula:   s = A^b mod p = 8^15 mod 23 = 2

Clave compartida = 2 (sin haberla enviado nunca)
```

Usado en TLS para establecer la clave de sesión AES.

---

## RSA en el contexto del ransomware

```
ANTES DEL ATAQUE (en el servidor del atacante):
────────────────────────────────────────────────
openssl genrsa -out privada.pem 2048
openssl rsa -in privada.pem -pubout -out publica.pem
↓
Clave pública → se embebe en el ejecutable del ransomware
Clave privada → se guarda en el C2 del atacante

DURANTE EL ATAQUE (en la máquina víctima):
────────────────────────────────────────────────
1. El ransomware genera clave AES-256 aleatoria
2. Cifra todos los archivos con AES-256 (rápido)
3. Cifra la clave AES con RSA pública embebida
4. Guarda el blob cifrado en ransomnote o lo envía al C2
5. Elimina la clave AES de memoria

RESULTADO:
────────────────────────────────────────────────
Sin clave RSA privada (en poder del atacante):
→ No se puede descifrar la clave AES
→ No se puede descifrar los archivos
→ Sin pago, sin archivos
```

---

## ¿Cuándo es posible recuperar sin pagar?

| Situación | Recuperación posible |
|-----------|---------------------|
| Clave AES no borrada de memoria (DUMP de RAM) | Sí — con herramientas forenses |
| RSA privada hardcodeada en malware (error del atacante) | Sí — análisis estático |
| Generador de números aleatorios débil (predecible) | A veces — con mucho esfuerzo |
| Backup offline limpio disponible | Sí — sin necesitar descifrar |
| Ninguna de las anteriores | No — sin clave RSA privada |

---

## Relevancia SOC 🔍

- **Ver en binario:** Strings `-----BEGIN PUBLIC KEY-----` → el malware tiene embebida clave RSA pública
- **En análisis de tráfico:** Handshake TLS con clave efímera (ECDHE) = Perfect Forward Secrecy
- **En certificados:** Revisar tamaño de clave — RSA-1024 en cert = legacy, RSA-2048+ = normal
- **Post-incidente ransomware:** Siempre intentar dump de RAM antes de apagar la máquina

---

## Próximo tema
→ [05_tls.md](./05_tls.md) — TLS y detección de C2 en tráfico de red
