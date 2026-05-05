"""
02 — Hashing: MD5, SHA-1, SHA-256, HMAC
=========================================
Demuestra funciones hash y sus propiedades clave.
Correlacionado con: Slide 04 de crypto-soc-training.html
                    teoria/02_hashing.md

Ejecutar: python 02_hashing.py
Requisitos: ninguno (solo stdlib)
"""

import hashlib
import hmac
import os
import time


# ─────────────────────────────────────────────
# FUNCIONES HASH BÁSICAS
# ─────────────────────────────────────────────

def calcular_hashes(texto: str) -> dict:
    """Calcula todos los hashes comunes de un texto."""
    data = texto.encode()
    return {
        "MD5":    hashlib.md5(data).hexdigest(),
        "SHA-1":  hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }


def demo_hashes_basicos():
    print("=" * 60)
    print("FUNCIONES HASH")
    print("=" * 60)

    texto = "Hola SOC"
    hashes = calcular_hashes(texto)

    print(f"\nInput: {texto!r}\n")
    for algo, digest in hashes.items():
        print(f"{algo:<10} ({len(digest)//2*8} bits / {len(digest)} chars hex)")
        print(f"  {digest}")

    print("\nLongitudes de hash (para identificación rápida):")
    print("  MD5    = 32 chars hex  → d41d8cd98f00b204e9800998ecf8427e")
    print("  SHA-1  = 40 chars hex  → da39a3ee5e6b4b0d3255bfef95601890afd80709")
    print("  SHA-256= 64 chars hex  → e3b0c44298fc1c149afbf4c8996fb924...")
    print("  SHA-512= 128 chars hex → cf83e1357eefb8bdf1542850d66d8007...")


# ─────────────────────────────────────────────
# EFECTO AVALANCHA
# ─────────────────────────────────────────────

def demo_efecto_avalancha():
    print("\n" + "=" * 60)
    print("EFECTO AVALANCHA")
    print("=" * 60)
    print("Un solo bit diferente → hash completamente distinto\n")

    pares = [
        ("Hello", "hello"),
        ("SOC Analyst", "SOC analyst"),
        ("password123", "password124"),
        ("a", "b"),
    ]

    for a, b in pares:
        hash_a = hashlib.sha256(a.encode()).hexdigest()
        hash_b = hashlib.sha256(b.encode()).hexdigest()
        # Contar bits diferentes
        bits_diff = bin(int(hash_a, 16) ^ int(hash_b, 16)).count('1')
        print(f"Input A: {a!r}")
        print(f"Input B: {b!r}")
        print(f"SHA-256 A: {hash_a[:32]}...")
        print(f"SHA-256 B: {hash_b[:32]}...")
        print(f"Bits diferentes: {bits_diff}/256 ({bits_diff/256*100:.1f}%)")
        print()


# ─────────────────────────────────────────────
# INTEGRIDAD DE ARCHIVOS (USO FORENSE)
# ─────────────────────────────────────────────

def hash_archivo(ruta: str, algoritmo: str = "sha256") -> str:
    """Calcula el hash SHA-256 de un archivo (en bloques para archivos grandes)."""
    h = hashlib.new(algoritmo)
    try:
        with open(ruta, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return "ARCHIVO_NO_ENCONTRADO"


def demo_integridad_forense():
    print("=" * 60)
    print("INTEGRIDAD FORENSE")
    print("=" * 60)

    # Simular hash de "evidencia"
    contenido_original = b"Imagen de disco forense - contenido original"
    h_original = hashlib.sha256(contenido_original).hexdigest()
    print(f"\nHash de evidencia original:")
    print(f"  SHA-256: {h_original}")

    # Simular modificación (1 byte cambiado)
    contenido_modificado = bytearray(contenido_original)
    contenido_modificado[0] ^= 0x01  # flip de 1 bit
    h_modificado = hashlib.sha256(bytes(contenido_modificado)).hexdigest()
    print(f"\nHash de evidencia (modificada — 1 bit cambiado):")
    print(f"  SHA-256: {h_modificado}")

    # Verificación
    intacta = h_original == h_modificado
    print(f"\nVerificación de integridad: {'✅ ÍNTEGRA' if intacta else '❌ MODIFICADA — NO USAR COMO EVIDENCIA'}")

    print("\n--- Comandos forenses equivalentes ---")
    print("  PowerShell: Get-FileHash archivo.exe -Algorithm SHA256")
    print("  Linux:      sha256sum archivo.img")
    print("  Python:     hashlib.sha256(open('archivo','rb').read()).hexdigest()")


# ─────────────────────────────────────────────
# HMAC
# ─────────────────────────────────────────────

def demo_hmac():
    print("\n" + "=" * 60)
    print("HMAC — Hash con autenticación")
    print("=" * 60)
    print("Combina hash + clave → verifica integridad Y autenticidad\n")

    clave = b"clave_secreta_soc_2024"
    mensaje_original = b"GET /api/v1/alerts?status=critical"
    mensaje_manipulado = b"GET /api/v1/alerts?status=resolved"

    mac_original = hmac.new(clave, mensaje_original, hashlib.sha256).hexdigest()
    mac_manipulado = hmac.new(clave, mensaje_manipulado, hashlib.sha256).hexdigest()

    print(f"Mensaje 1: {mensaje_original.decode()}")
    print(f"HMAC-256:  {mac_original}")

    print(f"\nMensaje 2 (manipulado): {mensaje_manipulado.decode()}")
    print(f"HMAC-256:  {mac_manipulado}")

    print(f"\nVerificación segura (hmac.compare_digest):")
    es_valido = hmac.compare_digest(mac_original, mac_original)
    es_invalido = hmac.compare_digest(mac_original, mac_manipulado)
    print(f"  Mensaje original vs su HMAC:   {'✅ VÁLIDO' if es_valido else '❌ INVÁLIDO'}")
    print(f"  Mensaje manipulado vs HMAC orig: {'✅ VÁLIDO' if es_invalido else '❌ INVÁLIDO — manipulación detectada'}")

    print("\nUsos comunes de HMAC:")
    print("  - Verificación de webhooks (GitHub, Stripe, etc.)")
    print("  - JWT (JSON Web Tokens)")
    print("  - APIs REST — firma de requests")


# ─────────────────────────────────────────────
# VELOCIDAD (por qué MD5 es peligroso para contraseñas)
# ─────────────────────────────────────────────

def demo_velocidad():
    print("\n" + "=" * 60)
    print("VELOCIDAD: Por qué MD5 es peligroso para contraseñas")
    print("=" * 60)

    iteraciones = 100_000
    datos = b"password123"

    algoritmos = {
        "MD5":    hashlib.md5,
        "SHA-1":  hashlib.sha1,
        "SHA-256": hashlib.sha256,
    }

    print(f"\nCalculando {iteraciones:,} hashes de {datos!r}:\n")
    for nombre, func in algoritmos.items():
        inicio = time.perf_counter()
        for _ in range(iteraciones):
            func(datos).hexdigest()
        elapsed = time.perf_counter() - inicio
        hashes_por_seg = iteraciones / elapsed
        print(f"  {nombre:<10}: {elapsed:.3f}s → {hashes_por_seg:,.0f} hashes/seg en CPU")

    print("\n⚠️  GPU moderna: MD5 → >10,000,000,000 hashes/seg")
    print("⚠️  Por eso MD5/SHA-1 NO se usan para almacenar contraseñas")
    print("✅  Usar: bcrypt, scrypt, Argon2 (diseñados para ser LENTOS)")

    # Demostrar sal (salt)
    print("\n--- SAL (Salt) para prevenir rainbow tables ---")
    password = "password123"
    sal1 = os.urandom(16).hex()
    sal2 = os.urandom(16).hex()

    hash_sin_sal = hashlib.sha256(password.encode()).hexdigest()
    hash_con_sal1 = hashlib.sha256((sal1 + password).encode()).hexdigest()
    hash_con_sal2 = hashlib.sha256((sal2 + password).encode()).hexdigest()

    print(f"  Password:         {password}")
    print(f"  Sin sal:          {hash_sin_sal[:32]}...")
    print(f"  Con sal1 ({sal1[:8]}...): {hash_con_sal1[:32]}...")
    print(f"  Con sal2 ({sal2[:8]}...): {hash_con_sal2[:32]}...")
    print("  → Mismo password, sals diferentes → hashes completamente distintos")
    print("  → Las rainbow tables precomputadas quedan inútiles")


# ─────────────────────────────────────────────
# BÚSQUEDA DE HASH EN IOCs
# ─────────────────────────────────────────────

def demo_busqueda_iocs():
    print("\n" + "=" * 60)
    print("BÚSQUEDA DE HASH EN IOCs (simulación)")
    print("=" * 60)

    # Simulamos una pequeña base de datos de hashes maliciosos
    iocs_malware = {
        "d41d8cd98f00b204e9800998ecf8427e": "Emotet loader v4.2",
        "44d88612fea8a8f36de82e1278abb02f": "WannaCry sample",
        "3395856ce81f2b7382dee72602f798b642f14d4": "Mirai botnet",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Clean file",
    }

    archivos_a_analizar = [
        ("documento.docx", "d41d8cd98f00b204e9800998ecf8427e"),
        ("update.exe", "aabbccddeeff00112233445566778899"),
        ("system32.dll", "44d88612fea8a8f36de82e1278abb02f"),
        ("readme.txt", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ]

    print("\nAnalizando archivos contra base de IOCs:\n")
    for archivo, hash_md5 in archivos_a_analizar:
        if hash_md5 in iocs_malware:
            print(f"  🔴 MATCH: {archivo}")
            print(f"     Hash: {hash_md5}")
            print(f"     IOC:  {iocs_malware[hash_md5]}")
        else:
            print(f"  ✅ OK:    {archivo} ({hash_md5[:16]}...)")

    print("\n  → En producción: integrar con VirusTotal API, MISP, OpenCTI")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_hashes_basicos()
    demo_efecto_avalancha()
    demo_integridad_forense()
    demo_hmac()
    demo_velocidad()
    demo_busqueda_iocs()
