"""
03 — AES: Cifrado Simétrico
============================
Demuestra AES-CBC y AES-GCM con ejemplos prácticos.
Correlacionado con: Slide 05 de crypto-soc-training.html
                    teoria/03_cifrado_simetrico.md

Ejecutar: python 03_aes.py
Requisitos: pip install pycryptodome
"""

import os
import struct

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    PYCRYPTO_OK = True
except ImportError:
    PYCRYPTO_OK = False
    print("⚠️  pycryptodome no instalado. Ejecutar: pip install pycryptodome")
    print("   Mostrando demos con stdlib limitada...\n")


# ─────────────────────────────────────────────
# AES-CBC (modo clásico — común en malware legacy)
# ─────────────────────────────────────────────

def demo_aes_cbc():
    if not PYCRYPTO_OK:
        print("[AES-CBC] Requiere pycryptodome — instalá con: pip install pycryptodome")
        return

    print("=" * 60)
    print("AES-CBC — Cipher Block Chaining")
    print("=" * 60)

    # Generar clave y IV aleatorios
    clave = get_random_bytes(32)        # AES-256
    iv = get_random_bytes(AES.block_size)  # 16 bytes

    mensaje = "Datos confidenciales del SOC: alert crítica en 192.168.1.50"
    print(f"\nMensaje original: {mensaje!r}")
    print(f"Clave AES-256:    {clave.hex()[:32]}... ({len(clave)*8} bits)")
    print(f"IV:               {iv.hex()} ({len(iv)*8} bits)")

    # Cifrar
    cipher_enc = AES.new(clave, AES.MODE_CBC, iv)
    cifrado = cipher_enc.encrypt(pad(mensaje.encode(), AES.block_size))
    print(f"\nCifrado (hex):    {cifrado.hex()}")
    print(f"Longitud cifrada: {len(cifrado)} bytes (múltiplo de 16)")

    # Descifrar
    cipher_dec = AES.new(clave, AES.MODE_CBC, iv)
    descifrado = unpad(cipher_dec.decrypt(cifrado), AES.block_size).decode()
    print(f"Descifrado:       {descifrado!r}")
    print(f"¿Coincide?:       {'✅' if descifrado == mensaje else '❌'}")

    # Mostrar por qué el IV importa
    print("\n--- ¿Qué pasa si usamos el mismo IV dos veces? ---")
    msg1 = "Contraseña del sistema: admin123"
    msg2 = "Contraseña del sistema: admin456"

    cipher1 = AES.new(clave, AES.MODE_CBC, iv)
    cifrado1 = cipher1.encrypt(pad(msg1.encode(), AES.block_size))
    cipher2 = AES.new(clave, AES.MODE_CBC, iv)
    cifrado2 = cipher2.encrypt(pad(msg2.encode(), AES.block_size))

    # XOR de los cifrados (revela información)
    xor_cifrados = bytes(a ^ b for a, b in zip(cifrado1, cifrado2))
    xor_mensajes = bytes(a ^ b for a, b in zip(
        pad(msg1.encode(), AES.block_size),
        pad(msg2.encode(), AES.block_size)
    ))
    print(f"XOR de cifrados:  {xor_cifrados.hex()[:32]}...")
    print(f"XOR de mensajes:  {xor_mensajes.hex()[:32]}...")
    print("→ Con IV repetido, el XOR de dos cifrados = XOR de los plaintexts")
    print("→ Esto puede revelar información parcial. SIEMPRE usar IV único.")


# ─────────────────────────────────────────────
# AES-GCM (modo moderno — autenticado)
# ─────────────────────────────────────────────

def demo_aes_gcm():
    if not PYCRYPTO_OK:
        print("[AES-GCM] Requiere pycryptodome")
        return

    print("\n" + "=" * 60)
    print("AES-GCM — Galois/Counter Mode (AEAD)")
    print("=" * 60)
    print("Cifrado + Autenticación integrada\n")

    clave = get_random_bytes(32)   # AES-256
    nonce = get_random_bytes(12)   # 96 bits — recomendado para GCM

    mensaje = "Reporte de incidente: sistema comprometido en producción"
    aad = b"header: SOC-REPORT-2024"  # Datos adicionales autenticados (no cifrados)

    print(f"Mensaje:  {mensaje!r}")
    print(f"AAD:      {aad!r} (se autentica pero no se cifra)")

    # Cifrar
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    cifrado, tag = cipher.encrypt_and_digest(mensaje.encode())

    print(f"\nCifrado:  {cifrado.hex()}")
    print(f"Tag:      {tag.hex()} (16 bytes — autenticación)")
    print(f"Nonce:    {nonce.hex()}")

    # Descifrar y verificar (caso exitoso)
    print("\n--- Descifrado correcto ---")
    try:
        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        descifrado = cipher.decrypt_and_verify(cifrado, tag)
        print(f"✅ Autenticación correcta")
        print(f"   Descifrado: {descifrado.decode()!r}")
    except Exception as e:
        print(f"❌ Error: {e}")

    # Descifrar con datos manipulados
    print("\n--- Descifrado con datos manipulados (1 bit cambiado) ---")
    cifrado_manipulado = bytearray(cifrado)
    cifrado_manipulado[0] ^= 0x01
    try:
        cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        descifrado = cipher.decrypt_and_verify(bytes(cifrado_manipulado), tag)
        print(f"Descifrado: {descifrado}")
    except Exception as e:
        print(f"❌ Manipulación detectada: {type(e).__name__}")
        print("   → AES-GCM detecta cualquier modificación del texto cifrado")

    print("\nVentajas de AES-GCM sobre AES-CBC:")
    print("  ✅ Detecta manipulación del texto cifrado (tag de autenticación)")
    print("  ✅ Paralelizable (más rápido en hardware moderno)")
    print("  ✅ Usado en TLS 1.3, SSH, WireGuard")


# ─────────────────────────────────────────────
# ANÁLISIS: Identificar archivos cifrados con AES
# ─────────────────────────────────────────────

def demo_analisis_forense():
    print("\n" + "=" * 60)
    print("ANÁLISIS FORENSE: Reconocer cifrado AES")
    print("=" * 60)

    print("""
Características de un archivo cifrado con AES:

1. ALTA ENTROPÍA (Shannon entropy ≈ 8.0 bits/byte)
   - Archivo normal: ~4-7 bits/byte
   - Archivo comprimido: ~7.9 bits/byte
   - Archivo cifrado: ~7.99 bits/byte
   - Herramienta: binwalk -E archivo, ent archivo

2. LONGITUD MÚLTIPLO DE 16 (si usa CBC con padding)
   - AES opera en bloques de 128 bits = 16 bytes
   - Archivo .docx original: 52,341 bytes
   - Archivo cifrado AES-CBC: 52,352 bytes (siguiente múltiplo de 16)

3. MAGIC BYTES DESTRUIDOS
   - .docx: empieza con PK (ZIP)
   - .pdf: empieza con %PDF
   - Cifrado: empieza con bytes aleatorios

4. SIN STRINGS LEGIBLES
   - strings archivo.enc → salida mínima o vacía
   - Strings herramienta: strings archivo | head

5. EN MALWARE: buscar importaciones criptográficas
   - Windows API: CryptEncrypt, CryptAcquireContext, BCryptEncrypt
   - OpenSSL: EVP_EncryptInit, AES_set_encrypt_key
   - Herramienta: strings malware.exe | grep -i crypt
""")


# ─────────────────────────────────────────────
# PATRÓN RANSOMWARE (simplificado, solo educativo)
# ─────────────────────────────────────────────

def demo_patron_ransomware_aes():
    """
    Muestra el PATRÓN criptográfico del ransomware.
    NO cifra archivos reales. Solo demuestra la lógica.
    """
    if not PYCRYPTO_OK:
        print("[Ransomware pattern] Requiere pycryptodome")
        return

    print("\n" + "=" * 60)
    print("PATRÓN CRIPTOGRÁFICO DEL RANSOMWARE (simulación educativa)")
    print("=" * 60)

    # Simular que hay una clave RSA pública del atacante
    # (En ransomware real, está embebida en el ejecutable)
    print("\n[ATACANTE] Genera par RSA (antes del ataque):")
    print("  → Clave pública RSA-2048: embebida en el malware")
    print("  → Clave privada RSA-2048: guardada en C2")

    # Por la víctima (simulamos con AES únicamente, sin RSA para simplificar)
    print("\n[VÍCTIMA] El malware en ejecución:")

    # Paso 1: Generar clave AES única por víctima
    clave_aes = get_random_bytes(32)
    iv = get_random_bytes(16)
    print(f"\n  Paso 1: Genera clave AES-256 aleatoria")
    print(f"          Clave: {clave_aes.hex()[:32]}...")

    # Paso 2: Cifrar archivo con AES
    archivo_original = b"Documento_importante.docx: contenido confidencial de la empresa"
    cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
    archivo_cifrado = cipher.encrypt(pad(archivo_original, AES.block_size))
    print(f"\n  Paso 2: Cifra el archivo con AES-256-CBC")
    print(f"          Original ({len(archivo_original)}b): {archivo_original[:40]}...")
    print(f"          Cifrado  ({len(archivo_cifrado)}b): {archivo_cifrado.hex()[:40]}...")

    # Paso 3: Cifrar clave AES con RSA pública (simulado)
    print(f"\n  Paso 3: Cifra la clave AES con RSA pública del atacante")
    print(f"          (En producción: RSA_encrypt(clave_aes, rsa_public_key))")
    print(f"          Resultado: blob cifrado RSA → guardado en ransomnote")

    # Paso 4: Borrar clave AES
    clave_aes = bytes(32)  # Sobrescribir con zeros
    print(f"\n  Paso 4: Borra la clave AES de memoria")
    print(f"          Clave borrada: {clave_aes.hex()}")

    print(f"\n  Resultado: sin clave RSA privada del atacante → imposible recuperar")
    print(f"\n  DETECCIÓN en tiempo real:")
    print(f"  → Proceso accediendo a 100+ archivos por minuto")
    print(f"  → Extensiones siendo renombradas masivamente")
    print(f"  → CPU alta + I/O disco alto en proceso desconocido")
    print(f"  → Archivos con entropía alta donde antes había documentos normales")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_aes_cbc()
    demo_aes_gcm()
    demo_analisis_forense()
    demo_patron_ransomware_aes()

    print("\n" + "=" * 60)
    print("PRÓXIMO: python 04_rsa.py — Criptografía asimétrica")
    print("=" * 60)
