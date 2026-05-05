"""
04 — RSA: Cifrado Asimétrico y Firmas Digitales
=================================================
Demuestra generación de claves RSA, cifrado y firmas.
Correlacionado con: Slides 06 y 08 de crypto-soc-training.html
                    teoria/04_cifrado_asimetrico.md
                    teoria/06_firmas_digitales.md

Ejecutar: python 04_rsa.py
Requisitos: pip install pycryptodome
"""

try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Signature import pss
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes
    PYCRYPTO_OK = True
except ImportError:
    PYCRYPTO_OK = False
    print("⚠️  pycryptodome no instalado. Ejecutar: pip install pycryptodome")


def demo_generacion_claves():
    if not PYCRYPTO_OK:
        return None, None

    print("=" * 60)
    print("RSA — GENERACIÓN DE PAR DE CLAVES")
    print("=" * 60)

    print("\nGenerando par RSA-2048 (puede tardar un momento)...")
    clave = RSA.generate(2048)

    # Exportar claves en formato PEM
    privada_pem = clave.export_key().decode()
    publica_pem = clave.publickey().export_key().decode()

    print(f"\nClave PÚBLICA (compartir libremente):")
    print(publica_pem)

    print(f"\nClave PRIVADA (NUNCA compartir):")
    # Solo mostramos las primeras líneas por seguridad educativa
    lineas_privada = privada_pem.split('\n')
    print('\n'.join(lineas_privada[:4]))
    print("... [resto de la clave privada — CONFIDENCIAL] ...")
    print(lineas_privada[-1])

    print(f"\nTamaño de clave: {clave.size_in_bits()} bits")
    print(f"Módulo n (primeros 40 chars): {hex(clave.n)[:40]}...")
    print(f"Exponente público e: {clave.e} (estándar: 65537)")

    return clave, clave.publickey()


def demo_cifrado_rsa(clave_privada, clave_publica):
    if not PYCRYPTO_OK or not clave_privada:
        return

    print("\n" + "=" * 60)
    print("RSA — CIFRADO Y DESCIFRADO")
    print("=" * 60)

    # RSA solo cifra datos pequeños (< tamaño de clave)
    # Para datos grandes: usar híbrido RSA + AES
    mensaje = b"Clave AES secreta: " + get_random_bytes(32)
    print(f"\nMensaje a cifrar ({len(mensaje)} bytes): {mensaje[:20].hex()}...")
    print("(Simulando el cifrado de una clave AES como hace el ransomware)")

    # Cifrar con clave pública
    cipher_pub = PKCS1_OAEP.new(clave_publica)
    cifrado = cipher_pub.encrypt(mensaje)
    print(f"\nCifrado con RSA pública ({len(cifrado)} bytes):")
    print(f"  {cifrado.hex()[:60]}...")
    print("  (Solo quien tiene la clave privada puede descifrar esto)")

    # Descifrar con clave privada
    cipher_priv = PKCS1_OAEP.new(clave_privada)
    descifrado = cipher_priv.decrypt(cifrado)
    print(f"\nDescifrado con RSA privada:")
    print(f"  {descifrado[:20].hex()}...")
    print(f"  ¿Coincide?: {'✅' if descifrado == mensaje else '❌'}")

    # Intentar descifrar con clave pública (debe fallar)
    print("\n--- ¿Qué pasa si intentamos descifrar con la clave pública? ---")
    try:
        cipher_wrong = PKCS1_OAEP.new(clave_publica)
        cipher_wrong.decrypt(cifrado)
        print("❌ Esto no debería ocurrir")
    except Exception as e:
        print(f"✅ Correcto — no se puede descifrar con la clave pública: {type(e).__name__}")


def demo_firma_digital(clave_privada, clave_publica):
    if not PYCRYPTO_OK or not clave_privada:
        return

    print("\n" + "=" * 60)
    print("RSA — FIRMAS DIGITALES")
    print("=" * 60)

    documento = b"Reporte forense: el sistema fue comprometido el 2024-01-15 a las 03:42 UTC"
    print(f"\nDocumento a firmar:")
    print(f"  {documento.decode()!r}")

    # Firmar con clave privada
    hash_doc = SHA256.new(documento)
    firma = pss.new(clave_privada).sign(hash_doc)
    print(f"\nFirma digital ({len(firma)} bytes):")
    print(f"  {firma.hex()[:60]}...")

    # Verificar firma con clave pública
    print("\n--- Verificación de firma ---")

    def verificar(doc, firma, clave_pub, descripcion):
        try:
            hash_verif = SHA256.new(doc)
            pss.new(clave_pub).verify(hash_verif, firma)
            print(f"  ✅ {descripcion}: FIRMA VÁLIDA")
        except Exception:
            print(f"  ❌ {descripcion}: FIRMA INVÁLIDA")

    # Verificación correcta
    verificar(documento, firma, clave_publica, "Documento original")

    # Documento modificado (1 byte)
    doc_modificado = bytearray(documento)
    doc_modificado[0] ^= 0x01
    verificar(bytes(doc_modificado), firma, clave_publica, "Documento modificado")

    # Firma falsa
    firma_falsa = bytes(len(firma))
    verificar(documento, firma_falsa, clave_publica, "Firma falsa")

    print("""
Conclusión:
  → Solo quien tiene la clave privada puede CREAR firmas válidas
  → Cualquiera con la clave pública puede VERIFICAR
  → Cualquier modificación del documento invalida la firma
  → Esto garantiza autenticidad + integridad simultáneamente
""")


def demo_cifrado_hibrido():
    if not PYCRYPTO_OK:
        return

    print("=" * 60)
    print("CIFRADO HÍBRIDO RSA+AES (patrón del ransomware)")
    print("=" * 60)
    print("RSA para intercambio de clave → AES para cifrar datos (velocidad)")

    # Simular par del "atacante"
    print("\n[ATACANTE] Par RSA-2048:")
    clave_atacante = RSA.generate(2048)
    publica_atacante = clave_atacante.publickey()
    print("  → Clave pública embebida en malware")
    print("  → Clave privada guardada en C2")

    # La víctima (el malware ejecutándose)
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    datos_victima = b"Archivo secreto de la empresa: contrato_2024.pdf [contenido sensitivo]"
    print(f"\n[VÍCTIMA] Datos a cifrar ({len(datos_victima)} bytes)")

    # Paso 1: Generar clave AES efímera
    clave_aes = get_random_bytes(32)
    iv = get_random_bytes(16)
    print(f"\n  1. Genera clave AES-256 efímera: {clave_aes.hex()[:20]}...")

    # Paso 2: Cifrar datos con AES (rápido)
    cipher_aes = AES.new(clave_aes, AES.MODE_CBC, iv)
    datos_cifrados = cipher_aes.encrypt(pad(datos_victima, AES.block_size))
    print(f"  2. Cifra datos con AES: {datos_cifrados.hex()[:20]}... ({len(datos_cifrados)} bytes)")

    # Paso 3: Cifrar clave AES con RSA pública del atacante
    cipher_rsa = PKCS1_OAEP.new(publica_atacante)
    clave_aes_cifrada = cipher_rsa.encrypt(clave_aes + iv)  # cifra AES key + IV
    print(f"  3. Cifra clave AES con RSA pública: {clave_aes_cifrada.hex()[:20]}... ({len(clave_aes_cifrada)} bytes)")
    print(f"     → Esta clave cifrada RSA queda en la ransomnote")

    # Destruir clave AES de memoria
    clave_aes = bytes(32)
    print(f"  4. Borra clave AES: {clave_aes.hex()}")

    print(f"\n  Resultado para la víctima:")
    print(f"    - Datos cifrados ({len(datos_cifrados)} bytes): inútiles sin clave AES")
    print(f"    - Clave AES cifrada RSA: inútil sin clave RSA privada del atacante")
    print(f"    - Sin pago: sin datos")

    # [RECUPERACIÓN] — solo con clave privada RSA del atacante
    print(f"\n[RECUPERACIÓN] Con clave RSA privada (en poder del atacante):")
    cipher_rsa_dec = PKCS1_OAEP.new(clave_atacante)
    clave_aes_recuperada_bytes = cipher_rsa_dec.decrypt(clave_aes_cifrada)
    clave_aes_recuperada = clave_aes_recuperada_bytes[:32]
    iv_recuperado = clave_aes_recuperada_bytes[32:]

    cipher_aes_dec = AES.new(clave_aes_recuperada, AES.MODE_CBC, iv_recuperado)
    datos_recuperados = unpad(cipher_aes_dec.decrypt(datos_cifrados), AES.block_size)
    print(f"  Datos recuperados: {datos_recuperados.decode()!r}")
    print(f"  ✅ Recuperación exitosa (con clave privada RSA)")


def demo_conceptos_pki():
    print("\n" + "=" * 60)
    print("PKI — CONCEPTOS CLAVE PARA SOC")
    print("=" * 60)
    print("""
Jerarquía de certificados:
  Root CA (confiada por el OS)
    └── Intermediate CA
          └── Certificado final (tu web, tu exe)

En análisis de tráfico TLS:
  1. Ver el certificado del servidor en Wireshark/Zeek
  2. Verificar la cadena de confianza
  3. Si self-signed: la CA es el mismo servidor → sospechoso
  4. Si CA desconocida: no está en el almacén del OS → alerta

En análisis de malware:
  1. Get-AuthenticodeSignature archivo.exe
  2. Ver: Status, SignerCertificate, TimeStamperCertificate
  3. Firma válida NO garantiza seguridad (ver: CCleaner 2017, 3CX 2023)
  4. Siempre verificar hash SHA-256 contra fuente oficial

Verificar revocación:
  - OCSP: Online Certificate Status Protocol (tiempo real)
  - CRL: Certificate Revocation List (lista descargable)
  - PowerShell verifica automáticamente por defecto

Comandos útiles:
  # Ver certificados en Windows
  certmgr.msc

  # Ver certificado de un sitio web
  openssl s_client -connect example.com:443 </dev/null | openssl x509 -noout -text

  # Verificar firma de ejecutable
  Get-AuthenticodeSignature archivo.exe | Format-List *
""")


if __name__ == "__main__":
    privada, publica = demo_generacion_claves()
    demo_cifrado_rsa(privada, publica)
    demo_firma_digital(privada, publica)
    demo_cifrado_hibrido()
    demo_conceptos_pki()
