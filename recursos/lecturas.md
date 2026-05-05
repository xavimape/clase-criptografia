# 📖 Lecturas y Recursos Recomendados

---

## Libros gratuitos online

| Título | URL | Nivel | Enfoque |
|--------|-----|-------|---------|
| **Practical Cryptography for Developers** | cryptobook.nakov.com | Intermedio | Implementación práctica, Python |
| **A Graduate Course in Applied Cryptography** | toc.cryptobook.us | Avanzado | Teoría formal |
| **Crypto 101** | crypto101.io | Principiante | Introducción amigable |

---

## Recursos online gratuitos

### Para aprender criptografía
- **[CryptoHack](https://cryptohack.org/)** — Plataforma de challenges progresivos. Cubre AES, RSA, ECC, hash, TLS. Muy bien hecho.
- **[The Cryptopals Challenges](https://cryptopals.com/)** — Challenges clásicos enfocados en ataques reales (padding oracle, CBC bit flipping, etc.)
- **[Khan Academy — Criptografía](https://www.khanacademy.org/computing/computer-science/cryptography)** — Conceptos básicos con explicaciones visuales

### Para SOC / Blue Team
- **[MITRE ATT&CK — Cryptography techniques](https://attack.mitre.org/)** — Buscar T1486 (Data Encrypted), T1059.001 (PowerShell), T1140, etc.
- **[SANS Reading Room](https://www.sans.org/white-papers/)** — Papers gratuitos de incident response y forense
- **[CISA Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)** — Alertas sobre ransomware activo con IoCs
- **[No More Ransom](https://www.nomoreransom.org/)** — Proyecto conjunto Europol/Intel/Kaspersky con decryptors

---

## Videos y cursos

| Recurso | URL | Nota |
|---------|-----|------|
| Computerphile (YouTube) | youtube.com/@Computerphile | Excelentes videos de criptografía, 10-20 min |
| SANS Webcasts | sans.org/webcasts | Gratuitos, nivel SOC |
| TCM Security (YouTube) | youtube.com/@TCMSecurityAcademy | Muy práctico, nivel L1 |

### Videos específicos recomendados de Computerphile
- "AES Explained" — cómo funciona AES internamente
- "How TLS Works" — handshake visual
- "SHA: Secure Hashing Algorithm" — SHA-256 explicado
- "Diffie Hellman - the Mathematics bit" — DH entendible
- "RSA-OAEP Encryption" — RSA con padding correcto

---

## Papers y documentos técnicos

| Documento | Relevancia |
|-----------|------------|
| [NIST SP 800-175B: Guideline for Using Crypto Standards](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final) | Guía oficial de qué usar |
| [Análisis técnico de WannaCry (US-CERT)](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) | Estudio de caso real |
| [SHAttered - colisiones en SHA-1](https://shattered.io/) | Por qué SHA-1 está roto |
| [Hive Ransomware decryptor paper](https://eprint.iacr.org/2022/1327.pdf) | Cómo rompieron el RNG de Hive |

---

## MITRE ATT&CK — Técnicas criptográficas relevantes

| ID | Nombre | Descripción |
|----|--------|-------------|
| **T1486** | Data Encrypted for Impact | Ransomware — cifrado de datos |
| **T1140** | Deobfuscate/Decode Files | certutil -decode, Base64 decode |
| **T1059.001** | PowerShell | PowerShell -enc, encoded commands |
| **T1027** | Obfuscated Files | Base64, XOR, capas de encoding |
| **T1218.005** | mshta | LOLBin execution |
| **T1218.010** | regsvr32 | LOLBin — Squiblydoo |
| **T1071.001** | Web Protocols (C2) | C2 sobre HTTP/HTTPS |
| **T1573** | Encrypted Channel | Canal C2 cifrado |
| **T1036** | Masquerading | Nombres de proceso que emulan legítimos |
| **T1003.001** | LSASS Memory | Mimikatz, volcado de credenciales |

---

## Glosario rápido

| Término | Definición |
|---------|------------|
| **AES** | Advanced Encryption Standard — cifrado simétrico estándar |
| **AEAD** | Authenticated Encryption with Associated Data — cifrado + autenticación |
| **C2 / CnC** | Command and Control — servidor de control del atacante |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator |
| **DH** | Diffie-Hellman — protocolo de intercambio de claves |
| **ECC** | Elliptic Curve Cryptography — curvas elípticas |
| **GCM** | Galois/Counter Mode — modo de operación de AES con autenticación |
| **HMAC** | Hash-based Message Authentication Code |
| **IOC** | Indicator of Compromise — hash, IP, dominio malicioso |
| **IV / Nonce** | Initialization Vector — valor único para evitar patrones en AES |
| **JA3** | Fingerprint del cliente TLS (hash de parámetros ClientHello) |
| **LOLBin** | Living off the Land Binary — binario legítimo usado maliciosamente |
| **MITM** | Man-in-the-Middle — intercepción de comunicaciones |
| **NTLM** | NT LAN Manager — protocolo de autenticación Windows (hash MD4) |
| **OAEP** | Optimal Asymmetric Encryption Padding — padding seguro para RSA |
| **PFS** | Perfect Forward Secrecy — claves efímeras por sesión |
| **PKI** | Public Key Infrastructure — infraestructura de clave pública |
| **RSA** | Rivest-Shamir-Adleman — algoritmo asimétrico |
| **Salt** | Valor aleatorio único añadido antes de hashear contraseñas |
| **SHA** | Secure Hash Algorithm |
| **SNI** | Server Name Indication — hostname en handshake TLS |
| **TLS** | Transport Layer Security — protocolo de cifrado en tránsito |
| **TTPs** | Tactics, Techniques, and Procedures — métodos del atacante |
