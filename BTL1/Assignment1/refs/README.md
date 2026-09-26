# Tai lieu & ma nguon tham khao

Toan bo ma nguon trong `srcs/` la do nhom hien thuc. Cac tai lieu/chuan
tham khao chinh:

## Chuan & RFC
- RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
  (tham khao mo hinh bat tay va key schedule bang HKDF).
- RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile.
- RFC 6960 - X.509 Internet PKI Online Certificate Status Protocol (OCSP).
- RFC 7748 - Elliptic Curves for Security (Curve25519 / X25519).
- RFC 8017 - PKCS #1 v2.2 (RSAES/RSASSA-PSS).
- FIPS 197 (AES), FIPS 180-4 (SHA-2), FIPS 198-1 (HMAC).
- NIST SP 800-38A - Block Cipher Modes of Operation (CBC).

## Thu vien ma nguon mo
- pyca/cryptography (https://cryptography.io) - phien ban >= 41.0
  Dung cho: RSA, X25519, AES-CBC, HMAC, HKDF, SHA-256, va toan bo X.509/CRL.
  Giay phep: Apache-2.0 / BSD.
- Thu vien chuan Python: socket, ssl, http.server, json, hashlib, hmac.

## Kien thuc tham khao
- Encrypt-then-MAC: Bellare & Namprempre, "Authenticated Encryption" (2000).
- Mo hinh tan cong MitM tren Diffie-Hellman va vai tro cua xac thuc danh tinh
  (khoa cong khai/chu ky) de chong lai.
