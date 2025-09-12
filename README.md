# 🔐 JET – JSON Encrypted Token

**JET (JSON Encrypted Token)** is a modern cryptographic token format, designed as a secure alternative to **JWT** and **JWE**. Unlike JWT, which often encodes sensitive data without encryption, **JET is encrypted by design** — using strong authenticated symmetric ciphers and memory‑hard key derivation functions.

## 🌍 Why JET?
JWT is widely used but has important pitfalls:
- ❌ Sensitive claims in JWT are often only Base64‑encoded, not encrypted.  
- ❌ Security relies heavily on correct algorithm choices and secure usage.  
- ❌ Combining JWT with JWE/JWS adds complexity and new failure modes.

**JET aims to solve these problems:**
- ✅ **Encryption‑first design** — payloads are encrypted by default.  
- ✅ **Modern AEAD ciphers** — AES‑256‑GCM, ChaCha20‑Poly1305, XChaCha20‑Poly1305.  
- ✅ **Memory‑hard KDFs** — Argon2id and scrypt for deriving CEK encryption keys from passwords.  
- ✅ **AAD protection for header** — the header is included as AAD (authenticated additional data) so tampering with header parameters will cause decryption to fail.  
- ✅ **Simple, extensible format** — two-part token (`header:payload`) that is easy to parse and extend.

## 🔒 Cryptography

### Symmetric Algorithms
- **AES‑256‑GCM** — industry standard, often hardware accelerated.  
- **ChaCha20‑Poly1305** — fast on platforms without AES hardware.  
- **XChaCha20‑Poly1305** — ChaCha20 with an extended nonce (safer when many random nonces are needed).

### Key Derivation Functions
- **Argon2id** — recommended (winner of PHC), good resistance to GPU/ASIC attacks.  
- **scrypt** — proven memory‑hard KDF and widely used.

## 📖 Token Structure

A JET token is two Base64Url parts separated by `:`:

```
<header_base64url> : <payload_base64url>
```

### Header (JSON, Base64Url-encoded)
Contains algorithm and KDF parameters and **salt** (salt is public):
```json
{
  "symmetric": "AES-256-GCM",
  "kdf": {
    "type": "Argon2id",
    "memory": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "..."
  },
  "type": "JET"
}
```

### Payload (JSON, Base64Url-encoded)
Contains two AEAD outputs: the encrypted content and the encrypted CEK (Content Encryption Key):
```json
{
  "content": {
    "ciphertext": "...",
    "tag": "...",
    "nonce": "..."
  },
  "cek": {
    "ciphertext": "...",
    "tag": "...",
    "nonce": "..."
  }
}
```

- The header JSON is used as AEAD AAD (authenticated additional data) during both CEK encryption and content encryption, so modifying header fields will break decryption authenticity checks.
- Salt is stored in the header (public) and used by the chosen KDF to derive the key that encrypts the CEK.

## 🛠 Encoding / Decoding (high level)

**Encode (simplified):**
1. Serialize payload → bytes.  
2. Generate salt and derive a KDF key from the password.  
3. Generate a random CEK (content encryption key) and random nonces for CEK and content.  
4. Build canonical header JSON and use it as AAD.  
5. Encrypt CEK with derived key (produces CEK ciphertext + tag).  
6. Encrypt payload with CEK (produces ciphertext + tag).  
7. Package `payload` JSON carrying both CEK and content AEAD outputs, Base64Url-encode header and payload, join with `:`.

**Decode (simplified):**
1. Split token by `:` and Base64Url-decode header and payload.  
2. Parse header, reconstruct header JSON used as AAD (use the exact decoded header text as AAD).  
3. Recreate KDF using header params and derive key from password + salt.  
4. Decrypt CEK (with derived key, CEK nonce and tag) using header as AAD.  
5. Decrypt content (with CEK, content nonce and tag) using header as AAD.  
6. Parse decrypted payload JSON into claims or application data.

> Implementation note: the reference implementation uses the exact decoded header JSON string as AAD during decryption to guarantee bytewise equality with the AAD used in encryption (canonicalization must be stable if you choose to canonicalize).

## ⚠️ Replay protection (important)

Nonces are generated randomly for CEK and content to ensure AEAD uniqueness and semantic security. **However, nonces alone do not prevent token replay attacks** (an attacker can resend a valid token to the server). To mitigate replay in practice you should:
- Include standard claims such as `exp` (expiration) and `iat` (issued-at) and validate them on decode, and/or  
- Include a `jti` (token identifier) and track used `jti`s server-side (or keep a short-lived revocation/used-token cache).

This implementation leaves replay protection as an application-level responsibility; future releases may include optional server-side replay mitigation helpers.

## 🧪 Example (C#)

```csharp
using JetNet;
using JetNet.Crypto;

var jet = new Jet("myStrongPassword123!");
var payload = new { user = "Soheil Jashnsaz", role = "admin" };

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);
string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM);

// Decode
var decoded = jet.Decode<dynamic>(token);
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"
```

## ✅ Tests

Provided round-trip unit tests cover combinations:

- Argon2id + AES-256‑GCM  
- Argon2id + ChaCha20‑Poly1305  
- Argon2id + XChaCha20‑Poly1305  
- scrypt   + AES-256‑GCM  
- scrypt   + ChaCha20‑Poly1305  
- scrypt   + XChaCha20‑Poly1305

## 🚀 Example Token

```
eyJrZGYiOnsidHlwZSI6IkFyZ29uMmlkIiwibWVtb3J5Ijo2NTUzNiwiaXRlcmF0aW9ucyI6MywicGFyYWxsZWxpc20iOjEsInNhbHQiOiJ5WnMtMGFpd01CMVBYbXBkUGtWUDZnIn0sInN5bW1ldHJpYyI6IkFFUy0yNTYtR0NNIiwidHlwZSI6IkpFVCJ9:eyJjb250ZW50Ijp7ImNpcGhlcnRleHQiOiJZLTJnWndUQXJKSFRJQjNWT2NVa0lPSSIsInRhZyI6ImJKRi1DMlU3NWN0MmFVbUNGbVg1RUEiLCJub25jZSI6IlM4TzVqSkEyRXVjYmlaZjIifSwiY2VrIjp7ImNpcGhlcnRleHQiOiJ6RzdMd3BsVlF4Q2NVOHN1eHFDYzVVZTBUU0RUV3daVU5iOFhRbHhsVWVVIiwidGFnIjoiWUNyVm5IUTZQQUtBdi1RcVRDeFloQSIsIm5vbmNlIjoiSm9JZnhJYjh3T2dpUlRjViJ9fQ
```

Decoded Payload:
```json
{
  "user": "Soheil Jashnsaz",
  "role": "admin"
}
```

## 🤝 Contributing

JET is experimental and open for contributions. Pull requests, issues, and algorithm proposals are welcome.

## 📜 License
MIT License

## :bookmark:Credits
- [Newtonsoft.Json](https://github.com/JamesNK/Newtonsoft.Json) (Json.NET is a popular high-performance JSON framework for .NET)
- [NSec.Cryptography](https://github.com/ektrah/nsec) (A modern and easy-to-use cryptographic library for .NET based on libsodium)