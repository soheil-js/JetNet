# 🔐 JET – JSON Encrypted Token

**JET (JSON Encrypted Token)** is a modern cryptographic token format, designed as a secure alternative to **JWT** and **JWE**. Unlike JWT, which often encodes sensitive data without encryption, **JET is encrypted by design** — using strong authenticated symmetric ciphers and memory‑hard key derivation functions.

## 🌍 Why JET?

JWT is widely adopted, but it has several limitations and pitfalls when it comes to real-world security:

- ❌ **Claims are not encrypted by default** — sensitive information is only Base64-encoded, making it trivially readable.  
- ❌ **Vulnerable to algorithm attacks** — JWT security heavily depends on choosing the right algorithm and not misconfiguring it (e.g., `none` or weak HMAC).  
- ❌ **Complexity with JWE/JWS** — combining JWT with JWE/JWS to add encryption and signature increases implementation complexity, and even small mistakes can break security.  
- ❌ **Replay and tampering issues** — JWT does not enforce replay protection; additional infrastructure is needed to track token usage.  
- ❌ **Key management is tricky** — rotating keys and securely sharing symmetric secrets is error-prone.

**JET solves these problems with a modern, secure design:**

- ✅ **Payload encryption by default** — all sensitive data is encrypted with strong AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305).  
- ✅ **Header integrity and tamper protection** — the header is included as authenticated additional data (AAD), so any modification breaks decryption.  
- ✅ **Memory-hard, per-token KDF** — Argon2id (or scrypt) derives a unique key for each token with a random salt, mitigating brute-force attacks on passwords.  
- ✅ **Built-in timing and replay protection** — `issuedAt`, `notBefore`, `expiration` and optional `id` validation prevent token reuse and enforce strict token lifetimes.  
- ✅ **Flexible validation hooks** — easy delegates allow claims validation and server-side token-ID revocation.  
- ✅ **Simple, extensible format** — two-part structure (`header:payload`) is easy to parse, inspect, and extend with custom fields.  
- ✅ **Resistant to common JWT attacks** — such as none-algorithm abuse, key confusion, and misconfigured signatures.  
- ✅ **No dependency on external JWE/JWS libraries** — reduces complexity, surface area for bugs, and attack vectors.  
- ✅ **Random nonces per token** — ensures AEAD uniqueness and semantic security even for identical payloads.

**In short:** JET is designed to be secure by default, minimizes developer mistakes, and provides a clear, modern approach to token encryption and validation that addresses real-world risks where JWT and JWE can fall short.



## 🔒 Cryptography

### Symmetric Algorithms
- **AES‑256‑GCM** — industry standard, often hardware accelerated.  
- **ChaCha20‑Poly1305** — fast on platforms without AES hardware.  
- **XChaCha20‑Poly1305** — ChaCha20 with an extended nonce (safer when many random nonces are needed).

### Key Derivation Functions
- **Argon2id** — recommended (winner of PHC), good resistance to GPU/ASIC attacks.  
- **Scrypt** — proven memory‑hard KDF and widely used.

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
  "id": "c8ba40ce-d5d4-4b95-966a-f701d33b27d9",
  "claims": {
    "issuer": "...",  
    "subject": "",
    "audience": [
      "...",
      "..."
    ]
  },
  "issuedAt": "...",
  "notBefore": "...",
  "expiration": "...",
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

## 🛡️ Replay protection

JET uses a unique `id` (GUID) in each token header as a token identifier.  
While AEAD nonces ensure semantic security, they **do not prevent replay attacks by themselves**.  

To protect against token replay:

- Validate the `id` (token identifier) server-side or in your application, e.g., keep a short-lived cache of used IDs.  
- Standard claims like `expiration` and `notBefore`/`issuedAt` (not-before/issued-at) should also be verified to limit the token's valid window.  

This implementation provides `header.id` and hooks via `validateTokenId` for application-level replay protection. Replay mitigation is enforced by the consuming application rather than the JET library itself.


## 🧪 Example (C#)

```csharp
using JetNet;
using JetNet.Crypto;
using JetNet.Models;

var jet = new Jet("myStrongPassword123!");
var payload = new { user = "Soheil Jashnsaz", role = "admin" };

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);
Claims claims = new Claims()
{
    Issuer = "mycompany.com",
    Subject = "user-authentication",
};
claims.Audience.AddRange("app-web", "app-mobile", "api-service");
string token = jet.Encode(payload, claims, kdf, SymmetricAlgorithm.AES_256_GCM, expiration: DateTime.UtcNow.AddSeconds(10));

// Decode
var decoded = jet.Decode<dynamic>(token, ValidateClaims, ValidateTokenID);

Console.WriteLine(token); // Encoded token
Console.WriteLine(); // New line
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"


Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// Validate claims
bool ValidateClaims(Claims claims)
{
    return true;
}

// Validate token id
bool ValidateTokenID(string id)
{
    return true;
}

```

## ✅ Tests

Provided round-trip unit tests cover combinations:

- Argon2id + AES-256‑GCM  
- Argon2id + ChaCha20‑Poly1305  
- Argon2id + XChaCha20‑Poly1305  
- Scrypt   + AES-256‑GCM  
- Scrypt   + ChaCha20‑Poly1305  
- Scrypt   + XChaCha20‑Poly1305

## 🚀 Example Token

```
eyJjbGFpbXMiOnsiaXNzdWVyIjoibXljb21wYW55LmNvbSIsInN1YmplY3QiOiJ1c2VyLWF1dGhlbnRpY2F0aW9uIiwiYXVkaWVuY2UiOlsiYXBwLXdlYiIsImFwcC1tb2JpbGUiLCJhcGktc2VydmljZSJdfSwiZXhwaXJhdGlvbiI6IjIwMjUtMDktMTRUMjM6MTE6MjYuODYxNzQ2MloiLCJpZCI6ImM4YmE0MGNlLWQ1ZDQtNGI5NS05NjZhLWY3MDFkMzNiMjdkOSIsImlzc3VlZEF0IjoiMjAyNS0wOS0xNFQyMzoxMToxNy4xMjYyMDA1WiIsImtkZiI6eyJ0eXBlIjoiQXJnb24yaWQiLCJtZW1vcnkiOjY1NTM2LCJpdGVyYXRpb25zIjozLCJwYXJhbGxlbGlzbSI6MSwic2FsdCI6IlNkb1NuSWdBc0pzUExxMGJOX2IxVGcifSwibm90QmVmb3JlIjoiMjAyNS0wOS0xNFQyMzoxMToxNy4xMjYyMDA1WiIsInN5bW1ldHJpYyI6IkFFUy0yNTYtR0NNIiwidHlwZSI6IkpFVCJ9:eyJjb250ZW50Ijp7ImNpcGhlcnRleHQiOiI3cEEtTDhNUmp1elVVMl9DSGR6TzZYbExuMS1rWDExeUdoNTdsWWZ4Mlg0eVA0MWVUUTRhX1ZnIiwidGFnIjoiSEZsTGhjbGNkdXpyVko0Y0d4dkV2USIsIm5vbmNlIjoickFyd3JWTDN2ZGtXclFwYyJ9LCJjZWsiOnsiY2lwaGVydGV4dCI6IkZhc0ZDN19JYW1lcWh6R1J4Yk90T1dHN2RUOFV1M1Azbl94TTRuZU5kX2ciLCJ0YWciOiJ3eFAxUksxeC1HekpwOWZTckYybGxRIiwibm9uY2UiOiJzankyWUp5elJYUTBXY0txIn19
```

Decoded Payload:
```json
{
  "user": "Soheil Jashnsaz",
  "role": "admin"
}
```

## 🔑 Choosing a Strong Master Password

The security of JET tokens ultimately relies on the strength of your master password. A weak password can undermine all cryptographic protections, even if AEAD ciphers and memory-hard KDFs are used.

**Best practices for a strong password:**

- ✅ Use at least 16 characters.  
- ✅ Include a mix of uppercase, lowercase, numbers, and symbols.  
- ✅ Avoid common words, predictable patterns, or personal information.  
- ✅ Consider using a passphrase of multiple unrelated words for memorability.  
- ✅ Do not reuse passwords across services.

**Example of a strong master password:**
```
G7$wR9!vZp2#qK8d
```

This password is random, long enough, and contains diverse character types, making it resistant to brute-force or dictionary attacks.  

> Tip: Use a secure password manager to generate and store master passwords safely.


## 🤝 Contributing

JET is experimental and open for contributions. Pull requests, issues, and algorithm proposals are welcome.

## 📜 License
MIT License

## :bookmark:Credits
- [Newtonsoft.Json](https://github.com/JamesNK/Newtonsoft.Json) (Json.NET is a popular high-performance JSON framework for .NET)
- [NSec.Cryptography](https://github.com/ektrah/nsec) (A modern and easy-to-use cryptographic library for .NET based on libsodium)