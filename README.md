# 🔐 JET – JSON Encrypted Token

**JET (JSON Encrypted Token)** is a modern cryptographic token format, designed as a secure alternative to **JWT** and **JWE**. Unlike JWT, which often encodes sensitive data without encryption, **JET is encrypted by design** — using strong authenticated symmetric ciphers and memory‑hard key derivation functions.

## 🌍 Why JET?

Modern token security faces critical challenges with existing standards:

**JWT's fundamental flaws:**
* ❌ **Zero confidentiality** — payloads are Base64-encoded, readable by anyone with basic tools
* ❌ **Algorithm vulnerabilities** — `"alg": "none"` attacks and HMAC/RSA confusion exploits  
* ❌ **No replay protection** — stolen tokens remain valid until natural expiration
* ❌ **Sensitive data exposure** — user details, roles, and permissions visible in logs and traffic

**JWE's complexity burden:**
* ❌ **Key distribution nightmare** — complex infrastructure for key sharing and rotation
* ❌ **Multiple algorithm coordination** — increased attack surface and implementation errors
* ❌ **Development overhead** — steep learning curve and error-prone integration

**JET solves these with modern cryptographic design:**
* ✅ **Industry-standard encryption by default** — AES-256-GCM and ChaCha20-Poly1305 protect all payload data
* ✅ **Password-based simplicity** — no complex key infrastructure, just strong password management  
* ✅ **Extensible crypto suite** — header-declared `enc` and `kdf` algorithms, ready for future standards
* ✅ **Memory-hard key derivation** — currently supports Argon2id and Scrypt with configurable parameters
* ✅ **Per-token key isolation** — unique salts generate independent encryption keys for each token
* ✅ **Built-in replay defense** — token IDs and strict timing validation prevent reuse attacks
* ✅ **Authenticated headers** — tamper-proof metadata without exposing sensitive information
* ✅ **Future-proof design** — algorithm agility allows seamless upgrades to emerging cryptographic standards
* ✅ **Single responsibility** — focused on encryption, avoiding JWT's multi-purpose confusion

**Bottom line:** JET delivers enterprise-grade security with developer-friendly simplicity — encrypted by design, not as an afterthought.

### 📊 Quick Comparison

| Feature | JWT | JWE | JET |
|---------|-----|-----|-----|
| **Payload Encryption** | ❌ Base64 only | ✅ Yes | ✅ Yes |
| **Implementation Complexity** | ✅ Simple | ❌ Complex | ✅ Simple |
| **Key Management** | ✅ Simple | ❌ Complex PKI | ✅ Password-based |
| **Memory-Hard KDF** | ❌ No | ❌ No | ✅ Argon2id/Scrypt |
| **Per-Token Unique Keys** | ❌ No | ❌ No | ✅ Yes |
| **Built-in Replay Protection** | ❌ No | ❌ No | ✅ Token ID + timing |
| **Algorithm Agility** | ⚠️ Limited | ⚠️ Complex | ✅ Header-declared |
| **Quantum Resistance** | ❌ RSA vulnerable | ⚠️ Depends | ✅ Current standards |
| **Development Learning Curve** | ✅ Low | ❌ High | ✅ Low |

## 🔒 Cryptography

### Symmetric Algorithms
- **AES‑256‑GCM** — industry standard, hardware accelerated on most modern processors  
- **ChaCha20‑Poly1305** — high performance on platforms without dedicated AES hardware  
- **XChaCha20‑Poly1305** — ChaCha20 with 192-bit nonces instead of 96-bit, reducing collision risk

### Key Derivation Functions
- **Argon2id** — Password Hashing Competition winner, optimal resistance to GPU/ASIC attacks  
- **Scrypt** — established memory‑hard KDF with proven security properties

## 📖 Token Structure

A JET token is two Base64Url parts separated by `.`:

```
<header_base64url> . <payload_base64url>
```

### Header (JSON, Base64Url-encoded)
Contains algorithm parameters, KDF configuration, and public metadata:
```json
{
    "enc": "AES-256-GCM",
    "kdf": {
        "t": "Argon2id",
        "m": 65536,
        "i": 3,
        "p": 1,
        "s": "gIVCGNiKIFGBViYGs1H-qQ"
    },
    "md": {
        "app": "my-application"
    },
    "jti": "01998774-9242-7b96-8aa9-51d3e39af9cb",
    "iat": "2025-09-26T19:16:27.833Z",
    "nbf": "2025-09-26T19:16:27.833Z",
    "exp": "2025-09-27T19:16:27.82Z",
    "typ": "JET"
}
```
**⚠️ Security Notice:** Header fields are authenticated but **not encrypted**. Never include sensitive data in headers or metadata.

### Payload (JSON, Base64Url-encoded)
Contains two AEAD outputs: the encrypted content and the encrypted CEK (Content Encryption Key):
```json
{
    "ct": {
        "c": "iT1zBdyEEK1hW6yCxP2-ebL-9wU826Cdyyuxs-rFY2MBUO8cam1ohMKsHpf1P0X8SCa90kyAZUNl4GtzrR-zgyPQG8KsBPQp7MWGBgCCTWS2Erjl-NZXFlWJD3YiKcQvX3PTocVlwbKhCdUkME2x3pmCNdraIXo8WhgRZwJLaEXHFjyrqjh41MjvvcbZmaJHxJ24",
        "t": "I5K5a003gjF8VeLsMdO7fA",
        "n": "oleKByrG0AwU2ot_"
    },
    "k": {
        "c": "ys1wdmy0Ttl5oFSd_JtMWkR7e9c3g3bSbJxAbl84enQ",
        "t": "nRiqIk60vK2D6twJxQiApQ",
        "n": "05FYx3BrwHHPvWJo"
    }
}
```

- Header JSON serves as Additional Authenticated Data (AAD) for both CEK and content encryption
- Salt is publicly stored in header and used for password-based key derivation
- Modifying any header field invalidates the token through authentication failure

## 🛠 Encoding / Decoding (high level)

**Encode Process:**
1. Serialize sensitive payload to JSON bytes
2. Generate cryptographically random salt and derive KEK (Key Encryption Key) using chosen KDF
3. Generate random CEK (Content Encryption Key) and unique nonces for both operations
4. Build canonical header JSON for use as authenticated additional data
5. Encrypt CEK with derived KEK, producing CEK ciphertext and authentication tag
6. Encrypt payload with CEK, producing content ciphertext and authentication tag  
7. Construct final payload JSON with both encrypted components, encode header and payload as Base64Url

**Decode Process:**
1. Parse token structure and Base64Url-decode header and payload components
2. Reconstruct header JSON exactly as used during encoding for AAD consistency
3. Extract KDF parameters and derive KEK from password and salt
4. Decrypt CEK using derived KEK, nonce, and authentication tag with header as AAD
5. Decrypt content using recovered CEK, nonce, and authentication tag with header as AAD
6. Parse decrypted JSON to recover original sensitive data

**Implementation Note:** The reference uses exact decoded header JSON as AAD to ensure byte-perfect consistency between encoding and decoding operations.

## 🛡️ Replay protection

JET implements multiple layers of replay protection:

**Token Identifier (`jti`):** Each token contains a unique GUID Version 7 identifier in the header

**Temporal Controls:** Built-in timestamp validation with `iat`, `nbf`, and `exp` claims

**Application Integration:** Validation hooks allow server-side token ID tracking and revocation

**Security Model:** While AEAD nonces ensure semantic security (identical payloads produce different ciphertexts), replay protection requires application-level validation of token identifiers and temporal bounds.

**Best Practice:** Implement short-lived token ID cache to detect and reject replayed tokens within their validity window.


## 🧪 Example (C#)

```csharp
using JetNet;
using JetNet.Crypto;
using System.Security;

// Secure password handling
using var securePassword = new SecureString();
string plainPassword = "G7$wR9!vZp2#qK8d";
try
{
    foreach (char c in plainPassword)
        securePassword.AppendChar(c);
}
finally
{
    plainPassword = string.Empty;
    securePassword.MakeReadOnly();
}

var jet = new Jet(securePassword);

// Sensitive payload data
var payload = new
{
    user = "Soheil Jashnsaz",
    role = "admin",
    claims = new
    {
        iss = "mycompany.com",
        sub = "user-authentication",
        aud = new string[] { "app-web", "app-mobile", "api-service" }
    }
};

// Public metadata (will be in authenticated but unencrypted header)
Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();
keyValuePairs.Add("app", "my-application");

// Strong key derivation configuration
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Create encrypted token
string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM, 
    expiration: DateTime.UtcNow.AddHours(24), metadata: keyValuePairs);

// Decode with validation
var decoded = jet.Decode<dynamic>(token, ValidateMetadata, ValidateTokenID);

Console.WriteLine("Token created successfully");
Console.WriteLine($"User: {decoded.user}");
Console.WriteLine($"Role: {decoded.role}");

// Validation functions
bool ValidateMetadata(Dictionary<string, string> metadata)
{
    return metadata.ContainsKey("app") && metadata["app"] == "my-application";
}

bool ValidateTokenID(string id)
{
    // Implement server-side revocation checking
    return !IsTokenRevoked(id);
}

bool IsTokenRevoked(string tokenId)
{
    // TODO: Implement with your persistence layer (Redis/Database)
    // For production, check revocation list from your data store
    return false;
}
```

## ✅ Test Coverage

Comprehensive round-trip validation across supported cipher/KDF combinations:

- Argon2id + AES‑256‑GCM  
- Argon2id + ChaCha20‑Poly1305  
- Argon2id + XChaCha20‑Poly1305  
- Scrypt + AES‑256‑GCM  
- Scrypt + ChaCha20‑Poly1305  
- Scrypt + XChaCha20‑Poly1305

## 🚀 Example Token Structure

**Encoded Token:**
```
eyJlbmMiOiJBRVMtMjU2LUdDTSIsImV4cCI6IjIwMjUtMDktMjdUMTk6MTY6MjcuODJaIiwiaWF0IjoiMjAyNS0wOS0yNlQxOToxNjoyNy44MzNaIiwianRpIjoiMDE5OTg3NzQtOTI0Mi03Yjk2LThhYTktNTFkM2UzOWFmOWNiIiwia2RmIjp7InQiOiJBcmdvbjJpZCIsIm0iOjY1NTM2LCJpIjozLCJwIjoxLCJzIjoiZ0lWQ0dOaUtJRkdCVmlZR3MxSC1xUSJ9LCJtZCI6eyJhcHAiOiJteS1hcHBsaWNhdGlvbiJ9LCJuYmYiOiIyMDI1LTA5LTI2VDE5OjE2OjI3LjgzM1oiLCJ0eXAiOiJKRVQifQ.eyJjdCI6eyJjIjoiaVQxekJkeUVFSzFoVzZ5Q3hQMi1lYkwtOXdVODI2Q2R5eXV4cy1yRlkyTUJVTzhjYW0xb2hNS3NIcGYxUDBYOFNDYTkwa3lBWlVObDRHdHpyUi16Z3lQUUc4S3NCUFFwN01XR0JnQ0NUV1MyRXJqbC1OWlhGbFdKRDNZaUtjUXZYM1BUb2NWbHdiS2hDZFVrTUUyeDNwbUNOZHJhSVhvOFdoZ1Jad0pMYUVYSEZqeXJxamg0MU1qdnZjYlptYUpIeEoyNCIsInQiOiJJNUs1YTAwM2dqRjhWZUxzTWRPN2ZBIiwibiI6Im9sZUtCeXJHMEF3VTJvdF8ifSwiayI6eyJjIjoieXMxd2RteTBUdGw1b0ZTZF9KdE1Xa1I3ZTljM2czYlNiSnhBYmw4NGVuUSIsInQiOiJuUmlxSWs2MHZLMkQ2dHdKeFFpQXBRIiwibiI6IjA1Rll4M0Jyd0hIUHZXSm8ifX0
```

**After Decryption (sensitive data protected):**
```json
{
  "user": "Soheil Jashnsaz",
  "role": "admin",
  "claims": {
    "iss": "mycompany.com",
    "sub": "user-authentication",
    "aud": [
      "app-web",
      "app-mobile",
      "api-service"
    ]
  }
}

```

## 🔑 Master Password Security

JET's security fundamentally depends on password strength. Memory-hard key derivation provides defense against brute-force attacks but cannot overcome weak password entropy.

**Essential Requirements:**
- ✅ Minimum 16 characters with high entropy
- ✅ Cryptographically random generation preferred  
- ✅ Mixed character classes (uppercase, lowercase, digits, symbols)
- ✅ Avoid dictionary words, patterns, or personal information
- ✅ Unique passwords per application/service
- ✅ Secure storage using password managers

**Example High-Entropy Password:**
```
G7$wR9!vZp2#qK8d
```

**Passphrase Alternative:**  
Multiple unrelated words can provide equivalent security with better memorability:
```
correct-horse-battery-staple-9X2m
```


## 🤝 Contributing

JET welcomes community contributions including:
- Cryptographic analysis and security reviews
- Performance optimizations and benchmarks  
- Additional language implementations
- Protocol extensions and algorithm proposals

## 📜 License
MIT License

## :bookmark:Credits
- [Newtonsoft.Json](https://github.com/JamesNK/Newtonsoft.Json) (Json.NET is a popular high-performance JSON framework for .NET)
- [NSec.Cryptography](https://github.com/ektrah/nsec) (A modern and easy-to-use cryptographic library for .NET based on libsodium)