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
<header_base64url>.<payload_base64url>
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
        "s": "j6K93DzEKt5dTYbA8lF2gw"
    },
	"md": {
        "app": "my-application"
    },
	"jti": "019b2df2-9778-743c-8d68-941b72a5f08b",
	"iat": 1766002431,
	"nbf": 1766002431,
    "exp": 1766006031,
    "typ": "JET"
}
```
**⚠️ Security Notice:** Header fields are authenticated but **not encrypted**. Never include sensitive data in headers or metadata.

### Payload (JSON, Base64Url-encoded)
Contains two AEAD outputs: the encrypted content and the encrypted CEK (Content Encryption Key):
```json
{
    "ct": {
        "c": "U4D3Dwydw5pBimccuMBVentQcECqiV2YLxyLaPxnqkJw5D4Ex9EflxhUvheqg0V-zBYlGxJ1MBSWQIsV05T6K00dnJKDgK2rBbVPxTBfR5WcAMQPpFot6Eolm2EJHOd4lFPsr-JoZu9Xag7xOBfKHmYIL766BBAwUUGQmPf6bR9B8qVip6QZCAdqtPjppRmAl-QgvigzjlUNL24Cz1fVwO4Mww",
        "n": "CFHk6NqPPOaYmTcz"
    },
    "k": {
        "c": "8sKBYXTtbTFD3SKqzIEIByyWOr9mUtBTHqRMW3h-qtnsBOPuYj6IKavo757DPh2_",
        "n": "KgKh0LRev7b5Cf9v"
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
using SysCrypto = System.Security.Cryptography;

// Secure password handling
Span<byte> _key = stackalloc byte[32];
SysCrypto.RandomNumberGenerator.Fill(_key);
using var jet = new Jet(_key);
SysCrypto.CryptographicOperations.ZeroMemory(_key);

// Sensitive payload data
var _payload = new
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
Dictionary<string, string> _metadata = new Dictionary<string, string>()
{
    { "app", "my-application" }
};


// Strong key derivation configuration
var _kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Create encrypted token
string _token = jet.Encode(_payload, _kdf, metadata: _metadata);

// Decode with validation
var _decoded = jet.Decode<dynamic>(_token, ValidateMetadata, ValidateTokenID);

Console.WriteLine("Token created successfully");
Console.WriteLine($"User: {_decoded.user}");
Console.WriteLine($"Role: {_decoded.role}");

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
eyJlbmMiOiJBRVMtMjU2LUdDTSIsImV4cCI6MTc2NjAwNjAzMSwiaWF0IjoxNzY2MDAyNDMxLCJqdGkiOiIwMTliMmRmMi05Nzc4LTc0M2MtOGQ2OC05NDFiNzJhNWYwOGIiLCJrZGYiOnsidCI6IkFyZ29uMmlkIiwibSI6NjU1MzYsImkiOjMsInAiOjEsInMiOiJqNks5M0R6RUt0NWRUWWJBOGxGMmd3In0sIm1kIjp7ImFwcCI6Im15LWFwcGxpY2F0aW9uIn0sIm5iZiI6MTc2NjAwMjQzMSwidHlwIjoiSkVUIn0.eyJjdCI6eyJjIjoiVTREM0R3eWR3NXBCaW1jY3VNQlZlbnRRY0VDcWlWMllMeHlMYVB4bnFrSnc1RDRFeDlFZmx4aFV2aGVxZzBWLXpCWWxHeEoxTUJTV1FJc1YwNVQ2SzAwZG5KS0RnSzJyQmJWUHhUQmZSNVdjQU1RUHBGb3Q2RW9sbTJFSkhPZDRsRlBzci1Kb1p1OVhhZzd4T0JmS0htWUlMNzY2QkJBd1VVR1FtUGY2YlI5QjhxVmlwNlFaQ0FkcXRQanBwUm1BbC1RZ3ZpZ3pqbFVOTDI0Q3oxZlZ3TzRNd3ciLCJuIjoiQ0ZIazZOcVBQT2FZbVRjeiJ9LCJrIjp7ImMiOiI4c0tCWVhUdGJURkQzU0txeklFSUJ5eVdPcjltVXRCVEhxUk1XM2gtcXRuc0JPUHVZajZJS2F2bzc1N0RQaDJfIiwibiI6IktnS2gwTFJldjdiNUNmOXYifX0
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

## 🔑 Master Key / Password Security

JET supports two input modes for authentication: **byte-based master keys** and **string-based passwords**.  
While both are secure, **byte arrays are strongly recommended** for high-security applications, as they allow full control over memory lifecycle and zeroization.

### 🧩 Option 1: Master Key (Byte Array) — *Recommended*
The most secure way to initialize JET is by providing a raw byte sequence.  
This approach avoids managed strings, prevents GC exposure, and enables direct integration with HSMs or key vaults.

**Example (secure memory use):**
```csharp
Span<byte> key = stackalloc byte[32];
RandomNumberGenerator.Fill(key);
using var jet = new Jet(key);
CryptographicOperations.ZeroMemory(key);
```

**Advantages:**
- 🧠 Never exposes secrets in managed memory  
- ⚡ Enables direct use of hardware or derived session keys  
- 🧩 Compatible with secure key lifecycle management  
- 🧹 Can be safely wiped using `CryptographicOperations.ZeroMemory`


### 🔐 Option 2: Password (String)
For convenience, JET also accepts traditional passwords as UTF-8 strings.  
Internally, the string is converted to bytes, used to derive the encryption key, and then **immediately wiped from memory**.

**Example:**
```csharp
using var jet = new Jet("CorrectHorseBatteryStaple9X2m");
```

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

### ⚖️ Summary
| Mode | Type | Security | Use Case |
|------|------|-----------|-----------|
| **Master Key (Byte Array)** | `ReadOnlySpan<byte>` | 🔒 Highest | Cryptographic systems, secure sessions, HSM integration |
| **Password (String)** | `string` | 🟡 Moderate | User-entered credentials, UI-based applications |


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