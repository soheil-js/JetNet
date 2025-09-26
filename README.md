# 🔐 JET – JSON Encrypted Token

**JET (JSON Encrypted Token)** is a modern cryptographic token format, designed as a secure alternative to **JWT** and **JWE**. Unlike JWT, which often encodes sensitive data without encryption, **JET is encrypted by design** — using strong authenticated symmetric ciphers and memory‑hard key derivation functions.

## 🌍 Why JET?

JWT is widely adopted, but it has several real-world security pitfalls:

- ❌ **Claims not encrypted** — the JWT payload is only Base64URL-encoded, so anyone can read sensitive information.  
- ❌ **Algorithm confusion risks** — security depends on strict algorithm choices; misconfigurations (e.g., `none`, weak HMAC) break guarantees.  
- ❌ **Extra complexity for encryption** — adding JWE/JWS layers to gain confidentiality increases code and the chance of mistakes.  
- ❌ **No built-in replay defense** — preventing token reuse requires extra server-side tracking.  
- ❌ **Key-management burden** — rotating keys and sharing symmetric secrets safely is error-prone.

**JET addresses these problems with a modern, secure design:**

- ✅ **Encrypted payload by default** — all confidential data is protected with strong AEAD ciphers  
  *(AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)*.  
- ✅ **Header integrity with explicit visibility notice** — the header is **authenticated but not encrypted**.  
  Fields like `alg`, `typ`, and optional public `clm` claims remain visible and **must never contain secrets**.  
- ✅ **Per-token, memory-hard key derivation** — Argon2id (or scrypt) derives a unique key with a random salt  
  for every token, slowing brute-force attacks.  
- ✅ **Built-in lifetime & replay protection** — `issuedAt`, `notBefore`, `expiration`, and optional `id` checks  
  prevent reuse and enforce strict validity windows.  
- ✅ **Flexible validation hooks** — easy delegates for custom claim checks and server-side revocation of token IDs.  
- ✅ **Simple, extensible format** — a concise two-part structure (`header:payload`) is easy to parse and extend  
  with custom fields.  
- ✅ **Resistant to classic JWT flaws** — avoids “none” algorithm abuse, key-confusion, and signature-misuse issues.  
- ✅ **Random nonces per token** — guarantees AEAD uniqueness and semantic security even for identical payloads.  
- ✅ **No external JWE/JWS dependency** — reducing complexity and attack surface.

**In short:**  
JET is **secure by default**, minimizes developer mistakes, and provides clear guidance:  
> *Confidential data goes only in the encrypted payload; headers stay public but tamper-proof.*



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
<header_base64url> . <payload_base64url>
```

### Header (JSON, Base64Url-encoded)
Contains algorithm and KDF parameters and **salt** (salt is public):
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
7. Package `payload` JSON carrying both CEK and content AEAD outputs, Base64Url-encode header and payload, join with `.`.

**Decode (simplified):**
1. Split token by `.` and Base64Url-decode header and payload.  
2. Parse header, reconstruct header JSON used as AAD (use the exact decoded header text as AAD).  
3. Recreate KDF using header params and derive key from password + salt.  
4. Decrypt CEK (with derived key, CEK nonce and tag) using header as AAD.  
5. Decrypt content (with CEK, content nonce and tag) using header as AAD.  
6. Parse decrypted payload JSON into claims or application data.

> Implementation note: the reference implementation uses the exact decoded header JSON string as AAD during decryption to guarantee bytewise equality with the AAD used in encryption (canonicalization must be stable if you choose to canonicalize).

## 🛡️ Replay protection

JET uses a unique `jti` (GUID) in each token header as a token identifier.  
While AEAD nonces ensure semantic security, they **do not prevent replay attacks by themselves**.  

To protect against token replay:

- Validate the `jti` (token identifier) server-side or in your application, e.g., keep a short-lived cache of used IDs.  
- Standard claims like `exp` and `nbf`/`iat` (not-before/issued-at) should also be verified to limit the token's valid window.  

This implementation provides `header.jti` and hooks via `validateTokenId` for application-level replay protection. Replay mitigation is enforced by the consuming application rather than the JET library itself.


## 🧪 Example (C#)

```csharp
using JetNet;
using JetNet.Crypto;
using System.Security;

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

// Data
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

// Metadata
Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();
keyValuePairs.Add("app", "my-application");

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Encode
string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM, expiration: DateTime.UtcNow.AddHours(24), metadata: keyValuePairs);

// Decode
var decoded = jet.Decode<dynamic>(token, ValidateMetadata, ValidateTokenID);

Console.WriteLine(token); // Encoded token
Console.WriteLine(); // New line
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"


Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// Validate claims
bool ValidateMetadata(Dictionary<string, string> metadata)
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
eyJlbmMiOiJBRVMtMjU2LUdDTSIsImV4cCI6IjIwMjUtMDktMjdUMTk6MTY6MjcuODJaIiwiaWF0IjoiMjAyNS0wOS0yNlQxOToxNjoyNy44MzNaIiwianRpIjoiMDE5OTg3NzQtOTI0Mi03Yjk2LThhYTktNTFkM2UzOWFmOWNiIiwia2RmIjp7InQiOiJBcmdvbjJpZCIsIm0iOjY1NTM2LCJpIjozLCJwIjoxLCJzIjoiZ0lWQ0dOaUtJRkdCVmlZR3MxSC1xUSJ9LCJtZCI6eyJhcHAiOiJteS1hcHBsaWNhdGlvbiJ9LCJuYmYiOiIyMDI1LTA5LTI2VDE5OjE2OjI3LjgzM1oiLCJ0eXAiOiJKRVQifQ.eyJjdCI6eyJjIjoiaVQxekJkeUVFSzFoVzZ5Q3hQMi1lYkwtOXdVODI2Q2R5eXV4cy1yRlkyTUJVTzhjYW0xb2hNS3NIcGYxUDBYOFNDYTkwa3lBWlVObDRHdHpyUi16Z3lQUUc4S3NCUFFwN01XR0JnQ0NUV1MyRXJqbC1OWlhGbFdKRDNZaUtjUXZYM1BUb2NWbHdiS2hDZFVrTUUyeDNwbUNOZHJhSVhvOFdoZ1Jad0pMYUVYSEZqeXJxamg0MU1qdnZjYlptYUpIeEoyNCIsInQiOiJJNUs1YTAwM2dqRjhWZUxzTWRPN2ZBIiwibiI6Im9sZUtCeXJHMEF3VTJvdF8ifSwiayI6eyJjIjoieXMxd2RteTBUdGw1b0ZTZF9KdE1Xa1I3ZTljM2czYlNiSnhBYmw4NGVuUSIsInQiOiJuUmlxSWs2MHZLMkQ2dHdKeFFpQXBRIiwibiI6IjA1Rll4M0Jyd0hIUHZXSm8ifX0
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