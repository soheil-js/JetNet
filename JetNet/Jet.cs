using System.Text;
using JetNet.Crypto;
using JetNet.Crypto.Base64;
using JetNet.Crypto.Mapper;
using JetNet.Exceptions;
using JetNet.Models;
using JetNet.Models.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JetNet
{
    public sealed class Jet
    {
        private readonly string _password;

        public Jet(string password)
        {
            _password = password;
        }

        public string Encode(object payload, Claims? claims, IKdf kdf, SymmetricAlgorithm symmetric = SymmetricAlgorithm.AES_256_GCM, DateTime? expiration = default, DateTime? notBefore = default)
        {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            ICipher cipher = symmetric.ToCipher();

            // --- Serialize payload ---
            string payloadJson = JsonConvert.SerializeObject(payload);
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

            // --- Salt & Derived Key ---
            byte[] salt = new byte[kdf.MaxSaltSize];
            rng.GetBytes(salt);
            byte[] derivedKey = kdf.GetBytes(_password, salt, cipher.KeySize);

            // --- Nonce for CEK ---
            byte[] cekNonce = new byte[cipher.NonceSize];
            rng.GetBytes(cekNonce);

            // --- Content Key (CEK) & Nonce ---
            byte[] contentKey = new byte[cipher.KeySize];
            rng.GetBytes(contentKey);
            byte[] contentNonce = new byte[cipher.NonceSize];
            rng.GetBytes(contentNonce);

            var now = DateTime.UtcNow;
            var nbf = notBefore ?? now;
            var exp = expiration ?? DateTime.UtcNow.AddHours(1);

            // --- Header ---
            Header header = new Header
            {
                symmetric = symmetric.SymmetricToString(),
                kdf = kdf.GetParams(salt),
                id = Guid.NewGuid(),
                claims = claims,
                issuedAt = now,
                notBefore = nbf,
                expiration = exp
            };
            string headerJson = CanonicalizeObject(header);
            byte[] headerBytes = Encoding.UTF8.GetBytes(headerJson);

            // --- Encrypt ---
            var encryptedCek = cipher.Encrypt(contentKey, derivedKey, cekNonce, headerBytes);
            var encryptedContent = cipher.Encrypt(payloadBytes, contentKey, contentNonce, headerBytes);

            // --- Build Payload ---
            Payload jetPayload = new Payload
            {
                content = new Data()
                {
                    ciphertext = Base64Url.Encode(encryptedContent.ciphertext),
                    tag = Base64Url.Encode(encryptedContent.tag),
                    nonce = Base64Url.Encode(contentNonce)
                },
                cek = new Data()
                {
                    ciphertext = Base64Url.Encode(encryptedCek.ciphertext),
                    tag = Base64Url.Encode(encryptedCek.tag),
                    nonce = Base64Url.Encode(cekNonce)
                }
            };
            string jetPayloadJson = JsonConvert.SerializeObject(jetPayload);

            return $"{Base64Url.EncodeString(headerJson)}:{Base64Url.EncodeString(jetPayloadJson)}";
        }

        public T Decode<T>(string token, Func<Claims, bool>? validateClaims = default, Func<string, bool>? validateTokenId = default)
        {
            string[] parts = token.Split(':');
            if (parts.Length != 2)
                throw new JetTokenException("Invalid JET token format: token must contain exactly one ':' separator.");

            // --- Decode header ---
            Header header;
            try
            {
                header = JsonConvert.DeserializeObject<Header>(Base64Url.DecodeToString(parts[0])) ?? throw new JetTokenException("Decoded header is null.");
            }
            catch (JsonException ex)
            {
                throw new JetTokenException("Failed to deserialize JET header. Possibly malformed JSON.", ex);
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to decode JET header.", ex);
            }

            // --- Cipher & KDF ---
            ICipher cipher;
            try
            {
                cipher = CryptoMapper.SymmetricFromString(header.symmetric).ToCipher();
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to initialize cipher from header information.", ex);
            }

            byte[] salt;
            try
            {
                salt = Base64Url.Decode(header.kdf.salt ?? throw new JetTokenException("Salt missing in header KDF parameters."));
            }
            catch (FormatException ex)
            {
                throw new JetTokenException("Invalid base64 format for KDF salt in header.", ex);
            }

            IKdf kdf;
            try
            {
                kdf = header.kdf.ToKdf();
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to construct KDF from header parameters.", ex);
            }

            byte[] keyForCek;
            try
            {
                keyForCek = kdf.GetBytes(_password, salt, cipher.KeySize);
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to derive key for CEK using KDF.", ex);
            }

            // --- Decode payload ---
            Payload payload;
            try
            {
                string payloadJson = Base64Url.DecodeToString(parts[1]);
                payload = JsonConvert.DeserializeObject<Payload>(payloadJson) ?? throw new JetTokenException("Decoded payload is null.");
            }
            catch (JsonException ex)
            {
                throw new JetTokenException("Failed to deserialize JET payload. Possibly malformed JSON.", ex);
            }
            catch (FormatException ex)
            {
                throw new JetTokenException("Invalid base64 format for payload.", ex);
            }

            // --- Decrypt CEK & content ---
            byte[] keyForContent;
            byte[] decryptedBytes;
            try
            {
                byte[] headerBytes = Encoding.UTF8.GetBytes(CanonicalizeObject(header));
                keyForContent = cipher.Decrypt(
                    Base64Url.Decode(payload.cek.ciphertext),
                    Base64Url.Decode(payload.cek.tag),
                    keyForCek,
                    Base64Url.Decode(payload.cek.nonce),
                    headerBytes
                ) ?? throw new JetTokenException("Failed to decrypt CEK.");

                decryptedBytes = cipher.Decrypt(
                    Base64Url.Decode(payload.content.ciphertext),
                    Base64Url.Decode(payload.content.tag),
                    keyForContent,
                    Base64Url.Decode(payload.content.nonce),
                    headerBytes
                ) ?? throw new JetTokenException("Failed to decrypt content.");
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Decryption failed for CEK or payload.", ex);
            }

            // --- Validate timing ---
            var now = DateTime.UtcNow;
            if (header.notBefore > now)
                throw new JetTokenException($"Token is not valid yet. NotBefore: {header.notBefore:u}, Now: {now:u}");
            if (header.expiration < now)
                throw new JetTokenException($"Token has expired. Expiration: {header.expiration:u}, Now: {now:u}");

            // --- Validate claims ---
            if (validateClaims != null && header.claims != null)
            {
                if (!validateClaims(header.claims))
                    throw new JetTokenException("Claims validation failed: token is not authorized or contains invalid claims.");
            }

            // --- Validate token id ---
            if (validateTokenId != null)
            {
                if (!validateTokenId(header.id.ToString()))
                    throw new JetTokenException($"Token ID validation failed: {header.id} is not recognized or revoked.");
            }

            // --- Deserialize payload ---
            try
            {
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
                return JsonConvert.DeserializeObject<T>(decryptedJson)
                       ?? throw new JetTokenException("Failed to deserialize decrypted payload into target type.");
            }
            catch (JsonException ex)
            {
                throw new JetTokenException("Failed to parse decrypted payload JSON.", ex);
            }
        }

        private string CanonicalizeObject(object obj)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj), "Cannot canonicalize a null object.");

            try
            {
                var jObj = JObject.FromObject(obj, new JsonSerializer
                {
                    NullValueHandling = NullValueHandling.Include,
                    DefaultValueHandling = DefaultValueHandling.Include
                });

                var ordered = new JObject(jObj.Properties().OrderBy(p => p.Name, StringComparer.Ordinal));

                return ordered.ToString(Formatting.None);
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to canonicalize object for JET header or AAD.", ex);
            }
        }
    }
}
