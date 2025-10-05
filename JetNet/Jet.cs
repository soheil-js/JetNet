using JetNet.Crypto;
using JetNet.Crypto.Base;
using JetNet.Crypto.Mapper;
using JetNet.Exceptions;
using JetNet.Models.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Globalization;
using System.Security;
using System.Text;
using SysCrypto = System.Security.Cryptography;

namespace JetNet
{
    public sealed class Jet
    {
        private readonly SecureString _password;

        public Jet(SecureString password)
        {
            _password = password ?? throw new ArgumentNullException(nameof(password));
        }

        public string Encode(object payload, IKdf kdf, SymmetricAlgorithm symmetric = SymmetricAlgorithm.AES_256_GCM, DateTime? expiration = default, DateTime? notBefore = default, Dictionary<string, string>? metadata = default)
        {
            using var rng = SysCrypto.RandomNumberGenerator.Create();
            ICipher cipher = symmetric.ToCipher();

            var now = DateTime.UtcNow;
            var iat = now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var nbf = (notBefore ?? now).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var exp = (expiration ?? now.AddHours(1)).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            // --- Salt ---
            Span<byte> salt = stackalloc byte[kdf.MaxSaltSize];
            rng.GetBytes(salt);

            // --- Header ---
            Header header = new Header
            {
                Symmetric = symmetric.SymmetricToString(),
                Kdf = kdf.GetParams(salt),
                Id = Guid.CreateVersion7(),
                IssuedAt = DateTime.Parse(iat, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal),
                NotBefore = DateTime.Parse(nbf, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal),
                Expiration = DateTime.Parse(exp, null, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal)
            };
            if (metadata != null)
            {
                header.Metadata = new Dictionary<string, string>();
                foreach (var kvp in metadata)
                {
                    header.Metadata[kvp.Key] = kvp.Value;
                }
            }

            string headerJson = CanonicalizeObject(header);
            Span<byte> headerBytes = Encoding.UTF8.GetBytes(headerJson);

            // --- Nonce for CEK ---
            Span<byte> cekNonce = stackalloc byte[cipher.NonceSize];
            rng.GetBytes(cekNonce);

            // --- Content Key (CEK) & Nonce ---
            Span<byte> contentKey = stackalloc byte[cipher.KeySize];
            rng.GetBytes(contentKey);
            Span<byte> contentNonce = stackalloc byte[cipher.NonceSize];
            rng.GetBytes(contentNonce);

            // --- Derived Key ---
            Span<byte> passwordBytes = SecureStringToBytes(_password);
            Span<byte> derivedKey = stackalloc byte[cipher.KeySize];
            kdf.GetBytes(passwordBytes, salt, derivedKey);
            SysCrypto.CryptographicOperations.ZeroMemory(passwordBytes);

            // --- Encrypt ---
            Span<byte> encryptedCek = new byte[cipher.TagSize + contentKey.Length];
            cipher.Encrypt(contentKey, derivedKey, cekNonce, headerBytes, encryptedCek);
            SysCrypto.CryptographicOperations.ZeroMemory(derivedKey);

            // --- Serialize payload ---
            string payloadJson = JsonConvert.SerializeObject(payload);
            Span<byte> payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

            Span<byte> encryptedContent = new byte[cipher.TagSize + payloadBytes.Length];
            cipher.Encrypt(payloadBytes, contentKey, contentNonce, headerBytes, encryptedContent);
            payloadJson = string.Empty;
            SysCrypto.CryptographicOperations.ZeroMemory(payloadBytes);
            SysCrypto.CryptographicOperations.ZeroMemory(contentKey);
            SysCrypto.CryptographicOperations.ZeroMemory(salt);

            // --- Build Payload ---
            Payload jetPayload = new Payload
            {
                Content = new Data()
                {
                    ciphertext = Base64Url.Encode(encryptedContent),
                    nonce = Base64Url.Encode(contentNonce)
                },
                Cek = new Data()
                {
                    ciphertext = Base64Url.Encode(encryptedCek),
                    nonce = Base64Url.Encode(cekNonce)
                }
            };
            string jetPayloadJson = JsonConvert.SerializeObject(jetPayload);
            SysCrypto.CryptographicOperations.ZeroMemory(encryptedContent);
            SysCrypto.CryptographicOperations.ZeroMemory(contentNonce);
            SysCrypto.CryptographicOperations.ZeroMemory(encryptedCek);
            SysCrypto.CryptographicOperations.ZeroMemory(cekNonce);

            return $"{Base64Url.EncodeString(headerJson)}.{Base64Url.EncodeString(jetPayloadJson)}";
        }

        public T Decode<T>(string token, Func<Dictionary<string, string>, bool>? validateMetadata = default, Func<string, bool>? validateTokenId = default)
        {
            string[] parts = token.Split('.');
            if (parts.Length != 2)
                throw new JetTokenException("Invalid JET token format: token must contain exactly one '.' separator.");

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
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to decode JET payload.", ex);
            }

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
                cipher = CryptoMapper.SymmetricFromString(header.Symmetric).ToCipher();
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to initialize cipher from header information.", ex);
            }

            IKdf kdf;
            try
            {
                kdf = header.Kdf.ToKdf();
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to construct KDF from header parameters.", ex);
            }

            Span<byte> salt;
            try
            {
                salt = Base64Url.Decode(header.Kdf.Salt ?? throw new JetTokenException("Salt missing in header KDF parameters."));
            }
            catch (FormatException ex)
            {
                throw new JetTokenException("Invalid base64 format for KDF salt in header.", ex);
            }

            Span<byte> keyForCek = stackalloc byte[cipher.KeySize];
            Span<byte> passwordBytes = SecureStringToBytes(_password);
            try
            {
                kdf.GetBytes(passwordBytes, salt, keyForCek);
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Failed to derive key for CEK using KDF.", ex);
            }
            finally
            {
                SysCrypto.CryptographicOperations.ZeroMemory(passwordBytes);
                SysCrypto.CryptographicOperations.ZeroMemory(salt);
            }

            // --- Decrypt CEK & content ---
            Span<byte> headerBytes = Encoding.UTF8.GetBytes(CanonicalizeObject(header));

            Span<byte> cekCiphertext = Base64Url.Decode(payload.Cek.ciphertext);
            Span<byte> contentCiphertext = Base64Url.Decode(payload.Content.ciphertext);

            Span<byte> keyForContent = stackalloc byte[cekCiphertext.Length - cipher.TagSize];
            Span<byte> decryptedBytes = new byte[contentCiphertext.Length - cipher.TagSize];
            try
            {
                bool isDecryptedCek = cipher.Decrypt(cekCiphertext, keyForCek, Base64Url.Decode(payload.Cek.nonce), headerBytes, keyForContent);
                if (!isDecryptedCek)
                    throw new JetTokenException("Failed to decrypt CEK.");

                bool isDecryptedContent = cipher.Decrypt(contentCiphertext, keyForContent, Base64Url.Decode(payload.Content.nonce), headerBytes, decryptedBytes);
                if (!isDecryptedContent)
                    throw new JetTokenException("Failed to decrypt content.");
            }
            catch (Exception ex)
            {
                throw new JetTokenException("Decryption failed for CEK or payload.", ex);
            }
            finally
            {
                SysCrypto.CryptographicOperations.ZeroMemory(keyForContent);
                SysCrypto.CryptographicOperations.ZeroMemory(contentCiphertext);
                SysCrypto.CryptographicOperations.ZeroMemory(cekCiphertext);
                SysCrypto.CryptographicOperations.ZeroMemory(headerBytes);
            }

            // --- Validate timing ---
            var now = DateTime.UtcNow;
            if (header.NotBefore > now)
                throw new JetTokenException($"Token is not valid yet. NotBefore: {header.NotBefore:u}, Now: {now:u}");
            if (header.Expiration < now)
                throw new JetTokenException($"Token has expired. Expiration: {header.Expiration:u}, Now: {now:u}");

            // --- Validate claims ---
            if (validateMetadata != null && header.Metadata != null)
            {
                if (!validateMetadata(header.Metadata))
                    throw new JetTokenException("Metadata validation failed: token is not authorized or contains invalid metadata.");
            }

            // --- Validate token id ---
            if (validateTokenId != null)
            {
                if (!validateTokenId(header.Id.ToString()))
                    throw new JetTokenException($"Token ID validation failed: {header.Id} is not recognized or revoked.");
            }

            // --- Deserialize payload ---
            try
            {
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
                return JsonConvert.DeserializeObject<T>(decryptedJson) ?? throw new JetTokenException("Failed to deserialize decrypted payload into target type.");
            }
            catch (JsonException ex)
            {
                throw new JetTokenException("Failed to parse decrypted payload JSON.", ex);
            }
            finally
            {
                SysCrypto.CryptographicOperations.ZeroMemory(decryptedBytes);
            }
        }

        private byte[] SecureStringToBytes(SecureString secure)
        {
            if (secure == null) throw new ArgumentNullException(nameof(secure));

            IntPtr unmanagedString = IntPtr.Zero;
            byte[] bytes;
            try
            {
                unmanagedString = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(secure);
                int length = secure.Length;
                bytes = new byte[length * 2];
                System.Runtime.InteropServices.Marshal.Copy(unmanagedString, bytes, 0, bytes.Length);
                return bytes;
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
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
                    NullValueHandling = NullValueHandling.Ignore,
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
