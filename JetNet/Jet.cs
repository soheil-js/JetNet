using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using JetNet.Crypto;
using JetNet.Crypto.Base64;
using JetNet.Crypto.Mapper;
using JetNet.Exceptions;
using JetNet.Models.Core;

namespace JetNet
{
    public sealed class Jet
    {
        private readonly string _password;

        public Jet(string password)
        {
            _password = password;
        }

        public string Encode(object payload, IKdf kdf, SymmetricAlgorithm symmetric = SymmetricAlgorithm.AES_256_GCM)
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

            // --- Header ---
            Header header = new Header
            {
                symmetric = symmetric.SymmetricToString(),
                kdf = kdf.GetParams(salt),
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

        public T Decode<T>(string token)
        {
            var parts = token.Split(':');
            if (parts.Length != 2)
                throw new JetTokenException("Invalid JET token format.");

            // --- Decode header ---
            string headerJson = Base64Url.DecodeToString(parts[0]);
            Header header = JsonConvert.DeserializeObject<Header>(headerJson) ?? throw new JetTokenException("Invalid header");

            ICipher cipher = CryptoMapper.SymmetricFromString(header.symmetric).ToCipher();

            byte[] salt = Base64Url.Decode(header.kdf.salt ?? throw new JetTokenException("Salt missing in header"));

            IKdf kdf = header.kdf.ToKdf();
            byte[] keyForCek = kdf.GetBytes(_password, salt, cipher.KeySize);

            // --- Decode payload ---
            string payloadJson = Base64Url.DecodeToString(parts[1]);
            var payload = JsonConvert.DeserializeObject<Payload>(payloadJson) ?? throw new JetTokenException("Invalid payload");

            byte[] cekCiphertext = Base64Url.Decode(payload.cek.ciphertext);
            byte[] cekTag = Base64Url.Decode(payload.cek.tag);
            byte[] cekNonce = Base64Url.Decode(payload.cek.nonce);

            byte[] contentCiphertext = Base64Url.Decode(payload.content.ciphertext);
            byte[] contentTag = Base64Url.Decode(payload.content.tag);
            byte[] contentNonce = Base64Url.Decode(payload.content.nonce);

            // --- Decrypt ---
            byte[] headerBytes = Encoding.UTF8.GetBytes(CanonicalizeObject(header));
            byte[] keyForContent = cipher.Decrypt(cekCiphertext, cekTag, keyForCek, cekNonce, headerBytes) ?? throw new JetTokenException("Failed to decrypt CEK");
            byte[] decryptedBytes = cipher.Decrypt(contentCiphertext, contentTag, keyForContent, contentNonce, headerBytes) ?? throw new JetTokenException("Failed to decrypt content");

            string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
            return JsonConvert.DeserializeObject<T>(decryptedJson) ?? throw new JetTokenException("Failed to deserialize payload");
        }

        // helper: canonicalize JSON by sorting property names (shallow)
        private string CanonicalizeObject(object obj)
        {
            var jObj = JObject.FromObject(obj);
            var ordered = new JObject(jObj.Properties().OrderBy(p => p.Name));
            return ordered.ToString(Formatting.None);
        }
    }
}
