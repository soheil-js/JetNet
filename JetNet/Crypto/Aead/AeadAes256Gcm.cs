using NSec.Cryptography;
using System.Security.Cryptography;

namespace JetNet.Crypto.Aead
{
    public class AeadAes256Gcm : ICipher
    {
        private readonly Aes256Gcm _symmetric;

        public int KeySize => _symmetric.KeySize;
        public int NonceSize => _symmetric.NonceSize;
        public int TagSize => _symmetric.TagSize;

        public AeadAes256Gcm()
        {
            _symmetric = AeadAlgorithm.Aes256Gcm;
        }

        public (byte[] ciphertext, byte[] tag) Encrypt(
            byte[] plaintext,
            byte[] key,
            byte[] nonce,
            byte[]? associatedData = default)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != _symmetric.KeySize)
                throw new ArgumentException($"AES-256 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"AES-256-GCM nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            associatedData ??= Array.Empty<byte>();

            using var k = Key.Import(_symmetric, key, KeyBlobFormat.RawSymmetricKey);
            var output = _symmetric.Encrypt(k, nonce, associatedData, plaintext);

            byte[] ciphertext = new byte[output.Length - _symmetric.TagSize];
            byte[] tag = new byte[_symmetric.TagSize];
            Array.Copy(output, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(output, ciphertext.Length, tag, 0, _symmetric.TagSize);

            return (ciphertext, tag);
        }

        public byte[]? Decrypt(
            byte[] ciphertext,
            byte[] tag,
            byte[] key,
            byte[] nonce,
            byte[]? associatedData = default)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != _symmetric.KeySize)
                throw new ArgumentException($"AES-256 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce == null)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"AES-256-GCM nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (tag == null)
                throw new ArgumentNullException(nameof(tag));

            if (tag.Length != _symmetric.TagSize)
                throw new ArgumentException($"AES-256-GCM tag must be {_symmetric.TagSize} bytes.", nameof(tag));

            associatedData ??= Array.Empty<byte>();

            using var k = Key.Import(_symmetric, key, KeyBlobFormat.RawSymmetricKey);

            var combined = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, combined, 0, ciphertext.Length);
            Array.Copy(tag, 0, combined, ciphertext.Length, tag.Length);

            try
            {
                return _symmetric.Decrypt(k, nonce, associatedData, combined);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }
}
