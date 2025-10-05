using NSec.Cryptography;

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

        public bool Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext)
        {
            if (key.IsEmpty)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != _symmetric.KeySize)
                throw new ArgumentException($"AES-256 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce.IsEmpty)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"AES-256-GCM nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

            if (plaintext.IsEmpty)
                throw new ArgumentNullException(nameof(plaintext));

            try
            {
                using var k = Key.Import(_symmetric, key, KeyBlobFormat.RawSymmetricKey);
                _symmetric.Encrypt(k, nonce, associatedData, plaintext, ciphertext);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> plaintext)
        {
            if (key.IsEmpty)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != _symmetric.KeySize)
                throw new ArgumentException($"AES-256 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce.IsEmpty)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"AES-256-GCM nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

            if (ciphertext.IsEmpty)
                throw new ArgumentNullException(nameof(ciphertext));

            try
            {
                using var k = Key.Import(_symmetric, key, KeyBlobFormat.RawSymmetricKey);
                return _symmetric.Decrypt(k, nonce, associatedData, ciphertext, plaintext);
            }
            catch
            {
                return false;
            }
        }
    }
}