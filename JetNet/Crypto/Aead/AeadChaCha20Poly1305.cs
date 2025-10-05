using NSec.Cryptography;

namespace JetNet.Crypto.Aead
{
    internal class AeadChaCha20Poly1305 : ICipher
    {
        private readonly ChaCha20Poly1305 _symmetric;

        public int KeySize => _symmetric.KeySize;
        public int NonceSize => _symmetric.NonceSize;
        public int TagSize => _symmetric.TagSize;

        public AeadChaCha20Poly1305()
        {
            _symmetric = AeadAlgorithm.ChaCha20Poly1305;
        }

        public bool Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext)
        {
            if (key.IsEmpty)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != _symmetric.KeySize)
                throw new ArgumentException($"ChaCha20 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce.IsEmpty)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"ChaCha20 nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

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
                throw new ArgumentException($"ChaCha20 key must be {_symmetric.KeySize} bytes.", nameof(key));

            if (nonce.IsEmpty)
                throw new ArgumentNullException(nameof(nonce));

            if (nonce.Length != _symmetric.NonceSize)
                throw new ArgumentException($"ChaCha20 nonce must be {_symmetric.NonceSize} bytes.", nameof(nonce));

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
