using JetNet.Crypto.Base;
using JetNet.Models;
using JetNet.Models.Params;
using NSec.Cryptography;

namespace JetNet.Crypto.Kdf
{
    internal class KdfScrypt : IKdf
    {
        private readonly ScryptParameters _parameters;
        private readonly Scrypt _scrypt;

        public KdfAlgorithm Algorithm => KdfAlgorithm.Scrypt;

        public int MaxCount => _scrypt.MaxCount;

        public int MaxSaltSize => _scrypt.MaxSaltSize;

        public int MinSaltSize => _scrypt.MinSaltSize;

        public KdfScrypt(long cost, int blockSize, int parallelization)
        {
            _parameters = new ScryptParameters { Cost = cost, BlockSize = blockSize, Parallelization = parallelization };
            _scrypt = PasswordBasedKeyDerivationAlgorithm.Scrypt(_parameters);
        }

        public void GetBytes(string password, ReadOnlySpan<byte> salt, Span<byte> bytes)
        {
            _scrypt.DeriveBytes(password, salt, bytes);
        }

        public void GetBytes(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> bytes)
        {
            _scrypt.DeriveBytes(password, salt, bytes);
        }

        public IKdfParams GetParams(Span<byte> salt)
        {
            return new ScryptParams
            {
                Cost = _parameters.Cost,
                BlockSize = _parameters.BlockSize,
                Parallelization = _parameters.Parallelization,
                Salt = Base64Url.Encode(salt)
            };
        }
    }
}
