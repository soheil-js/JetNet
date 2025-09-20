using JetNet.Crypto.Base64;
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

        public byte[] GetBytes(string password, ReadOnlySpan<byte> salt, int count)
        {
            return _scrypt.DeriveBytes(password, salt, count);
        }

        public byte[] GetBytes(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int count)
        {
            return _scrypt.DeriveBytes(password, salt, count);
        }

        public IKdfParams GetParams(byte[] salt)
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
