using JetNet.Crypto.Base64;
using JetNet.Models;
using JetNet.Models.Params;
using NSec.Cryptography;

namespace JetNet.Crypto.Kdf
{
    internal class KdfArgon2id : IKdf
    {
        private readonly Argon2Parameters _parameters;
        private readonly Argon2id _argon2id;

        public KdfAlgorithm Algorithm => KdfAlgorithm.Argon2id;

        public int MaxCount => _argon2id.MaxCount;

        public int MaxSaltSize => _argon2id.MaxSaltSize;

        public int MinSaltSize => _argon2id.MinSaltSize;

        public KdfArgon2id(int parallelism, long memory, long iterations)
        {
            _parameters = new Argon2Parameters { DegreeOfParallelism = parallelism, MemorySize = memory, NumberOfPasses = iterations };
            _argon2id = PasswordBasedKeyDerivationAlgorithm.Argon2id(_parameters);
        }

        public byte[] GetBytes(string password, ReadOnlySpan<byte> salt, int count)
        {
            return _argon2id.DeriveBytes(password, salt, count);
        }

        public byte[] GetBytes(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int count)
        {
            return _argon2id.DeriveBytes(password, salt, count);
        }

        public IKdfParams GetParams(byte[] salt)
        {
            return new Argon2Params
            {
                memory = _parameters.MemorySize,
                parallelism = _parameters.DegreeOfParallelism,
                iterations = _parameters.NumberOfPasses,
                salt = Base64Url.Encode(salt)
            };
        }
    }
}
