using JetNet.Crypto.Kdf;

namespace JetNet.Crypto
{
    public static class KdfFactory
    {
        public static IKdf CreateArgon2id(int parallelism, long memory, long iterations)
        {
            return new KdfArgon2id(parallelism, memory, iterations);
        }

        public static IKdf CreateScrypt(long cost, int blockSize, int parallelization)
        {
            return new KdfScrypt(cost, blockSize, parallelization);
        }
    }
}
