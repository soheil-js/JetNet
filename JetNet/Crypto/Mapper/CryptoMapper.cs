using JetNet.Crypto.Aead;
using JetNet.Models;
using JetNet.Models.Params;

namespace JetNet.Crypto.Mapper
{
    internal static class CryptoMapper
    {
        public static string SymmetricToString(this SymmetricAlgorithm enc)
        {
            return enc switch
            {
                SymmetricAlgorithm.AES_256_GCM => "AES-256-GCM",
                SymmetricAlgorithm.XChaCha20_Poly1305 => "XChaCha20-Poly1305",
                SymmetricAlgorithm.ChaCha20_Poly1305 => "ChaCha20-Poly1305",
                _ => throw new ArgumentOutOfRangeException(nameof(enc), enc, null)
            };
        }

        public static SymmetricAlgorithm SymmetricFromString(string enc)
        {
            return enc switch
            {
                "AES-256-GCM" => SymmetricAlgorithm.AES_256_GCM,
                "XChaCha20-Poly1305" => SymmetricAlgorithm.XChaCha20_Poly1305,
                "ChaCha20-Poly1305" => SymmetricAlgorithm.ChaCha20_Poly1305,
                _ => throw new ArgumentException($"Unknown symmetric algorithm: {enc}")
            };
        }

        public static ICipher ToCipher(this SymmetricAlgorithm enc)
        {
            return enc switch
            {
                SymmetricAlgorithm.AES_256_GCM => new AeadAes256Gcm(),
                SymmetricAlgorithm.XChaCha20_Poly1305 => new AeadChaCha20Poly1305(),
                SymmetricAlgorithm.ChaCha20_Poly1305 => new AeadXChaCha20Poly1305(),
                _ => throw new ArgumentOutOfRangeException(nameof(enc), enc, null)
            };
        }

        public static IKdf ToKdf(this IKdfParams kdfParams)
        {
            return kdfParams switch
            {
                Argon2Params argon2 => KdfFactory.CreateArgon2id(argon2.Parallelism, argon2.Memory, argon2.Iterations),
                ScryptParams scrypt => KdfFactory.CreateScrypt(scrypt.Cost, scrypt.BlockSize, scrypt.Parallelization),
                _ => throw new ArgumentOutOfRangeException(nameof(kdfParams), kdfParams, "Unsupported KDF parameters type.")
            };
        }
    }
}
