using JetNet.Models;

namespace JetNet.Crypto
{
    public interface IKdf
    {
        KdfAlgorithm Algorithm { get; }
        int MaxCount { get; }
        int MaxSaltSize { get; }
        int MinSaltSize { get; }

        byte[] GetBytes(string password, ReadOnlySpan<byte> salt, int count);
        byte[] GetBytes(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int count);
        IKdfParams GetParams(byte[] salt);
    }
}
