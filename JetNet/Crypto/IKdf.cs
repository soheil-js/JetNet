using JetNet.Models;

namespace JetNet.Crypto
{
    public interface IKdf
    {
        KdfAlgorithm Algorithm { get; }
        int MaxCount { get; }
        int MaxSaltSize { get; }
        int MinSaltSize { get; }

        void GetBytes(string password, ReadOnlySpan<byte> salt, Span<byte> bytes);
        void GetBytes(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, Span<byte> bytes);
        IKdfParams GetParams(Span<byte> salt);
    }
}
