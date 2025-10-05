namespace JetNet.Crypto
{
    public interface ICipher
    {
        public int KeySize { get; }
        public int NonceSize { get; }
        public int TagSize { get; }
        

        public bool Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext);
        public bool Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, Span<byte> plaintext);
    }
}
