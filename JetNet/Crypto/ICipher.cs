namespace JetNet.Crypto
{
    public interface ICipher
    {
        public int KeySize { get; }
        public int NonceSize { get; }
        public int TagSize { get; }
        

        public (byte[] ciphertext, byte[] tag) Encrypt(byte[] plaintext, byte[] key, byte[] nonce, byte[]? associatedData = default);
        public byte[]? Decrypt(byte[] ciphertext, byte[] tag, byte[] key, byte[] nonce, byte[]? associatedData = default);
    }
}
