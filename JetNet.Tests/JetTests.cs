using JetNet.Crypto;

namespace JetNet.Tests
{
    public class JetTests
    {
        private readonly Jet jet = new Jet("myStrongPassword123!");
        private readonly object payload = new { user = "Soheil Jashnsaz", role = "admin" };
        private readonly string user = "Soheil Jashnsaz";
        private readonly string role = "admin";


        [Fact]
        public void Argon2_Aes256Gcm_RoundTripTest()
        {
            var kdf = KdfFactory.CreateArgon2id(1, 65536, 3);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_ChaCha20Poly1305_RoundTripTest()
        {
            var kdf = KdfFactory.CreateArgon2id(1, 65536, 3);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_XChaCha20Poly1305_RoundTripTest()
        {
            var kdf = KdfFactory.CreateArgon2id(1, 65536, 3);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_Aes256Gcm_RoundTripTest()
        {
            var kdf = KdfFactory.CreateScrypt(32768, 8, 1);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_ChaCha20Poly1305_RoundTripTest()
        {
            var kdf = KdfFactory.CreateScrypt(32768, 8, 1);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_XChaCha20Poly1305_RoundTripTest()
        {
            var kdf = KdfFactory.CreateScrypt(32768, 8, 1);
            string token = jet.Encode(payload, kdf, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }
    }
}
