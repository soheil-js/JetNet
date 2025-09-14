using JetNet.Crypto;

namespace JetNet.Tests
{
    public class JetTests
    {
        private readonly Jet jet = new Jet("myStrongPassword123!");
        private readonly IKdf argon2id = KdfFactory.CreateArgon2id(1, 65536, 3);
        private readonly IKdf scrypt = KdfFactory.CreateScrypt(32768, 8, 1);
        private readonly object payload = new { user = "Soheil Jashnsaz", role = "admin" };
        private readonly string user = "Soheil Jashnsaz";
        private readonly string role = "admin";


        [Fact]
        public void Argon2_Aes256Gcm_RoundTripTest()
        {
            string token = jet.Encode(payload, null, argon2id, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_ChaCha20Poly1305_RoundTripTest()
        {
            
            string token = jet.Encode(payload, null, argon2id, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_XChaCha20Poly1305_RoundTripTest()
        {
            string token = jet.Encode(payload, null, argon2id, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_Aes256Gcm_RoundTripTest()
        {
            string token = jet.Encode(payload, null, scrypt, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_ChaCha20Poly1305_RoundTripTest()
        {
            string token = jet.Encode(payload, null, scrypt, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_XChaCha20Poly1305_RoundTripTest()
        {
            string token = jet.Encode(payload, null, scrypt, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }
    }
}
