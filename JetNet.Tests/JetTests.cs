using JetNet.Crypto;
using SysCrypto = System.Security.Cryptography;

namespace JetNet.Tests
{
    public class JetTests
    {
        private readonly IKdf argon2id = KdfFactory.CreateArgon2id(1, 65536, 3);
        private readonly IKdf scrypt = KdfFactory.CreateScrypt(32768, 8, 1);
        private readonly string user = "Soheil Jashnsaz";
        private readonly string role = "admin";
        private readonly object payload = new
        {
            user = "Soheil Jashnsaz",
            role = "admin",
            claims = new
            {
                iss = "mycompany.com",
                sub = "user-authentication",
                aud = new string[] { "app-web", "app-mobile", "api-service" }
            }
        };


        [Fact]
        public void Argon2_Aes256Gcm_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_ChaCha20Poly1305_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_XChaCha20Poly1305_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_Aes256Gcm_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_ChaCha20Poly1305_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_XChaCha20Poly1305_Password_RoundTripTest()
        {
            using Jet jet = new Jet("G7$wR9!vZp2#qK8d");
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_Aes256Gcm_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_ChaCha20Poly1305_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_XChaCha20Poly1305_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_Aes256Gcm_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_ChaCha20Poly1305_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_XChaCha20Poly1305_Bytes_RoundTripTest()
        {
            Span<byte> key = stackalloc byte[32];
            SysCrypto.RandomNumberGenerator.Fill(key);
            using Jet jet = new Jet(key);
            SysCrypto.CryptographicOperations.ZeroMemory(key);

            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }
    }
}
