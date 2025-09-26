using JetNet.Crypto;
using System.Security;

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
        public void Argon2_Aes256Gcm_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_ChaCha20Poly1305_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Argon2_XChaCha20Poly1305_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, argon2id, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_Aes256Gcm_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.AES_256_GCM);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_ChaCha20Poly1305_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.ChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }

        [Fact]
        public void Scrypt_XChaCha20Poly1305_RoundTripTest()
        {
            SecureString securePassword = new SecureString();
            string plainPassword = "G7$wR9!vZp2#qK8d";
            try
            {
                foreach (char c in plainPassword)
                    securePassword.AppendChar(c);
            }
            finally
            {
                plainPassword = string.Empty;
                securePassword.MakeReadOnly();
            }


            Jet jet = new Jet(securePassword);
            string token = jet.Encode(payload, scrypt, SymmetricAlgorithm.XChaCha20_Poly1305);
            var decoded = jet.Decode<dynamic>(token);

            Assert.Equal(user, (string)decoded.user);
            Assert.Equal(role, (string)decoded.role);
        }
    }
}
