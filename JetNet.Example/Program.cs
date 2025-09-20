using JetNet;
using JetNet.Crypto;
using JetNet.Models;
using System.Security;

using var securePassword = new SecureString();
string plainPassword = "myStrongPassword123!";
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

var jet = new Jet(securePassword);

// Data
var payload = new { user = "Soheil Jashnsaz", role = "admin" };
Claims claims = new Claims()
{
    Issuer = "mycompany.com",
    Subject = "user-authentication",
};
claims.Audience.AddRange("app-web", "app-mobile", "api-service");

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Encode
string token = jet.Encode(payload, claims, kdf, SymmetricAlgorithm.AES_256_GCM, expiration: DateTime.UtcNow.AddHours(24));

// Decode
var decoded = jet.Decode<dynamic>(token, ValidateClaims, ValidateTokenID);

Console.WriteLine(token); // Encoded token
Console.WriteLine(); // New line
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"


Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// Validate claims
bool ValidateClaims(Claims claims)
{
    return true;
}

// Validate token id
bool ValidateTokenID(string id)
{
    return true;
}
