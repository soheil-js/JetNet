using JetNet;
using JetNet.Crypto;
using JetNet.Models;

var jet = new Jet("myStrongPassword123!");
var payload = new { user = "Soheil Jashnsaz", role = "admin" };

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);
Claims claims = new Claims()
{
    Issuer = "mycompany.com",
    Subject = "user-authentication",
};
claims.Audience.AddRange("app-web", "app-mobile", "api-service");
string token = jet.Encode(payload, claims, kdf, SymmetricAlgorithm.AES_256_GCM, expiration: DateTime.UtcNow.AddSeconds(10));

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
