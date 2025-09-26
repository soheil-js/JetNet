using JetNet;
using JetNet.Crypto;
using System.Security;

using var securePassword = new SecureString();
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

var jet = new Jet(securePassword);

// Data
var payload = new
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

// Metadata
Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();
keyValuePairs.Add("app", "my-application");

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Encode
string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM, expiration: DateTime.UtcNow.AddHours(24), metadata: keyValuePairs);

// Decode
var decoded = jet.Decode<dynamic>(token, ValidateMetadata, ValidateTokenID);

Console.WriteLine(token); // Encoded token
Console.WriteLine(); // New line
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"


Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();

// Validate claims
bool ValidateMetadata(Dictionary<string, string> metadata)
{
    return true;
}

// Validate token id
bool ValidateTokenID(string id)
{
    return true;
}
