using JetNet;
using JetNet.Crypto;
using SysCrypto = System.Security.Cryptography;


Span<byte> _key = stackalloc byte[32];
var _kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);

// Metadata & Payload
Dictionary<string, string> _metadata = new Dictionary<string, string>()
{
    { "app", "my-application" }
};

var _payload = new
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


while (true)
{
    SysCrypto.RandomNumberGenerator.Fill(_key);
    using var jet = new Jet(_key);
    SysCrypto.CryptographicOperations.ZeroMemory(_key);

    // Encode
    string token = jet.Encode(_payload, _kdf, metadata: _metadata);

    // Decode
    var decoded = jet.Decode<dynamic>(token, ValidateMetadata, ValidateTokenID);

    Console.WriteLine(token); // Encoded token
    Console.WriteLine(); // New line
    Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
    Console.WriteLine(decoded.role); // "admin"

    Console.WriteLine();
    Console.WriteLine("Press any key to continue...");
    Console.ReadKey();
    Console.Clear();
}


// Validate Metadata
bool ValidateMetadata(Dictionary<string, string> metadata)
{
    return true;
}

// Validate token id
bool ValidateTokenID(string id)
{
    return true;
}
