using JetNet;
using JetNet.Crypto;

var jet = new Jet("myStrongPassword123!");
var payload = new { user = "Soheil Jashnsaz", role = "admin" };

// Choose Argon2id + AES-256-GCM
var kdf = KdfFactory.CreateArgon2id(parallelism: 1, memory: 65536, iterations: 3);
string token = jet.Encode(payload, kdf, SymmetricAlgorithm.AES_256_GCM);

// Decode
var decoded = jet.Decode<dynamic>(token);

Console.WriteLine(token); // Encoded token
Console.WriteLine(); // New line
Console.WriteLine(decoded.user); // "Soheil Jashnsaz"
Console.WriteLine(decoded.role); // "admin"


Console.WriteLine();
Console.WriteLine("Press any key to exit...");
Console.ReadKey();