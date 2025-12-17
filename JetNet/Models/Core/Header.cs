using Newtonsoft.Json;
using JetNet.Models.Converter;


namespace JetNet.Models.Core
{
    internal class Header
    {
        [JsonProperty("enc")]
        public string Symmetric { get; set; }

        [JsonConverter(typeof(ParamsConverter))]
        [JsonProperty("kdf")]
        public IKdfParams Kdf { get; set; }

        [JsonProperty("md")]
        public Dictionary<string, string>? Metadata { get; set; }

        [JsonProperty("jti")]
        public Guid Id { get; set; }

        [JsonProperty("iat")]
        public long IssuedAt { get; set; }

        [JsonProperty("nbf")]
        public long NotBefore { get; set; }

        [JsonProperty("exp")]
        public long Expiration { get; set; }

        [JsonProperty("typ")]
        public string Type { get; set; } = "JET";
    }
}
