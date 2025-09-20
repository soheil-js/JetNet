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

        [JsonProperty("clm")]
        public Claims? Claims { get; set; }

        [JsonProperty("jti")]
        public Guid Id { get; set; }

        [JsonProperty("iat")]
        public DateTime IssuedAt { get; set; }

        [JsonProperty("nbf")]
        public DateTime NotBefore { get; set; }

        [JsonProperty("exp")]
        public DateTime Expiration { get; set; }

        [JsonProperty("typ")]
        public string Type { get; set; } = "JET";
    }
}
