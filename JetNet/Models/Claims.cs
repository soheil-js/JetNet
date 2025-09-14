using Newtonsoft.Json;

namespace JetNet.Models
{
    public class Claims
    {
        [JsonProperty("issuer")]
        public string Issuer { get; set; }

        [JsonProperty("subject")]
        public string Subject { get; set; }

        [JsonProperty("audience")]
        public List<string> Audience { get; set; } = new List<string>();
    }
}
