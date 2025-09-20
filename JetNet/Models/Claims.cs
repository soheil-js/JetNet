using Newtonsoft.Json;

namespace JetNet.Models
{
    public class Claims
    {
        [JsonProperty("iss")]
        public string Issuer { get; set; }

        [JsonProperty("sub")]
        public string Subject { get; set; }

        [JsonProperty("aud")]
        public List<string> Audience { get; set; } = new List<string>();
    }
}
