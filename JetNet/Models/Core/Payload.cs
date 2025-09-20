using Newtonsoft.Json;

namespace JetNet.Models.Core
{
    internal class Payload
    {
        [JsonProperty("ct")]
        public Data Content { get; set; }

        [JsonProperty("k")]
        public Data Cek { get; set; }
    }
}
