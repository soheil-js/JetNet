using Newtonsoft.Json;

namespace JetNet.Models.Params
{
    internal class Argon2Params : IKdfParams
    {
        [JsonProperty("t")]
        public string Type => "Argon2id";

        [JsonProperty("m")]
        public long Memory { get; set; }

        [JsonProperty("i")]
        public long Iterations { get; set; }

        [JsonProperty("p")]
        public int Parallelism { get; set; }

        [JsonProperty("s")]
        public string Salt { get; set; }
    }
}
