using Newtonsoft.Json;

namespace JetNet.Models.Params
{
    internal class ScryptParams : IKdfParams
    {
        [JsonProperty("t")]
        public string Type => "Scrypt";

        [JsonProperty("c")]
        public long Cost { get; set; }

        [JsonProperty("b")]
        public int BlockSize { get; set; }

        [JsonProperty("p")]
        public int Parallelization { get; set; }

        [JsonProperty("s")]
        public string Salt { get; set; }
    }
}
