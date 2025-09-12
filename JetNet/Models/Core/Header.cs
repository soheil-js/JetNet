using Newtonsoft.Json;
using JetNet.Models.Converter;


namespace JetNet.Models.Core
{
    internal class Header
    {
        public string symmetric { get; set; }

        [JsonConverter(typeof(ParamsConverter))]
        public IKdfParams kdf { get; set; }

        public string type { get; set; } = "JET";
    }
}
