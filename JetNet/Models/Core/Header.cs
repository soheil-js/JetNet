using Newtonsoft.Json;
using JetNet.Models.Converter;


namespace JetNet.Models.Core
{
    internal class Header
    {
        public string symmetric { get; set; }
        [JsonConverter(typeof(ParamsConverter))]
        public IKdfParams kdf { get; set; }
        public Claims? claims { get; set; }
        public Guid id { get; set; }
        public DateTime issuedAt { get; set; }
        public DateTime notBefore { get; set; }
        public DateTime expiration { get; set; }
        public string type { get; set; } = "JET";
    }
}
