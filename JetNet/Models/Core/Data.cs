using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JetNet.Models.Core
{
    internal class Data
    {
        [JsonProperty("c")]
        public string ciphertext { get; set; }

        [JsonProperty("n")]
        public string nonce { get; set; }
    }
}
