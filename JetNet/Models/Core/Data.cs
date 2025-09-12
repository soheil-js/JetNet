using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JetNet.Models.Core
{
    internal class Data
    {
        public string ciphertext { get; set; }
        public string tag { get; set; }
        public string nonce { get; set; }
    }
}
