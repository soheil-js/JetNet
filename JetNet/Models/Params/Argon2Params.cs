namespace JetNet.Models.Params
{
    internal class Argon2Params : IKdfParams
    {
        public string type => "Argon2id";
        public long memory { get; set; }
        public long iterations { get; set; }
        public int parallelism { get; set; }
        public string salt { get; set; }
    }
}
