namespace JetNet.Models.Params
{
    internal class ScryptParams : IKdfParams
    {
        public string type => "Scrypt";
        public long cost { get; set; }
        public int blockSize { get; set; }
        public int parallelization { get; set; }
        public string salt { get; set; }
    }
}
