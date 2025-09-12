namespace JetNet.Models
{
    public interface IKdfParams
    {
        string type { get; }
        string salt { get; }
    }
}
