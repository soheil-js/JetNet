namespace JetNet.Exceptions
{
    public class JetTokenException : Exception
    {
        public JetTokenException(string message) : base(message) { }
        public JetTokenException(string message, Exception innerException) : base(message, innerException) { }
    }
}
