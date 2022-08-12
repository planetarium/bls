namespace BLSWrapper
{
    public class BLSInvalidSignatureException : BLSException
    {
        public BLSInvalidSignatureException(string message) : base(message)
        {
        }
    }
}
