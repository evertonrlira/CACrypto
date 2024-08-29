namespace CACrypto.Commons
{
    public class PermutiveCACryptoKey : CryptoKeyBase
    {
        public ToggleDirection Direction { get; set; }

        public PermutiveCACryptoKey(int[] bits, ToggleDirection toggleDirection) : base(bits)
        {
            Direction = toggleDirection;
        }

        public PermutiveCACryptoKey(byte[] bytes, ToggleDirection toggleDirection) : base(bytes)
        {
            Direction = toggleDirection;
        }
    }
}
