namespace CACrypto.Commons
{
    public class CryptoKey(byte[] keyBytes, Dictionary<string, byte[]>? extraData = null)
    {
        public byte[] Bytes { get; init; } = keyBytes;
        public int[] Bits => Util.ByteArrayToBinaryArray(Bytes);
        public Dictionary<string, byte[]> ExtraData { get; init; } = extraData ?? [];

        public virtual CryptoKey ChangeRandomBit()
        {
            var newBytes = Util.ChangeRandomBit(Bytes);
            return new CryptoKey(newBytes, ExtraData);
        }
    }
}