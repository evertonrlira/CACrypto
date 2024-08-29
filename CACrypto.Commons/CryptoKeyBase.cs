namespace CACrypto.Commons
{
    public abstract class CryptoKeyBase
    {
        public int[] Bits { get; private set; }
        public byte[] Bytes { get; private set; }

        protected CryptoKeyBase(int[] keyBits)
        {
            Bits = keyBits;
            Bytes = Util.BinaryArrayToByteArray(keyBits);
        }

        protected CryptoKeyBase(byte[] keyBytes)
        {
            Bits = Util.ByteArrayToBinaryArray(keyBytes);
            Bytes = keyBytes;
        }

        public void ChangeRandomBit()
        {
            Util.ChangeRandomBit(Bytes, true);
        }
    }
}