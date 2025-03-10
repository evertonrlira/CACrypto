using System.Buffers;

namespace CACrypto.Commons
{
    public abstract class PermutiveCACryptoKey(byte[] bytes, ToggleDirection toggleDirection)
        : CryptoKey(bytes, new Dictionary<string, byte[]> {
            { DirectionProperty, new byte[] { (byte)toggleDirection } }
        })
    {
        private static readonly string DirectionProperty = typeof(ToggleDirection).Name;
        private static readonly double MinimumValidKeyEntropy = 0.75;

        public ToggleDirection Direction =>
            (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), ExtraData[DirectionProperty][0]);

        public abstract bool IsValid();

        protected static bool IsValid(Span<byte> keyBytes)
        {
            var keyBitsLength = 8 * keyBytes.Length;
            var binaryArray = ArrayPool<int>.Shared.Rent(keyBitsLength);
            Util.ByteArrayToBinaryArray(keyBytes, binaryArray);
            var isValid = Util.SpatialEntropyCalculusForBinary(binaryArray.AsSpan(0, keyBitsLength)) > MinimumValidKeyEntropy;
            ArrayPool<int>.Shared.Return(binaryArray, true);
            return isValid;
        }
    }
}
