using System.Security.Cryptography;

namespace CACrypto.Commons
{
    public abstract class PermutiveCACryptoKey(byte[] bytes, ToggleDirection toggleDirection) 
        : CryptoKey(bytes, new Dictionary<string, byte[]> {
            { DirectionProperty, new byte[] { (byte)toggleDirection } }
        })
    {
        private static readonly string DirectionProperty = typeof(ToggleDirection).Name;
        public ToggleDirection Direction =>
            (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), ExtraData[DirectionProperty][0]);

        public abstract bool IsValid();
    }
}
