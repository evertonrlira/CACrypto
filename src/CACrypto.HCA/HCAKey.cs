using CACrypto.Commons;

namespace CACrypto.HCA;

public class HCAKey : PermutiveCACryptoKey
{
    public HCAKey(int[] keyBits, ToggleDirection toggleDirection) : base(Util.BinaryArrayToByteArray(keyBits), toggleDirection) { }

    public HCAKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static HCAKey GenerateRandomKey(int blockSize = HCACrypto.BlockSizeInBytes, ToggleDirection? toggleDirection = null)
    {
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytes = Util.GetSecureRandomByteArray(HCACrypto.KeySizeInBytes);
        while (Util.SpatialEntropyCalculusForBinary(Util.ByteArrayToBinaryArray(keyBytes)) <= 0.75)
        {
            keyBytes = Util.GetSecureRandomByteArray(HCACrypto.KeySizeInBytes);
        }
        return new HCAKey(keyBytes, toggleDirection.Value);
    }
}
