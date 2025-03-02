using CACrypto.Commons;

namespace CACrypto.HCA;

public class HCAKey : PermutiveCACryptoKey
{
    private HCAKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static HCAKey GenerateRandomKey(int? _ = null, ToggleDirection? toggleDirection = null)
    {
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytes = Util.GetSecureRandomByteArray(HCACrypto.KeySizeInBytes);
        return new HCAKey(keyBytes, toggleDirection.Value);
    }

    public override bool IsValid()
    {
        return Util.SpatialEntropyCalculusForBinary(Util.ByteArrayToBinaryArray(Bytes)) > 0.75;
    }
}
