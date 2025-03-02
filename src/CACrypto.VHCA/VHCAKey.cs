using CACrypto.Commons;

namespace CACrypto.VHCA;

public class VHCAKey : PermutiveCACryptoKey
{
    private VHCAKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static VHCAKey GenerateRandomKey(int? blockSize = null, ToggleDirection? toggleDirection = null)
    {
        blockSize ??= VHCACrypto.BlockSizeInBytes;
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytes = Util.GetSecureRandomByteArray(VHCACrypto.KeyBitsToRuleFactor * blockSize.Value);
        return new VHCAKey(keyBytes, toggleDirection.Value);
    }

    public override bool IsValid()
    {
        var blockSizeInBytes = VHCACrypto.BlockSizeInBytes;
        var keyPart01 = Util.ByteArrayToBinaryArray(Bytes[0..(2*blockSizeInBytes)]);
        var keyPart02 = Util.ByteArrayToBinaryArray(Bytes[blockSizeInBytes..]);
        var keyPart03 = Util.ByteArrayToBinaryArray([..Bytes[(2*blockSizeInBytes)..], ..Bytes[..blockSizeInBytes]]);
        return Util.SpatialEntropyCalculusForBinary(keyPart01) > 0.75 &&
               Util.SpatialEntropyCalculusForBinary(keyPart02) > 0.75 &&
               Util.SpatialEntropyCalculusForBinary(keyPart03) > 0.75;
    }
}
