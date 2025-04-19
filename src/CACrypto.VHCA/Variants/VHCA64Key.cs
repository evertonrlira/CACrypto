using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA64Key : VHCAKey
{
    internal VHCA64Key(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static new VHCA64Key GenerateRandomKey(int? blockSize = null, ToggleDirection? toggleDirection = null)
    {
        blockSize ??= VHCA64Crypto.DefaultBlockSizeInBytes;
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytesLength = VHCA64Crypto.KeyBitsToRuleFactor * blockSize.Value;
        var keyBytes = new byte[keyBytesLength];
        Util.FillArrayWithRandomData(keyBytes);
        return new VHCA64Key(keyBytes, toggleDirection.Value);
    }

    public override CryptoKey ChangeRandomBit()
    {
        var newBytes = Util.ChangeRandomBit(Bytes);
        return new VHCA64Key(newBytes, Direction);
    }
}
