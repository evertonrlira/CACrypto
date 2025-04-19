using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA256Key : VHCAKey
{
    internal VHCA256Key(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static new VHCA256Key GenerateRandomKey(int? blockSize = null, ToggleDirection? toggleDirection = null)
    {
        blockSize ??= VHCA256Crypto.DefaultBlockSizeInBytes;
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytesLength = VHCA256Crypto.KeyBitsToRuleFactor * blockSize.Value;
        var keyBytes = new byte[keyBytesLength];
        Util.FillArrayWithRandomData(keyBytes);
        return new VHCA256Key(keyBytes, toggleDirection.Value);
    }

    public override CryptoKey ChangeRandomBit()
    {
        var newBytes = Util.ChangeRandomBit(Bytes);
        return new VHCA256Key(newBytes, Direction);
    }
}
