using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA192Key : VHCAKey
{
    internal VHCA192Key(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static new VHCA192Key GenerateRandomKey(int? blockSize = null, ToggleDirection? toggleDirection = null)
    {
        blockSize ??= VHCA192Crypto.DefaultBlockSizeInBytes;
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytesLength = VHCA192Crypto.KeyBitsToRuleFactor * blockSize.Value;
        var keyBytes = new byte[keyBytesLength];
        Util.FillArrayWithRandomData(keyBytes);
        return new VHCA192Key(keyBytes, toggleDirection.Value);
    }

    public override CryptoKey ChangeRandomBit()
    {
        var newBytes = Util.ChangeRandomBit(Bytes);
        return new VHCA192Key(newBytes, Direction);
    }
}
