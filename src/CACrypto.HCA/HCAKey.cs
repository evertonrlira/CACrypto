using CACrypto.Commons;
using System.Buffers;

namespace CACrypto.HCA;

public class HCAKey : PermutiveCACryptoKey
{
    internal HCAKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static HCAKey GenerateRandomKey(int? _ = null, ToggleDirection? toggleDirection = null)
    {
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytes = new byte[HCACrypto.KeySizeInBytes];
        Util.FillArrayWithRandomData(keyBytes);
        return new HCAKey(keyBytes, toggleDirection.Value);
    }

    public override bool IsValid()
    {
        return IsValid(Bytes);
    }

    public override CryptoKey ChangeRandomBit()
    {
        var newBytes = Util.ChangeRandomBit(Bytes);
        return new HCAKey(newBytes, Direction);
    }
}
