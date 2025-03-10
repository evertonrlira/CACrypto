using CACrypto.Commons;
using System;

namespace CACrypto.VHCA;

public class VHCAKey : PermutiveCACryptoKey
{
    internal VHCAKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

    public static VHCAKey GenerateRandomKey(int? blockSize = null, ToggleDirection? toggleDirection = null)
    {
        blockSize ??= VHCACrypto.DefaultBlockSizeInBytes;
        toggleDirection ??= Util.GetRandomToggleDirection();

        var keyBytesLength = VHCACrypto.KeyBitsToRuleFactor * blockSize.Value;
        var keyBytes = new byte[keyBytesLength];
        Util.FillArrayWithRandomData(keyBytes);
        return new VHCAKey(keyBytes, toggleDirection.Value);
    }

    public override bool IsValid()
    {
        var thirdPartitionLength = Bytes.Length / 3;

        Span<byte> keyPart01 = Bytes[0..(2 * thirdPartitionLength)];
        Span<byte> keyPart02 = Bytes[thirdPartitionLength..];
        Span<byte> keyPart03 = [.. Bytes[(2 * thirdPartitionLength)..], .. Bytes[..thirdPartitionLength]];

        return IsValid(keyPart01)
            && IsValid(keyPart02)
            && IsValid(keyPart03);
    }

    public override CryptoKey ChangeRandomBit()
    {
        var newBytes = Util.ChangeRandomBit(Bytes);
        return new VHCAKey(newBytes, Direction);
    }
}
