using CACrypto.Commons;

namespace CACrypto.VHCA;

public class VHCAProvider : PermutiveCACryptoMethodBase
{
    public VHCAProvider() : base(algorithmName: VHCACrypto.Name) { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCAKey.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override byte[] EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules)
    {
        return VHCACrypto.BlockEncrypt(initialLattice, mainRules, borderRules);
    }

    public override byte[] DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules)
    {
        return VHCACrypto.BlockDecrypt(cipherText, mainRules, borderRules);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCACrypto.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCACrypto.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return VHCACrypto.BlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return VHCACrypto.BlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCAKey(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return VHCACrypto.KeySizeInBytes;
    }
}
