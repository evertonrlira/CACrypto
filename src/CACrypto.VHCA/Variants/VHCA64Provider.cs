using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA64Provider : PermutiveCACryptoProviderBase
{
    public VHCA64Provider() : base(algorithmName: VHCA64Crypto.Name) { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCA64Key.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override void EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        VHCA64Crypto.BlockEncrypt(initialLattice, mainRules, borderRules, finalLattice, latticeSize);
    }

    public override void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize)
    {
        VHCA64Crypto.BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA64Crypto.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA64Crypto.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return VHCA64Crypto.DefaultBlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return VHCA64Crypto.DefaultBlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCA64Key(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return VHCA64Crypto.KeySizeInBytes;
    }
}
