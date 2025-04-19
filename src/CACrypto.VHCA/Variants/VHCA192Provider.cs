using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA192Provider : VHCAProvider
{
    public VHCA192Provider() : base(algorithmName: VHCA192Crypto.Name) { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCA192Key.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override void EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        VHCA192Crypto.BlockEncrypt(initialLattice, mainRules, borderRules, finalLattice, latticeSize);
    }

    public override void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize)
    {
        VHCA192Crypto.BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA192Crypto.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA192Crypto.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return VHCA192Crypto.DefaultBlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return VHCA192Crypto.DefaultBlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCA192Key(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return VHCA192Crypto.KeySizeInBytes;
    }
}
