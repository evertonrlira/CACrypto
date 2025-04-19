using CACrypto.Commons;

namespace CACrypto.VHCA.Variants;

public class VHCA256Provider : PermutiveCACryptoProviderBase
{
    public VHCA256Provider() : base(algorithmName: VHCA256Crypto.Name) { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCA256Key.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override void EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        VHCA256Crypto.BlockEncrypt(initialLattice, mainRules, borderRules, finalLattice, latticeSize);
    }

    public override void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize)
    {
        VHCA256Crypto.BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA256Crypto.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return VHCA256Crypto.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return VHCA256Crypto.DefaultBlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return VHCA256Crypto.DefaultBlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCA256Key(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return VHCA256Crypto.KeySizeInBytes;
    }
}
