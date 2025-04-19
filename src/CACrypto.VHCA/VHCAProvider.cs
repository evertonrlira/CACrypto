using CACrypto.Commons;

namespace CACrypto.VHCA;

public class VHCAProvider : PermutiveCACryptoProviderBase
{
    private readonly VHCACryptoBase _cryptoMethod;

    public VHCAProvider() : base(algorithmName: VHCACrypto.Name) { _cryptoMethod = new VHCACrypto(); }
    public VHCAProvider(VHCACryptoBase cryptoMethod) : base(cryptoMethod.MethodName) { _cryptoMethod = cryptoMethod; }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return VHCAKey.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    public override void EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        _cryptoMethod.BlockEncrypt(initialLattice, mainRules, borderRules, finalLattice, latticeSize);
    }

    public override void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize)
    {
        _cryptoMethod.BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return _cryptoMethod.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        return _cryptoMethod.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return _cryptoMethod.MethodDefaultBlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return _cryptoMethod.MethodDefaultBlockSizeInBytes;
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new VHCAKey(keyBytes, toggleDirection);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return _cryptoMethod.MethodKeySizeInBytes;
    }
}
