using CACrypto.Commons;

namespace CACrypto.HCA;

public class HCAProvider : PermutiveCACryptoProviderBase
{
    public HCAProvider() : base(algorithmName: HCACrypto.Name) { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return HCAKey.GenerateRandomKey(blockSizeInBytes, toggleDirection);
    }

    protected override PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection)
    {
        return new HCAKey(keyBytes, toggleDirection);
    }

    public override Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        if (cryptoKey.Direction == ToggleDirection.Left) 
        { 
            return Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.Bits); 
        }
        else 
        { 
            return Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.Bits); 
        }
    }

    public override Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey)
    {
        if (cryptoKey.Direction == ToggleDirection.Left)
        {
            return Rule.GenerateLeftSensibleMarginRules(HCACrypto.RuleLength);
        }
        else
        {
            return Rule.GenerateRightSensibleMarginRules(HCACrypto.RuleLength);
        }
    }

    public override byte[] EncryptAsSingleBlock(byte[] plainText, Rule[] mainRules, Rule[] borderRules)
    {
        return HCACrypto.BlockEncrypt(plainText, mainRules, borderRules);
    }

    public override byte[] DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules)
    {
        return HCACrypto.BlockDecrypt(cipherText, mainRules, borderRules);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return HCACrypto.BlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return HCACrypto.BlockSizeInBytes;
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return HCACrypto.KeySizeInBytes;
    }
}
