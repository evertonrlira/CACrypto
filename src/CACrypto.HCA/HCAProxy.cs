using CACrypto.Commons;

namespace CACrypto.HCA;

public class HCAProxy : PermutiveCACryptoMethodBase
{
    public HCAProxy() : base(algorithmName: "HCA") { }

    protected override PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection)
    {
        return HCAKey.GenerateRandomKey(blockSizeInBytes, toggleDirection);
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
        return HCACrypto.BlockEncrypt(plainText, mainRules, borderRules, iterations: HCACrypto.BlockSizeInBits);
    }

    public override byte[] DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules)
    {
        return HCACrypto.BlockDecrypt(cipherText, mainRules, borderRules, iterations: HCACrypto.BlockSizeInBits);
    }

    public override int GetDefaultBlockSizeInBits()
    {
        return HCACrypto.BlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return HCACrypto.BlockSizeInBytes;
    }
}
