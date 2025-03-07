using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class KeyAvalancheValidator(IEnumerable<CryptoMethodBase> cryptoMethods, ValidatorOptions? opt = null)
    : AvalancheValidatorBase(cryptoMethods, opt)
{
    protected override string GetValidatorName() => "KEY_AVALANCHE";

    public KeyAvalancheValidator(CryptoMethodBase cryptoMethod, ValidatorOptions? opt = null) : this([cryptoMethod], opt) { }

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey.ChangeRandomBit();
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return originalPlaintext;
    }
}
