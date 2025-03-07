using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class KeyAvalancheValidator(CryptoMethodBase crypto, ValidatorOptions? opt = null)
    : AvalancheValidatorBase(crypto, opt)
{
    protected override string GetValidatorName() => "KEY_AVALANCHE";

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey.ChangeRandomBit();
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return originalPlaintext;
    }
}
