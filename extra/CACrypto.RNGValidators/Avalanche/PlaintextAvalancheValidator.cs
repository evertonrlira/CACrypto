using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class PlaintextAvalancheValidator(CryptoMethodBase crypto, ValidatorOptions? opt = null)
    : AvalancheValidatorBase(crypto, opt)
{
    protected override string GetValidatorName() => "PLAINTEXT_AVALANCHE";

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey;
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return Util.ChangeRandomBit(originalPlaintext);
    }
}
