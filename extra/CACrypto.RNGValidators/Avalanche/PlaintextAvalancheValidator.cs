using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class PlaintextAvalancheValidator(IEnumerable<CryptoMethodBase> cryptoMethods, ValidatorOptions? opt = null)
    : AvalancheValidatorBase(cryptoMethods, opt)
{
    protected override string GetValidatorName() => "PLAINTEXT_AVALANCHE";

    public PlaintextAvalancheValidator(CryptoMethodBase cryptoMethod, ValidatorOptions? opt = null) : this([cryptoMethod], opt) { }

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey;
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return Util.ChangeRandomBit(originalPlaintext);
    }
}
