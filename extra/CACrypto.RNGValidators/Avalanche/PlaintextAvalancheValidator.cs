using CACrypto.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class PlaintextAvalancheValidator(IEnumerable<CryptoProviderBase> cryptoMethods)
    : AvalancheValidatorBase(cryptoMethods)
{
    protected override string GetValidatorName() => "PLAINTEXT_AVALANCHE";

    public PlaintextAvalancheValidator(CryptoProviderBase cryptoMethod) : this([cryptoMethod]) { }

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey;
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return Util.ChangeRandomBit(originalPlaintext);
    }
}
