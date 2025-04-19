using CACrypto.Commons;

namespace CACrypto.RNGValidators.Avalanche;

internal class KeyAvalancheValidator(IEnumerable<CryptoProviderBase> cryptoMethods)
    : AvalancheValidatorBase(cryptoMethods)
{
    protected override string GetValidatorName() => "KEY_AVALANCHE";

    public KeyAvalancheValidator(CryptoProviderBase cryptoMethod) : this([cryptoMethod]) { }

    protected override CryptoKey GetNextKey(CryptoKey originalKey)
    {
        return originalKey.ChangeRandomBit();
    }

    protected override byte[] GetNextPlaintext(byte[] originalPlaintext)
    {
        return originalPlaintext;
    }
}
