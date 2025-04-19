using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

internal record CryptoValidatorInput
{
    internal required CryptoProviderBase CryptoMethod;
    internal required ValidatorOptions Options;
}
