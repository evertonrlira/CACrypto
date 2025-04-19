using CACrypto.Commons;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

public abstract class PermutiveCACryptoTestsBase(PermutiveCACryptoProviderBase cryptoMethodProvider)
{
    public PermutiveCACryptoProviderBase _cryptoMethod = cryptoMethodProvider;

    [TestMethod]
    [Theory]
    [InlineData(ToggleDirection.Left)]
    [InlineData(ToggleDirection.Right)]
    public void EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(ToggleDirection direction)
    {
        int textSize = _cryptoMethod.GetDefaultBlockSizeInBytes();
        CommonTests.EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(_cryptoMethod, textSize, direction);
    }

    [TestMethod]
    [Theory]
    [InlineData(OperationMode.ECB)]
    [InlineData(OperationMode.CBC)]
    [InlineData(OperationMode.CTR)]
    public void EncryptDecryptMultipleBlocks_ShouldRetrieveOriginalText(OperationMode operationMode)
    {
        int textSize = 3 * _cryptoMethod.GetDefaultBlockSizeInBytes();
        CommonTests.EncryptDecryptMultipleBlocks_ShouldRetrieveOriginalText(_cryptoMethod, textSize, operationMode);
    }
}