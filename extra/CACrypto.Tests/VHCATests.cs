using CACrypto.Commons;
using CACrypto.VHCA;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CACrypto.Tests;

[TestClass]
public class VHCATests
{
    public PermutiveCACryptoProviderBase _cryptoMethod;

    public VHCATests()
    {
        _cryptoMethod = new VHCAProvider();
    }

    [TestMethod]
    [Theory]
    [InlineData(SampleSize.DefaultBlockSize, ToggleDirection.Left)]
    [InlineData(SampleSize.DefaultBlockSize, ToggleDirection.Right)]
    [InlineData(SampleSize.OneKiloByte, ToggleDirection.Left)]
    [InlineData(SampleSize.OneKiloByte, ToggleDirection.Right)]
    public void EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(int textSize, ToggleDirection direction)
    {
        CommonTests.EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(_cryptoMethod, textSize, direction);
    }

    [TestMethod]
    [Theory]
    [InlineData(SampleSize.DefaultBlockSize, OperationMode.ECB)]
    [InlineData(SampleSize.DefaultBlockSize, OperationMode.CBC)]
    [InlineData(SampleSize.DefaultBlockSize, OperationMode.CTR)]
    [InlineData(SampleSize.OneKiloByte, OperationMode.ECB)]
    [InlineData(SampleSize.OneKiloByte, OperationMode.CBC)]
    [InlineData(SampleSize.OneKiloByte, OperationMode.CTR)]
    public void EncryptDecryptMultipleBlocks_ShouldRetrieveOriginalText(int textSize, OperationMode operationMode)
    {
        CommonTests.EncryptDecryptMultipleBlocks_ShouldRetrieveOriginalText(_cryptoMethod, textSize, operationMode);
    }
}