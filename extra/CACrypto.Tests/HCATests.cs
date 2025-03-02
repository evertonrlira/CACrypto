using CACrypto.Commons;
using CACrypto.HCA;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;

namespace CACrypto.Tests;

[TestClass]
public class HCATests
{
    public PermutiveCACryptoMethodBase _cryptoMethod;

    public HCATests()
    {
        _cryptoMethod = new HCAProxy();
    }

    [TestMethod]
    [Theory]
    [InlineData(SampleSize.DefaultBlockSize)]
    [InlineData(SampleSize.OneKiloByte)]
    public void EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(int textSize)
    {
        CommonTests.EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(_cryptoMethod, textSize);
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