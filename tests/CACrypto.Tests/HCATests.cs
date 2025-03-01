using CACrypto.Commons;
using CACrypto.HCA;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace CACrypto.Tests;

[TestClass]
public class HCATests
{
    [Fact]
    [TestMethod]
    public void Encrypt_WhenDeciphering_WillRetrieveOriginalText()
    {
        // Arrange
        var originalText = "Hello, World!";
        var textBytes = Encoding.ASCII.GetBytes(originalText);
        var blockSize = textBytes.Length;
        var key = HCAKey.GenerateRandomKey(blockSize);
        var iv = Util.GetSecureRandomByteArray(HCACrypto.BlockSizeInBytes / 2);
        // Act
        var encrypted = HCACrypto.BlockEncrypt(textBytes, key);
        var decrypted = HCACrypto.BlockDecrypt(encrypted, key);
        var recoveredText = Encoding.ASCII.GetString(decrypted).TrimEnd('\0');
        // Assert
        recoveredText.Should().Be(originalText);
    }
}