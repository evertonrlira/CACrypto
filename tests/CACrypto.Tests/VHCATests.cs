using CACrypto.Commons;
using CACrypto.VHCA;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace CACrypto.Tests;

[TestClass]
public class VHCATests
{
    [Fact]
    [TestMethod]
    public void Encrypt_WhenDeciphering_WillRetrieveOriginalText()
    {
        // Arrange
        var originalText = "Hello, World!";
        var textBytes = Encoding.ASCII.GetBytes(originalText);
        var blockSize = textBytes.Length;
        var key = VHCAKey.GenerateRandomKey(blockSize);
        var iv = Util.GetSecureRandomByteArray(VHCACrypto.BlockSizeInBytes / 2);
        // Act
        var encrypted = VHCACrypto.BlockEncrypt(textBytes, key);
        var decrypted = VHCACrypto.BlockDecrypt(encrypted, key);
        var recoveredText = Encoding.ASCII.GetString(decrypted).TrimEnd('\0');
        // Assert
        recoveredText.Should().Be(originalText);
    }
}