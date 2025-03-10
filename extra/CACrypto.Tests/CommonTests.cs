using CACrypto.Commons;
using FluentAssertions;
using System.Buffers;

namespace CACrypto.Tests;

internal static class CommonTests
{
    public static void EncryptDecryptAsSingleBlock_ShouldRetrieveOriginalText(
        PermutiveCACryptoProviderBase cryptoMethod, 
        int textSizeInBytes,
        ToggleDirection direction)
    {
        // Arrange
        var originalText = new byte[textSizeInBytes];
        Util.FillArrayWithRandomData(originalText);
        var cryptoKey = cryptoMethod.GenerateRandomKey(textSizeInBytes, direction);
        // Act
        var cipherText = cryptoMethod.EncryptAsSingleBlock(originalText, cryptoKey);
        cipherText.Should().NotEqual(originalText);
        var recoveredText = cryptoMethod.DecryptAsSingleBlock(cipherText, cryptoKey);
        // Assert
        recoveredText.Should().Equal(originalText);
    }

    public static void EncryptDecryptMultipleBlocks_ShouldRetrieveOriginalText(
        PermutiveCACryptoProviderBase cryptoMethod, 
        int textSizeInBytes, 
        OperationMode operationMode)
    {
        // Arrange
        var originalText = new byte[textSizeInBytes];
        Util.FillArrayWithRandomData(originalText);
        var cryptoKey = cryptoMethod.GenerateRandomKey(textSizeInBytes);
        var initializationVector = new byte[textSizeInBytes];
        Util.FillArrayWithRandomData(initializationVector);
        // Act
        var cipherText = cryptoMethod.Encrypt(originalText, cryptoKey, initializationVector, operationMode);
        cipherText.Should().NotEqual(originalText);
        var recoveredText = cryptoMethod.Decrypt(cipherText, cryptoKey, initializationVector, operationMode);
        // Assert
        recoveredText.Should().Equal(originalText);
    }
}
