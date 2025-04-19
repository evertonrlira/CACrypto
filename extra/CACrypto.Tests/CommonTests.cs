using CACrypto.Commons;
using FluentAssertions;

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
        var cipherText = new byte[textSizeInBytes];
        var recoveredText = new byte[textSizeInBytes];
        var cryptoKey = cryptoMethod.GenerateRandomKey(textSizeInBytes, direction);
        // Act
        cryptoMethod.EncryptAsSingleBlock(originalText, cryptoKey, cipherText, textSizeInBytes);
        cipherText.Should().NotEqual(originalText);
        cryptoMethod.DecryptAsSingleBlock(cipherText, cryptoKey, recoveredText, textSizeInBytes);
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
        var cryptoKey = cryptoMethod.GenerateRandomKey();
        var initializationVector = cryptoMethod.GenerateRandomIV();
        // Act
        var cipherText = cryptoMethod.Encrypt(originalText, cryptoKey, initializationVector, operationMode);
        cipherText.Should().NotEqual(originalText);
        var recoveredText = cryptoMethod.Decrypt(cipherText, cryptoKey, initializationVector, operationMode);
        // Assert
        recoveredText.Take(originalText.Length).Should().Equal(originalText);
    }
}
