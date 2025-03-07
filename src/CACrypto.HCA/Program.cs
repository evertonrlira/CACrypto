using CACrypto.Commons;
using System.Text;

namespace CACrypto.HCA;

class Program
{
    static void Main()
    {
        var cryptoMethod = new HCAProvider();

        var plaintextString = "Avocado is a delicious and nutritive fruit.";
        Console.WriteLine($"- Original Plaintext: {plaintextString}");

        var plaintextBytes = Encoding.ASCII.GetBytes(plaintextString);
        Console.WriteLine($"- Non-Padded Plaintext Bytes: {BitConverter.ToString(plaintextBytes)}");

        var cryptoKey = cryptoMethod.GenerateRandomKey();

        var initializationVector = Util.GetSecureRandomByteArray(cryptoMethod.GetDefaultBlockSizeInBytes() / 2);

        var ciphertext = cryptoMethod.Encrypt(plaintextBytes, cryptoKey, initializationVector);
        Console.WriteLine($"- Ciphertext Bytes: {BitConverter.ToString(ciphertext)}");

        var decryptedPlaintext = cryptoMethod.Decrypt(ciphertext, cryptoKey, initializationVector);

        var recoveredString = Encoding.ASCII.GetString(decryptedPlaintext).TrimEnd('\0');
        Console.WriteLine($"- Deciphered Plaintext: {recoveredString}");
        Console.ReadKey();
    }
}
