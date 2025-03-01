using CACrypto.Commons;
using System.Text;

namespace CACrypto.HCA;

class Program
{
    static void Main()
    {
        var plaintextString = "Avocado is a delicious and nutritive fruit.";
        Console.WriteLine($"- Original Plaintext: {plaintextString}");

        var plaintextBytes = Encoding.ASCII.GetBytes(plaintextString);
        Console.WriteLine($"- Non-Padded Plaintext Bytes: {BitConverter.ToString(plaintextBytes)}");

        var cryptoKey = HCAKey.GenerateRandomKey();

        var initializationVector = Util.GetSecureRandomByteArray(HCACrypto.BlockSizeInBytes / 2);

        var ciphertext = HCACrypto.BlockEncrypt(plaintextBytes, cryptoKey);
        Console.WriteLine($"- Ciphertext Bytes: {BitConverter.ToString(ciphertext)}");

        var decryptedPlaintext = HCACrypto.BlockDecrypt(ciphertext, cryptoKey);

        var recoveredString = Encoding.ASCII.GetString(decryptedPlaintext).TrimEnd('\0');
        Console.WriteLine($"- Deciphered Plaintext: {recoveredString}");
        Console.ReadKey();
    }
}
