using CACrypto.Commons;
using CACrypto.VHCA;
using System;
using System.Text;

namespace VHCA_Crypto
{
    class Program
    {
        static void Main()
        {
            var plaintextString = "Avocado is a delicious and nutritive fruit.";
            Console.WriteLine($"- Original Plaintext: {plaintextString}");

            var plaintextBytes = Encoding.ASCII.GetBytes(plaintextString);
            Console.WriteLine($"- Non-Padded Plaintext Bytes: {BitConverter.ToString(plaintextBytes)}");

            var blockSize = plaintextBytes.Length;
            var cryptoKey = VHCAKey.GenerateRandomKey(blockSize);

            var initializationVector = Util.GetSecureRandomByteArray(VHCACrypto.BlockSizeInBytes / 2);

            var ciphertext = VHCACrypto.BlockEncrypt(plaintextBytes, cryptoKey);
            Console.WriteLine($"- Ciphertext Bytes: {BitConverter.ToString(ciphertext)}");

            var decryptedPlaintext = VHCACrypto.BlockDecrypt(ciphertext, cryptoKey);

            var recoveredString = Encoding.ASCII.GetString(decryptedPlaintext).TrimEnd('\0');
            Console.WriteLine($"- Deciphered Plaintext: {recoveredString}");
            Console.ReadKey();
        }
    }
}
