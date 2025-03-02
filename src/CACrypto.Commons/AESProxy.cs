using System.Security.Cryptography;

namespace CACrypto.Commons;

public class AESProxy : CryptoMethodBase
{
    const int _BlockSizeInBytes = 16;

    public AESProxy() : base(algorithmName: "AES") { }

    public override int GetDefaultBlockSizeInBits()
    {
        return 8 * _BlockSizeInBytes;
    }

    static byte[] EncryptStringToBytes_Aes(byte[] data, ICryptoTransform encryptor)
    {
        byte[] encrypted;

        // Create the streams used for encryption.
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                csEncrypt.Write(data, 0, data.Length);
                csEncrypt.FlushFinalBlock();

                encrypted = msEncrypt.ToArray();
            }
        }

        return encrypted;
    }
    /*
    public override IEnumerable<string> GenerateBinaryFile(int sequenceSizeInBits, int howManySequences = 1, string outputDir = ".\\")
    {
        if (!Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        var dirNameForMethod = GetFolderNameForGeneratedFiles();
        var dirCombined = Path.Combine(outputDir, dirNameForMethod);
        if (!Directory.Exists(dirCombined))
            Directory.CreateDirectory(dirCombined);

        var fileBag = new ConcurrentBag<string>();
        Parallel.For(0, howManySequences, new ParallelOptions() { MaxDegreeOfParallelism = 10 }, (index) =>
        {
            using (var newFile = File.Create(string.Format("{0}.bin", Path.Combine(dirCombined, Path.GetRandomFileName()))))
            {
                var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
                var defaultBlockSizeInBytes = defaultBlockSizeInBits / 8;
                byte[] ciphertext;
                var plainText = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
                var cryptoKey = Util.GetSecureRandomByteArray(16);
                var IV = Util.GetSecureRandomByteArray(16);

                var executions = (sequenceSizeInBits / defaultBlockSizeInBits);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.KeySize = 128;
                    aesAlg.BlockSize = 128;
                    aesAlg.FeedbackSize = 128;
                    aesAlg.Padding = PaddingMode.Zeros;
                    aesAlg.Key = cryptoKey;
                    aesAlg.IV = IV;

                    // Create an encryptor to perform the stream transform.
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
                    {
                        ciphertext = EncryptStringToBytes_Aes(plainText, encryptor);

                        //var ciphertext = Util.BinaryArrayToByteArray(preImage);

                        for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
                        {
                            newFile.WriteByte((byte)(ciphertext[byteIdx] ^ plainText[byteIdx]));
                        }
                        plainText = ciphertext;
                    }
                }
                fileBag.Add(newFile.Name);
            }
        });
        return fileBag;
    }
    */

    public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
    {
        using var stream = new MemoryStream();
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = defaultBlockSizeInBits / 8;
        var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
        var cryptoKey = Util.GetSecureRandomByteArray(16);
        var IV = Util.GetSecureRandomByteArray(16);

        WriteNewBinaryStream(stream, initialSeed, cryptoKey, IV, sequenceSizeInBytes);

        return stream.ToArray();
    }

    private void WriteNewBinaryStream(MemoryStream stream, byte[] initialSeed, byte[] cryptoKey, byte[] IV, int sequenceSizeInBits)
    {
        var bw = new BinaryWriter(stream);
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBits() / 8;
        var executions = sequenceSizeInBits / defaultBlockSizeInBits;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.KeySize = 128;
            aesAlg.BlockSize = 128;
            aesAlg.FeedbackSize = 128;
            aesAlg.Padding = PaddingMode.Zeros;
            aesAlg.Key = cryptoKey;
            aesAlg.IV = IV;

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            var plainText = initialSeed;
            for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
            {
                var cipherText = EncryptStringToBytes_Aes(plainText, encryptor);

                for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
                {
                    bw.Write(cipherText[byteIdx]);
                }
                plainText = cipherText;
            }
            bw.Flush();
        }
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return 128;
    }
}
