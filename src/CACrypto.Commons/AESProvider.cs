using System.Security.Cryptography;

namespace CACrypto.Commons;

public class AESProvider : CryptoMethodBase
{
    const int _BlockSizeInBytes = 16;
    const int _BlockSizeInBits = 128;

    public AESProvider() : base(algorithmName: "AES") { }

    static byte[] EncryptStringToBytes_Aes(byte[] data, ICryptoTransform encryptor)
    {
        byte[] encrypted;

        // Create the streams used for encryption.
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            using CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            csEncrypt.Write(data, 0, data.Length);
            csEncrypt.FlushFinalBlock();

            encrypted = msEncrypt.ToArray();
        }

        return encrypted;
    }

    public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
    {
        using var stream = new MemoryStream();
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
        var cryptoKey = GenerateRandomKey();
        var IV = Util.GetSecureRandomByteArray(16);

        WriteNewBinaryStream(stream, initialSeed, cryptoKey.Bytes, IV, sequenceSizeInBytes);

        return stream.ToArray();
    }

    private void WriteNewBinaryStream(MemoryStream stream, byte[] initialSeed, byte[] cryptoKey, byte[] IV, int sequenceSizeInBits)
    {
        var bw = new BinaryWriter(stream);
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var executions = sequenceSizeInBits / defaultBlockSizeInBits;

        using Aes aesAlg = Aes.Create();
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.KeySize = defaultBlockSizeInBits;
        aesAlg.BlockSize = defaultBlockSizeInBits;
        aesAlg.FeedbackSize = defaultBlockSizeInBits;
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

    public override int GetDefaultBlockSizeInBits()
    {
        return _BlockSizeInBits;
    }

    public override int GetDefaultBlockSizeInBytes()
    {
        return _BlockSizeInBytes;
    }

    public override CryptoKey GenerateRandomKey()
    {
        var bytes = Util.GetSecureRandomByteArray(_BlockSizeInBytes);
        return new CryptoKey(bytes);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return _BlockSizeInBytes;
    }

    public override byte[] EncryptAsSingleBlock(byte[] plaintext, CryptoKey key)
    {
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();

        if (plaintext.Length > defaultBlockSizeInBytes)
        {
            throw new Exception("This plaintext cannot be encrypted as a single block");
        }

        using Aes aesAlg = Aes.Create();
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.KeySize = defaultBlockSizeInBits;
        aesAlg.BlockSize = defaultBlockSizeInBits;
        aesAlg.FeedbackSize = defaultBlockSizeInBits;
        aesAlg.Padding = PaddingMode.Zeros;
        aesAlg.Key = key.Bytes;
        aesAlg.IV = new byte[defaultBlockSizeInBytes];

        // Create an encryptor to perform the stream transform.
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        return EncryptStringToBytes_Aes(plaintext, encryptor);
    }
}
