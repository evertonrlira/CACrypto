﻿using System.Buffers;
using System.Security.Cryptography;

namespace CACrypto.Commons;

public class AESProvider : CryptoProviderBase
{
    const int _BlockSizeInBytes = 16;
    const int _BlockSizeInBits = 128;

    public AESProvider() : base(methodName: "AES") { }

    static void PerformCryptoTransformation(byte[] input, ICryptoTransform transformOperation, byte[] output, int blockSize)
    {
        using MemoryStream ms = new(output);
        using CryptoStream cs = new(ms, transformOperation, CryptoStreamMode.Write);
        cs.Write(input, 0, blockSize);
        cs.FlushFinalBlock();
    }

    public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
    {
        using var stream = new MemoryStream();
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var initialSeed = new byte[defaultBlockSizeInBytes];
        Util.FillArrayWithRandomData(initialSeed);
        var cryptoKey = GenerateRandomKey();
        var IV = new byte[defaultBlockSizeInBytes];
        Util.FillArrayWithRandomData(IV);

        WriteNewBinaryStream(stream, initialSeed, cryptoKey.Bytes, IV, sequenceSizeInBytes);

        return stream.ToArray();
    }

    private void WriteNewBinaryStream(MemoryStream stream, byte[] initialSeed, Span<byte> cryptoKey, byte[] IV, int sequenceSizeInBytes)
    {
        var bw = new BinaryWriter(stream);
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var executions = sequenceSizeInBytes / defaultBlockSizeInBytes;

        using Aes aesAlg = Aes.Create();
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.KeySize = defaultBlockSizeInBits;
        aesAlg.BlockSize = defaultBlockSizeInBits;
        aesAlg.FeedbackSize = defaultBlockSizeInBits;
        aesAlg.Padding = PaddingMode.Zeros;
        aesAlg.Key = cryptoKey.ToArray();
        aesAlg.IV = IV;

        // Create an encryptor to perform the stream transform.
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        var plaintext = initialSeed;
        var ciphertext = ArrayPool<byte>.Shared.Rent(defaultBlockSizeInBytes);
        for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
        {
            PerformCryptoTransformation(plaintext, encryptor, ciphertext, defaultBlockSizeInBytes);

            for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
            {
                bw.Write((byte)(ciphertext[byteIdx] ^ plaintext[byteIdx]));
            }

            Util.Swap(ref plaintext, ref ciphertext);
        }
        bw.Flush();
        ArrayPool<byte>.Shared.Return(ciphertext);
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
        var bytes = new byte[_BlockSizeInBytes];
        Util.FillArrayWithRandomData(bytes);
        return new CryptoKey(bytes);
    }

    public override int GetDefaultKeySizeInBytes()
    {
        return _BlockSizeInBytes;
    }

    public override void EncryptAsSingleBlock(byte[] plaintext, CryptoKey key, byte[] ciphertext, int blockSize)
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
        PerformCryptoTransformation(plaintext, encryptor, ciphertext, blockSize);
    }

    public void DecryptAsSingleBlock(byte[] ciphertext, CryptoKey key, byte[] plaintext, int blockSize)
    {
        var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();

        using Aes aesAlg = Aes.Create();
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.KeySize = defaultBlockSizeInBits;
        aesAlg.BlockSize = defaultBlockSizeInBits;
        aesAlg.FeedbackSize = defaultBlockSizeInBits;
        aesAlg.Padding = PaddingMode.Zeros;
        aesAlg.Key = key.Bytes;
        aesAlg.IV = new byte[defaultBlockSizeInBytes];

        // Create a decryptor to perform the stream transform.
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        PerformCryptoTransformation(ciphertext, decryptor, plaintext, blockSize);
    }
}
