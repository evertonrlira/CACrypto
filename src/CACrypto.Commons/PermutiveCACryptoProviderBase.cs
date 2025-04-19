using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CACrypto.Commons;

public abstract class PermutiveCACryptoProviderBase(string algorithmName) : CryptoProviderBase(algorithmName)
{
    public abstract Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey);
    public abstract Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey);

    public byte[] Encrypt(byte[] plaintext, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, OperationMode operationMode = OperationMode.CTR)
    {
        return operationMode switch
        {
            OperationMode.ECB => Encrypt_ECB(plaintext, cryptoKey),
            OperationMode.CBC => Encrypt_CBC(plaintext, cryptoKey, initializationVector),
            OperationMode.CTR => Encrypt_CTR(plaintext, cryptoKey, initializationVector),
            _ => throw new CryptographicException($"Unsupported operation mode: {operationMode}"),
        };
    }

    private byte[] Encrypt_ECB(byte[] plainText, PermutiveCACryptoKey cryptoKey)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(plainText.Length, blockSize);
        var cipherText = new byte[blockCount * blockSize];

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        Parallel.For(0, blockCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (blockIdx) =>
        {
            var blockPlaintext = ArrayPool<byte>.Shared.Rent(blockSize);
            var blockCiphertext = ArrayPool<byte>.Shared.Rent(blockSize);
            Util.CopyPlaintextIntoBlock(plainText, blockPlaintext, blockIdx, blockSize);

            EncryptAsSingleBlock(blockPlaintext, mainRules, borderRules, blockCiphertext, blockSize);
            Buffer.BlockCopy(blockCiphertext, 0, cipherText, blockIdx * blockSize, blockSize);

            ArrayPool<byte>.Shared.Return(blockPlaintext);
            ArrayPool<byte>.Shared.Return(blockCiphertext);
        });
        return cipherText;
    }

    private byte[] Encrypt_CBC(byte[] plaintext, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(plaintext.Length, blockSize);
        var cipherText = new byte[blockCount * blockSize];
        var xorVector = Util.CloneByteArray(initializationVector);

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        for (int blockIdx = 0; blockIdx < blockCount; ++blockIdx)
        {
            var blockPlaintext = ArrayPool<byte>.Shared.Rent(blockSize);
            var blockCiphertext = ArrayPool<byte>.Shared.Rent(blockSize);
            Util.CopyPlaintextIntoBlock(plaintext, blockPlaintext, blockIdx, blockSize);

            for (int byteIdx = 0; byteIdx < blockSize; ++byteIdx)
            {
                blockPlaintext[byteIdx] ^= xorVector[byteIdx];
            }

            EncryptAsSingleBlock(blockPlaintext, mainRules, borderRules, blockCiphertext, blockSize);
            Buffer.BlockCopy(blockCiphertext, 0, xorVector, 0, blockSize);
            Buffer.BlockCopy(blockCiphertext, 0, cipherText, blockIdx * blockSize, blockSize);

            ArrayPool<byte>.Shared.Return(blockPlaintext);
            ArrayPool<byte>.Shared.Return(blockCiphertext);
        }
        return cipherText;
    }

    public byte[] Encrypt_CTR(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(plainText.Length, blockSize);
        var paddedPlaintext = new byte[blockCount * blockSize];
        Buffer.BlockCopy(plainText, 0, paddedPlaintext, 0, plainText.Length);

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        var cipherText = new byte[paddedPlaintext.Length];

        Parallel.For(0, blockCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (counterIdx) =>
        {
            var blockPlaintext = ArrayPool<byte>.Shared.Rent(blockSize);
            Array.Fill(blockPlaintext, Byte.MinValue);
            var blockCiphertext = ArrayPool<byte>.Shared.Rent(blockSize);
            Array.Fill(blockCiphertext, Byte.MinValue);

            BinaryPrimitives.WriteIntPtrBigEndian(blockPlaintext.AsSpan(0, blockSize / 2), counterIdx);
            Buffer.BlockCopy(initializationVector, 0, blockPlaintext, blockSize / 2, blockSize / 2);

            EncryptAsSingleBlock(blockPlaintext, mainRules, borderRules, blockCiphertext, blockSize);

            var src01 = blockCiphertext;
            var src01BeginIdx = 0;
            var src02 = paddedPlaintext;
            var src02BeginIdx = counterIdx * blockSize;
            var xorLength = blockSize;
            var dst = cipherText;
            var dstBeginIdx = counterIdx * blockSize;
            Util.XOR(src01, src01BeginIdx, src02, src02BeginIdx, xorLength, dst, dstBeginIdx);

            ArrayPool<byte>.Shared.Return(blockPlaintext);
            ArrayPool<byte>.Shared.Return(blockCiphertext);
        });
        return cipherText;
    }

    public byte[] Decrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, OperationMode operationMode = OperationMode.CTR)
    {
        return operationMode switch
        {
            OperationMode.ECB => Decrypt_ECB(cipherText, cryptoKey),
            OperationMode.CBC => Decrypt_CBC(cipherText, cryptoKey, initializationVector),
            OperationMode.CTR => Decrypt_CTR(cipherText, cryptoKey, initializationVector),
            _ => throw new CryptographicException($"Unsupported operation mode: {operationMode}"),
        };
    }

    private byte[] Decrypt_ECB(byte[] cipherText, PermutiveCACryptoKey cryptoKey)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(cipherText.Length, blockSize);
        var plainText = new byte[blockCount * blockSize];

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        Parallel.For(0, blockCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (blockIdx) =>
        {
            var blockPlaintext = ArrayPool<byte>.Shared.Rent(blockSize);
            var blockCiphertext = ArrayPool<byte>.Shared.Rent(blockSize);
            Buffer.BlockCopy(cipherText, blockIdx * blockSize, blockCiphertext, 0, blockSize);

            DecryptAsSingleBlock(blockCiphertext, mainRules, borderRules, blockPlaintext, blockSize);
            Buffer.BlockCopy(blockPlaintext, 0, plainText, blockIdx * blockSize, blockSize);

            ArrayPool<byte>.Shared.Return(blockPlaintext);
            ArrayPool<byte>.Shared.Return(blockCiphertext);
        });
        return plainText;
    }

    private byte[] Decrypt_CBC(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(cipherText.Length, blockSize);
        var plainText = new byte[blockCount * blockSize];

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        Parallel.For(0, blockCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (blockIdx) =>
        {
            var blockPlaintext = ArrayPool<byte>.Shared.Rent(blockSize);
            var blockCiphertext = ArrayPool<byte>.Shared.Rent(blockSize);

            Buffer.BlockCopy(cipherText, blockIdx * blockSize, blockCiphertext, 0, blockSize);
            DecryptAsSingleBlock(blockCiphertext, mainRules, borderRules, blockPlaintext, blockSize);

            var xorVector = blockIdx == 0
                ? initializationVector
                : cipherText.AsSpan((blockIdx - 1) * blockSize, blockSize);

            for (int byteIdx = 0; byteIdx < blockSize; ++byteIdx)
            {
                blockPlaintext[byteIdx] ^= xorVector[byteIdx];
            }

            Buffer.BlockCopy(blockPlaintext, 0, plainText, blockIdx * blockSize, blockSize);

            ArrayPool<byte>.Shared.Return(blockPlaintext);
            ArrayPool<byte>.Shared.Return(blockCiphertext);
        });
        return plainText;
    }

    public byte[] Decrypt_CTR(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        return Encrypt_CTR(cipherText, cryptoKey, initializationVector);
    }

    protected abstract PermutiveCACryptoKey GenerateRandomKey(int blockSizeInBytes, ToggleDirection toggleDirection);
    public PermutiveCACryptoKey GenerateRandomKey(int? blockSizeInBytes = null, ToggleDirection? toggleDirection = null)
    {
        var defaultBlockSize = GetDefaultBlockSizeInBytes();
        if (blockSizeInBytes is null || blockSizeInBytes.Value < defaultBlockSize)
        {
            blockSizeInBytes = defaultBlockSize;
        }
        toggleDirection ??= Util.GetRandomToggleDirection();
        var key = GenerateRandomKey(blockSizeInBytes.Value, toggleDirection.Value);
        while (!key.IsValid())
        {
            key = GenerateRandomKey(blockSizeInBytes.Value, toggleDirection.Value);
        }
        return key;
    }
    public override CryptoKey GenerateRandomKey()
    {
        return GenerateRandomKey();
    }
    protected PermutiveCACryptoKey RebuildKey(byte[] bytes)
    {
        var keyBytes = bytes[..GetDefaultKeySizeInBytes()];
        var directionByte = bytes[^1];
        var toggleDirection = (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), directionByte);
        return BuildKey(keyBytes, toggleDirection);
    }
    protected abstract PermutiveCACryptoKey BuildKey(byte[] keyBytes, ToggleDirection toggleDirection);

    public abstract void EncryptAsSingleBlock(byte[] plainText, Rule[] mainRules, Rule[] borderRules, byte[] ciphertext, int blockSize);
    public void EncryptAsSingleBlock(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] ciphertext, int blockSize)
    {
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        EncryptAsSingleBlock(plainText, mainRules, borderRules, ciphertext, blockSize);
    }
    public override void EncryptAsSingleBlock(byte[] plaintext, CryptoKey key, byte[] ciphertext, int blockSize)
    {
        var permutiveKey = (key as PermutiveCACryptoKey) ?? throw new ArgumentException("Invalid Key Type");
        EncryptAsSingleBlock(plaintext, permutiveKey, ciphertext, blockSize);
    }

    public abstract void DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules, byte[] plaintext, int blockSize);
    public void DecryptAsSingleBlock(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] plaintext, int blockSize)
    {
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        DecryptAsSingleBlock(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
    {
        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var cryptoKey = GenerateRandomKey(defaultBlockSizeInBytes);
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);
        return GeneratePseudoRandomSequence(sequenceSizeInBytes, mainRules, borderRules);
    }

    public byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes, Rule[] mainRules, Rule[] borderRules)
    {
        using var stream = new MemoryStream();
        var bw = new BinaryWriter(stream);

        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var bytesToCopy = defaultBlockSizeInBytes;
        var plaintext = ArrayPool<byte>.Shared.Rent(defaultBlockSizeInBytes);
        Util.FillArrayWithRandomData(plaintext);
        var ciphertext = ArrayPool<byte>.Shared.Rent(defaultBlockSizeInBytes);
        var executions = (int)Math.Ceiling((decimal)sequenceSizeInBytes / defaultBlockSizeInBytes);
        for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
        {
            EncryptAsSingleBlock(plaintext, mainRules, borderRules, ciphertext, defaultBlockSizeInBytes);

            if (executionIdx == executions - 1)
            {
                bytesToCopy = sequenceSizeInBytes - (int)stream.Length;
            }

            for (int byteIdx = 0; byteIdx < bytesToCopy; ++byteIdx)
            {
                bw.Write((byte)(ciphertext[byteIdx] ^ plaintext[byteIdx]));
            }

            Util.Swap(ref plaintext, ref ciphertext);
        }
        bw.Flush();

        ArrayPool<byte>.Shared.Return(plaintext);
        ArrayPool<byte>.Shared.Return(ciphertext);

        return stream.ToArray();
    }

    public byte[] GenerateRandomIV(int? textSizeInBytes = null)
    {
        var defaultBlockSize = GetDefaultBlockSizeInBytes();
        byte[] initializationVector;
        if (textSizeInBytes is null || textSizeInBytes.Value < defaultBlockSize)
        {
            initializationVector = new byte[defaultBlockSize];
        }
        else
        {
            initializationVector = new byte[(int)textSizeInBytes.Value];
        }
        Util.FillArrayWithRandomData(initializationVector);
        return initializationVector;
    }
}