using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CACrypto.Commons;

public abstract class PermutiveCACryptoMethodBase(string algorithmName) : CryptoMethodBase(algorithmName)
{
    public abstract Rule[] DeriveMainRulesFromKey(PermutiveCACryptoKey cryptoKey);
    public abstract Rule[] DeriveBorderRulesFromKey(PermutiveCACryptoKey cryptoKey);

    public byte[] Encrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, OperationMode operationMode = OperationMode.CTR)
    {
        return operationMode switch
        {
            OperationMode.ECB => Encrypt_ECB(plainText, cryptoKey),
            OperationMode.CBC => Encrypt_CBC(plainText, cryptoKey, initializationVector),
            OperationMode.CTR => Encrypt_CTR(plainText, cryptoKey, initializationVector),
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

        Parallel.For(0, blockCount, (blockIdx) =>
        {
            var newBlock = new byte[blockSize];
            Buffer.BlockCopy(plainText, blockIdx * blockSize, newBlock, 0, blockSize);

            newBlock = EncryptAsSingleBlock(newBlock, mainRules, borderRules);
            Buffer.BlockCopy(newBlock, 0, cipherText, blockIdx * blockSize, blockSize);
        });
        return cipherText;
    }

    private byte[] Encrypt_CBC(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(plainText.Length, blockSize);
        var cipherText = new byte[blockCount * blockSize];
        var xorVector = Util.CloneByteArray(initializationVector);

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        for (int blockIdx = 0; blockIdx < blockCount; ++blockIdx)
        {
            var newBlock = new byte[blockSize];
            Buffer.BlockCopy(plainText, blockIdx * blockSize, newBlock, 0, blockSize);

            for (int byteIdx = 0; byteIdx < blockSize; ++byteIdx)
            {
                newBlock[byteIdx] ^= xorVector[byteIdx];
            }

            newBlock = EncryptAsSingleBlock(newBlock, mainRules, borderRules);
            Buffer.BlockCopy(newBlock, 0, xorVector, 0, blockSize);
            Buffer.BlockCopy(newBlock, 0, cipherText, blockIdx * blockSize, blockSize);
        }
        return cipherText;
    }

    public byte[] Encrypt_CTR(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        int blockSize = GetDefaultBlockSizeInBytes();
        int blockCount = Util.CalculateBlockCount(plainText.Length, blockSize);
        var paddedPlaintext = new Byte[blockCount * blockSize];
        Buffer.BlockCopy(plainText, 0, paddedPlaintext, 0, plainText.Length);

        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        var cipherText = new Byte[paddedPlaintext.Length];

        Parallel.For(0, blockCount, (counterIdx) =>
        {
            var input = new Byte[blockSize];
            BinaryPrimitives.WriteInt64BigEndian(input, counterIdx);
            Buffer.BlockCopy(initializationVector, 0, input, blockSize / 2, blockSize / 2);

            var encrypted = EncryptAsSingleBlock(input, mainRules, borderRules);

            var src01 = encrypted;
            var src01BeginIdx = 0;
            var src02 = paddedPlaintext;
            var src02BeginIdx = counterIdx * blockSize;
            var xorLength = blockSize;
            var dst = cipherText;
            var dstBeginIdx = counterIdx * blockSize;
            Util.XOR(src01, src01BeginIdx, src02, src02BeginIdx, xorLength, dst, dstBeginIdx);
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

        Parallel.For(0, blockCount, new ParallelOptions() { MaxDegreeOfParallelism = 2 }, (blockIdx) =>
        {
            var newBlock = new byte[blockSize];
            Buffer.BlockCopy(cipherText, blockIdx * blockSize, newBlock, 0, blockSize);
            newBlock = DecryptAsSingleBlock(newBlock, mainRules, borderRules);
            Buffer.BlockCopy(newBlock, 0, plainText, blockIdx * blockSize, blockSize);
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

        Parallel.For(0, blockCount, new ParallelOptions() { MaxDegreeOfParallelism = 2 }, (blockIdx) =>
        {
            var newBlock = new byte[blockSize];
            Buffer.BlockCopy(cipherText, blockIdx * blockSize, newBlock, 0, blockSize);
            newBlock = DecryptAsSingleBlock(newBlock, mainRules, borderRules);

            byte[] xorVector;
            if (blockIdx != 0)
            {
                xorVector = new byte[blockSize];
                Buffer.BlockCopy(cipherText, (blockIdx - 1) * blockSize, xorVector, 0, blockSize);
            }
            else
            {
                xorVector = Util.CloneByteArray(initializationVector);
            }

            for (int byteIdx = 0; byteIdx < blockSize; ++byteIdx)
            {
                newBlock[byteIdx] ^= xorVector[byteIdx];
            }

            Buffer.BlockCopy(newBlock, 0, plainText, blockIdx * blockSize, blockSize);
        });
        return plainText;
    }

    public byte[] Decrypt_CTR(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
    {
        return Encrypt_CTR(cipherText, cryptoKey, initializationVector);
    }

    public PermutiveCACryptoKey GenerateRandomGenericKey(int? blockSizeInBytes = null, ToggleDirection? toggleDirection = null)
    {
        blockSizeInBytes ??= GetDefaultBlockSizeInBytes();
        toggleDirection ??= Util.GetRandomToggleDirection();
        return GenerateRandomGenericKey(blockSizeInBytes, toggleDirection);
    }

    public abstract byte[] EncryptAsSingleBlock(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules);
    public byte[] EncryptAsSingleBlock(byte[] plainText, PermutiveCACryptoKey cryptoKey)
    {
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        return EncryptAsSingleBlock(plainText, mainRules, borderRules);
    }

    public abstract byte[] DecryptAsSingleBlock(byte[] cipherText, Rule[] mainRules, Rule[] borderRules);
    public byte[] DecryptAsSingleBlock(byte[] cipherText, PermutiveCACryptoKey cryptoKey)
    {
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        return DecryptAsSingleBlock(cipherText, mainRules, borderRules);
    }

    public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
    {
        using var stream = new MemoryStream();
        var bw = new BinaryWriter(stream);

        var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
        var cryptoKey = GenerateRandomGenericKey(defaultBlockSizeInBytes);
        var mainRules = DeriveMainRulesFromKey(cryptoKey);
        var borderRules = DeriveBorderRulesFromKey(cryptoKey);

        var plainText = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
        var executions = sequenceSizeInBytes / defaultBlockSizeInBytes;
        for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
        {
            var cipherText = EncryptAsSingleBlock(plainText, mainRules, borderRules);

            for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
            {
                bw.Write((byte)(cipherText[byteIdx] ^ plainText[byteIdx]));
            }
            plainText = cipherText;
        }
        bw.Flush();

        return stream.ToArray();
    }
}