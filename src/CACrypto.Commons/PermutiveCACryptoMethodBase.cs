using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CACrypto.Commons
{
    public abstract class PermutiveCACryptoMethodBase : CryptoMethodBase
    {
        public abstract byte[] Encrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode = CipherMode.CBC);

        public abstract byte[] Decrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode = CipherMode.CBC);

        public PermutiveCACryptoKey GenerateRandomGenericKeyInBits(int blockSizeInBits)
        {
            var toggleDirection = Util.GetRandomToggleDirection();
            return GenerateRandomGenericKeyInBits(blockSizeInBits, toggleDirection);
        }

        public abstract PermutiveCACryptoKey GenerateRandomGenericKeyInBits(int blockSizeInBits, ToggleDirection toggleDirection);

        public PermutiveCACryptoKey GenerateRandomGenericKey(int blockSizeInBytes)
        {
            var toggleDirection = Util.GetRandomToggleDirection();
            return GenerateRandomGenericKeyInBits(8 * blockSizeInBytes, toggleDirection);
        }

        public PermutiveCACryptoKey GenerateRandomGenericKey(int blockSizeInBytes, ToggleDirection toggleDirection)
        {
            return GenerateRandomGenericKeyInBits(8 * blockSizeInBytes, toggleDirection);
        }

        public abstract byte[] EncryptAsSingleBlock(byte[] plainText, PermutiveCACryptoKey cryptoKey);

        public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
        {
            using var stream = new MemoryStream();
            var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
            var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
            var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
            var cryptoKey = GenerateRandomGenericKeyInBits(defaultBlockSizeInBits);
            byte[] plainText = initialSeed;

            WritePseudoRandomGeneratedSequenceToBinaryStream(stream, initialSeed, cryptoKey, sequenceSizeInBytes);

            return stream.ToArray();
        }

        protected abstract void WritePseudoRandomGeneratedSequenceToBinaryStream(MemoryStream stream, byte[] initialSeed, PermutiveCACryptoKey cryptoKey, int sequenceSizeInBytes);

        /// <summary>
        /// Encrypt plaintext using CTR (counter) mode of operation
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cryptoKey"></param>
        /// <param name="initializationVector"></param>
        /// <returns></returns>
        public byte[] Encrypt_CTR(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
        {
            int blockSize = GetDefaultBlockSizeInBytes();
            int blockCount = Util.CalculateBlockCount(plainText.Length, blockSize);
            var paddedPlaintext = new Byte[blockCount * blockSize];
            Buffer.BlockCopy(plainText, 0, paddedPlaintext, 0, plainText.Length);

            var cipherText = new Byte[paddedPlaintext.Length];

            Parallel.For(0, blockCount, (counterIdx) =>
            {
                var input = new Byte[blockSize];
                BinaryPrimitives.WriteInt64BigEndian(input, counterIdx);
                Buffer.BlockCopy(initializationVector, 0, input, blockSize / 2, blockSize / 2);

                var encrypted = EncryptAsSingleBlock(input, cryptoKey);

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

        /// <summary>
        /// Decrypt ciphertext using CTR (counter) mode of operation
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="cryptoKey"></param>
        /// <param name="initializationVector"></param>
        /// <returns></returns>
        public byte[] Decrypt_CTR(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector)
        {
            return Encrypt_CTR(cipherText, cryptoKey, initializationVector);
        }
    }
}