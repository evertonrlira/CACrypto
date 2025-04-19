using MersenneTwister;
using System.Security.Cryptography;

namespace CACrypto.Commons
{
    public class Util
    {
        public static readonly Byte[] BytePosValues = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

        public static int CalculateBlockCount(int plainTextLengthInBytes, int blockSizeInBytes)
        {
            var blockCount = (plainTextLengthInBytes / blockSizeInBytes);
            if (plainTextLengthInBytes % blockSizeInBytes != 0)
            {
                blockCount++;
            }
            return blockCount;
        }

        public static byte[] CloneByteArray(Span<byte> oldArray)
        {
            return oldArray.ToArray();
        }

        public static string CreateUniqueTempDirectory()
        {
            var uniqueTempDir = Path.GetFullPath(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            Directory.CreateDirectory(uniqueTempDir);
            return uniqueTempDir;
        }

        public static void CopyDirectory(string sourceDirectory, string targetDirectory)
        {
            var diSource = new DirectoryInfo(sourceDirectory);
            var diTarget = new DirectoryInfo(targetDirectory);

            CopyAll(diSource, diTarget);
        }

        public static void CopyAll(DirectoryInfo source, DirectoryInfo target)
        {
            Directory.CreateDirectory(target.FullName);

            // Copy each file into the new directory.
            foreach (FileInfo fi in source.GetFiles())
            {
                fi.CopyTo(Path.Combine(target.FullName, fi.Name), true);
            }

            // Copy each subdirectory using recursion.
            foreach (DirectoryInfo diSourceSubDir in source.GetDirectories())
            {
                DirectoryInfo nextTargetSubDir =
                    target.CreateSubdirectory(diSourceSubDir.Name);
                CopyAll(diSourceSubDir, nextTargetSubDir);
            }
        }

        public static byte[] XOR(byte[] w1, byte[] w2, int blockSize)
        {
            if (w1.Length != w2.Length)
            {
                throw new Exception("Words to be XORed had different size");
            }

            byte[] xorArray = new byte[blockSize];
            for (int idx = 0; idx < blockSize; ++idx)
            {
                xorArray[idx] = (byte)(w1[idx] ^ w2[idx]);
            }
            return xorArray;
        }

        public static void XOR(byte[] src01, int src01BeginIdx, byte[] src02, int src02BeginIdx, int xorLength, byte[] dst, int dstBeginIdx)
        {
            for (int idx = 0; idx < xorLength; ++idx)
            {
                dst[dstBeginIdx + idx] = (byte)(src01[src01BeginIdx + idx] ^ src02[src02BeginIdx + idx]);
            }
        }

        public static byte[] ChangeRandomBit(Span<byte> originalArray)
        {
            var newArray = Util.CloneByteArray(originalArray);

            var randomBitIdx = Util.GetRandomNumber(0, 8 * (originalArray.Length));
            ToggleBit(newArray, randomBitIdx);

            return newArray;
        }

        public static IEnumerable<byte[]> GetSecureRandomByteArrays(int sequenceSize, int sequenceCount)
        {
            var result = new List<byte[]>(sequenceCount);
            for (int i = 0; i < sequenceCount; i++)
            {
                var array = new byte[sequenceSize];
                FillArrayWithRandomData(array);
                result.Add(array);
            }
            return result;
        }

        public static int CountBits(byte[] sequence)
        {
            var sum = 0;
            foreach (var b in sequence)
            {
                for (var i = 0; i < 8; i++)
                {
                    sum += (0x1) & (b >> i);
                }
            }
            return sum;
        }

        public static float SpatialEntropyCalculusForBinary(Span<int> word)
        {
            int windowSize = 8;

            double optimalWindowSize = (Math.Log(word.Length) / Math.Log(2)); //windowSideDec = 7, word.Length = 128
            if (optimalWindowSize % 1 == 0)
            {
                windowSize = (int)optimalWindowSize;
            }
            else if (word.Length <= 8)
            {
                throw new Exception("Word length must be a power of two or larger than 8 bits");
            }

            int[] ocurrence = new int[(int)Math.Pow(2, windowSize)]; // int[128] ocurrence
            for (int wIdx = 0; wIdx < word.Length; wIdx++) // 0 <= wIdx < 128
            {
                int windowIdx = 0;
                for (int i = 0; i < windowSize; i++) // 0 <= i < 7
                {
                    windowIdx *= 2;
                    windowIdx += word[(wIdx + i) % word.Length];
                }

                ocurrence[windowIdx]++;
            }

            double entropySum = 0.0D;
            foreach (int ocNumber in ocurrence)
            {
                if (ocNumber != 0)
                {
                    entropySum += (((float)ocNumber / word.Length) * (Math.Log((float)ocNumber / word.Length) / Math.Log(2)));
                }
            }
            return (-1 * (float)entropySum) / windowSize;
        }

        public static double PopulationStandardDeviation(IEnumerable<float> values)
        {
            double avg = values.Average();
            return Math.Sqrt(values.Average(v => Math.Pow(v - avg, 2)));
        }

        public static void FillArrayWithRandomData(byte[] array)
        {
            Randoms.FastestInt32.NextBytes(array);
        }

        public static void ByteArrayToBinaryArray(ReadOnlySpan<byte> byteArray, int[] outputBinaryArray, int byteCount)
        {
            for (int byteIdx = 0; byteIdx < byteCount; byteIdx++)
            {
                for (int bitIdx = 0; bitIdx < 8; bitIdx++)
                {
                    outputBinaryArray[8 * byteIdx + bitIdx] = (byteArray[byteIdx] & BytePosValues[bitIdx]) > 0 ? 1 : 0;
                }
            }
        }

        public static int[] ByteSpanToBinaryArray(Span<byte> bytes)
        {
            var binaryArray = new int[8 * bytes.Length];
            ByteArrayToBinaryArray(bytes, binaryArray, bytes.Length);
            return binaryArray;
        }

        public static void BinaryArrayToByteArray(ReadOnlySpan<int> input, byte[] output, int outputSize)
        {
            int length = input.Length;
            if (length % 8 != 0)
                throw new ArgumentException("The binary array does not have a Length that can allows conversion to byte array");

            for (int byteIdx = 0; byteIdx < outputSize; byteIdx++)
            {
                var byteValue = 0x0;
                for (int bitIdx = 0; bitIdx < 8; bitIdx++)
                {
                    if (input[8 * byteIdx + bitIdx] == 1)
                    {
                        byteValue |= BytePosValues[bitIdx];
                    }
                }
                output[byteIdx] = (byte)byteValue;
            }
        }

        public static int GetRandomNumber(int minValue, int maxValueExclusive)
        {
            var randomPosIdx = Randoms.Next(minValue, maxValueExclusive);
            return randomPosIdx;
        }

        public static IEnumerable<IEnumerable<T>> GetPermutations<T>(IEnumerable<T> list, int length)
        {
            if (length == 1) return list.Select(t => new T[] { t });

            return GetPermutations(list, length - 1)
                .SelectMany(t => list.Where(e => !t.Contains(e)),
                    (t1, t2) => t1.Concat(new T[] { t2 }));
        }

        public static IEnumerable<T[]> Permutations<T>(T[] values, int fromInd = 0)
        {
            if (fromInd + 1 == values.Length)
                yield return values;
            else
            {
                foreach (var v in Permutations(values, fromInd + 1))
                    yield return v;

                for (var i = fromInd + 1; i < values.Length; i++)
                {
                    SwapValues(values, fromInd, i);
                    foreach (var v in Permutations(values, fromInd + 1))
                        yield return v;
                    SwapValues(values, fromInd, i);
                }
            }
        }

        private static void SwapValues<T>(T[] values, int pos1, int pos2)
        {
            if (pos1 != pos2)
            {
                T tmp = values[pos1];
                values[pos1] = values[pos2];
                values[pos2] = tmp;
            }
        }

        public static int[] LeftShift(Span<int> array)
        {
            Span<int> slice = [.. array[1..], array[0]];
            return slice.ToArray();
        }

        public static int[] RightShift(Span<int> array)
        {
            Span<int> slice = [array[^1], .. array[0..^1]];
            return slice.ToArray();
        }

        public static int OppositeBit(int bit)
        {
            return (bit == 0) ? 1 : 0;
        }

        public static int CircularIdx(int x, int window)
        {
            if (x >= 0)
            {
                return x % window;
            }
            else
            {
                x = -1 * x;
                x = x % window;
                return (window - x) % window;
            }
        }

        public static void Swap<T>(ref T firstObj, ref T secondObj)
        {
            (firstObj, secondObj) = (secondObj, firstObj);
        }

        public static string GetCurrentProjectDirectoryPath()
        {
            var currentProjectName = System.Reflection.Assembly.GetCallingAssembly().GetName().Name;
            var currentDirectory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (currentDirectory is not null && currentDirectory.Name != currentProjectName)
            {
                currentDirectory = currentDirectory.Parent;
            }
            return currentDirectory?.FullName ?? string.Empty;
        }

        public static void ToggleBit(Span<byte> self, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            self[byteIndex] ^= mask;
        }

        public static ToggleDirection GetRandomToggleDirection()
        {
            return (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), Util.GetRandomNumber(0, 2));
        }

        public static IEnumerable<byte[]> GetLowEntropyByteArrays(int blockSize, int inputSamplesCount)
        {
            var lowEntropySet = new List<byte[]>(inputSamplesCount);

            var arrayCountForGroup = inputSamplesCount / 8;

            // Group 01 - Create Arrays with 000...0
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                lowEntropySet.Add(array);
            }

            // Group 02 - Create Arrays with 111...1
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = 0xFF;
                }
                lowEntropySet.Add(array);
            }

            // Group 03 - Create Arrays with 0101...01
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = array[j] = 0x55;
                }
                lowEntropySet.Add(array);
            }

            // Group 04 - Create Arrays with 1010...10
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = array[j] = 0xAA;
                }
                lowEntropySet.Add(array);
            }

            // Group 05 - Create Arrays with alternating 00000000 and 11111111
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = (byte)(i % 2 == 0 ? 0x00 : 0xFF);
                }
                lowEntropySet.Add(array);
            }

            // Group 06 - Create Arrays with alternating 11111111 and 00000000
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = (byte)(i % 2 == 0 ? 0xFF : 0x00);
                }
                lowEntropySet.Add(array);
            }

            // Group 07 - Create Arrays with 000...0111...1
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = (byte)(j < (blockSize / 2) ? 0x00 : 0xFF);
                }
                lowEntropySet.Add(array);
            }

            // Group 08 - Create Arrays with 111...1000...0
            for (int i = 0; i < arrayCountForGroup; i++)
            {
                var array = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                {
                    array[j] = (byte)(j < (blockSize / 2) ? 0xFF : 0x00);
                }
                lowEntropySet.Add(array);
            }

            return lowEntropySet;
        }

        internal static void CopyPlaintextIntoBlock(byte[] plainText, byte[] blockPlaintext, int blockIdx, int blockSize)
        {
            int copyAmount;
            if (plainText.Length < blockPlaintext.Length)
            {
                CryptographicOperations.ZeroMemory(blockPlaintext);
                copyAmount = plainText.Length;
            }
            else
            {
                copyAmount = blockSize;
            }
            Buffer.BlockCopy(plainText, blockIdx * blockSize, blockPlaintext, 0, copyAmount);
        }
    }
}