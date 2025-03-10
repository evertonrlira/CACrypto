using MersenneTwister;
using System.Collections.Concurrent;
using System.Diagnostics;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.Intrinsics.X86;
using System.Buffers;

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

        internal static Rule[] ConvertOctalArrayToR1RuleArray(int[] octalArray, bool isLeftDirected = true)
        {
            Rule[] directedRules;
            if (isLeftDirected)
            {
                directedRules = new Rule[] {
                new Rule("01111000"), // R30
                new Rule("10110100"), // R45
                new Rule("11010010"), // R75
                new Rule("00011110"), // R120
                new Rule("11100001"), // R135
                new Rule("00101101"), // R180
                new Rule("01001011"), // R210
                new Rule("10000111")  // R225
            };
            }
            else
            {
                directedRules = new Rule[] {
                new Rule("01101010"), // R86
                new Rule("10011010"), // R89
                new Rule("10100110"), // R101
                new Rule("01010110"), // R106
                new Rule("10101001"), // R149
                new Rule("01011001"), // R154
                new Rule("01100101"), // R166
                new Rule("10010101")  // R169
            };
            }
            return octalArray.Select(octal => directedRules[octal]).ToArray();
        }

        public static byte[] CloneByteArray(Span<byte> oldArray)
        {
            //var newArray = new byte[oldArray.Length];
            //Buffer.BlockCopy(oldArray, 0, newArray, 0, oldArray.Length);
            return oldArray.ToArray();
        }

        public static string CreateUniqueTempDirectory()
        {
            var uniqueTempDir = Path.GetFullPath(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            Directory.CreateDirectory(uniqueTempDir);
            return uniqueTempDir;
        }

        public static void CopyByteArrayTo(byte[] originArray, byte[] dstArray)
        {
            Buffer.BlockCopy(originArray, 0, dstArray, 0, originArray.Length);
        }

        public static int[] CopyLatticeExpandingForWrap(int[] oldLattice, int expansionSize)
        {
            var newLattice = new int[oldLattice.Length + 2 * expansionSize];
            Buffer.BlockCopy(oldLattice, 0, newLattice, expansionSize * sizeof(int), oldLattice.Length * sizeof(int));

            for (int wrapIdx = 0; wrapIdx < expansionSize; ++wrapIdx)
            {
                newLattice[wrapIdx] = newLattice[newLattice.Length - (2 * expansionSize) + wrapIdx];
                newLattice[newLattice.Length - expansionSize + wrapIdx] = newLattice[(2 * expansionSize) + wrapIdx];
            }
            return newLattice;
        }

        public static int[] CopyLatticeShrinking(int[] oldLattice, int shrinkageSize)
        {
            var newLattice = new int[oldLattice.Length - 2 * shrinkageSize];
            Buffer.BlockCopy(oldLattice, shrinkageSize * sizeof(int), newLattice, 0, newLattice.Length * sizeof(int));
            return newLattice;
        }

        public static int GetBitParityFromOctalArray(int[] octalArray)
        {
            bool parity = false;
            foreach (int octal in octalArray)
            {
                if (octal == 1 || octal == 2 || octal == 4 || octal == 7)
                    parity = !parity;
            }
            return parity ? 1 : 0;
        }

        // Usage: Benchmark(() => { /* your code */ }, 100);
        public static void Benchmark(Action act, int iterations, bool newLine = true)
        {
            GC.Collect();
            act.Invoke(); // run once outside of loop to avoid initialization costs
            Stopwatch sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                act.Invoke();
            }
            sw.Stop();
            if (newLine)
                Console.WriteLine(((double)sw.ElapsedMilliseconds / (double)iterations).ToString() + " ms");
            else
                Console.Write(((double)sw.ElapsedMilliseconds / (double)iterations).ToString() + " ms" + Environment.NewLine);
            //Console.WriteLine((sw.ElapsedMilliseconds).ToString() + " ms");
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

        public static byte[] XOR(byte[] w1, byte[] w2)
        {
            if (w1.Length != w2.Length)
            {
                throw new Exception("Words to be XORed had different size");
            }

            byte[] xorArray = new byte[w1.Length];
            for (int idx = 0; idx < xorArray.Length; ++idx)
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

        public static int[] StringToBitArray(string str)
        {
            return str.Select(c => (int)c - 48).ToArray();
        }

        public static string BinaryArrayToString(int[] bitArray, char falseChar = '0', char trueChar = '1')
        {
            return String.Join("", bitArray.Select(a => (a == 0 ? falseChar : trueChar)).ToArray());
        }

        public static void FillArrayWithRandomData(byte[] array)
        {
            Randoms.FastestInt32.NextBytes(array);
        }

        public static void ByteArrayToBinaryArray(Span<byte> byteArray, int[] outputBinaryArray)
        {
            int length = byteArray.Length;

            for (int byteIdx = 0; byteIdx < length; byteIdx++)
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
            ByteArrayToBinaryArray(bytes, binaryArray);
            return binaryArray;
        }

        public static byte[] BinaryArrayToByteArray(ReadOnlySpan<int> binaryArray)
        {
            int length = binaryArray.Length;
            if (length % 8 != 0)
                throw new ArgumentException("The binary array does not have a Length that can allows conversion to byte array");

            var byteLength = length / 8;
            var byteArray = new byte[byteLength]; // TODO: Optimize
            for (int i = 0; i < byteLength; i++)
            {
                var byteValue = 0;
                var basePos = i * 8;
                if (binaryArray[basePos] == 1) { byteValue += 128; }
                if (binaryArray[basePos + 1] == 1) { byteValue += 64; }
                if (binaryArray[basePos + 2] == 1) { byteValue += 32; }
                if (binaryArray[basePos + 3] == 1) { byteValue += 16; }
                if (binaryArray[basePos + 4] == 1) { byteValue += 8; }
                if (binaryArray[basePos + 5] == 1) { byteValue += 4; }
                if (binaryArray[basePos + 6] == 1) { byteValue += 2; }
                if (binaryArray[basePos + 7] == 1) { byteValue += 1; }
                byteArray[i] = (byte)byteValue;
            }
            return byteArray;
        }

        public static T? GetRandomElement<T>(IEnumerable<T> list)
        {
            // If there are no elements in the collection, return the default value of T
            if (!list.Any())
                return default;

            // Guids as well as the hash code for a guid will be unique and thus random        
            int hashCode = Math.Abs(Guid.NewGuid().GetHashCode());
            return list.ElementAt(hashCode % list.Count());
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
            Span<int> slice = [..array[1..], array[0]];
            return slice.ToArray();
        }

        public static int[] RightShift(Span<int> array)
        {
            Span<int> slice = [array[^1], ..array[0..^1]];
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
                return window - x;
            }
        }

        public static void Shuffle<T>(IList<T> source)
        {
            var length = source.Count;

            for (var currentIndex = 0; currentIndex < length; currentIndex++)
            {
                var swapIndex = Randoms.Next(currentIndex, length);
                Swap(source, currentIndex, swapIndex);
            }
        }

        public static void ShuffleStrong<T>(IList<T> source)
        {
            var length = source.Count;

            for (var currentIndex = 0; currentIndex < length; currentIndex++)
            {
                var swapIndex = Randoms.Next(currentIndex, length);
                Swap(source, currentIndex, swapIndex);
            }
        }

        public static void Swap<T>(ref T firstObj, ref T secondObj)
        {
            (firstObj, secondObj) = (secondObj, firstObj);
        }

        public static void Swap<T>(ref Span<T> firstObj, ref Span<T> secondObj)
        {
            var swapAux = firstObj;
            firstObj = secondObj;
            secondObj = swapAux;
        }

        internal static void Swap<T>(IList<T> source, int firstIndex, int secondIndex)
        {
            (source[secondIndex], source[firstIndex]) = (source[firstIndex], source[secondIndex]);
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

        public static void SetBit(byte[] self, int index, bool value)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            self[byteIndex] = (byte)(value ? (self[byteIndex] | mask) : (self[byteIndex] & ~mask));
        }

        public static void ToggleBit(Span<byte> self, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            self[byteIndex] ^= mask;
        }

        public static bool GetBit(byte[] self, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            return (self[byteIndex] & mask) != 0;
        }

        public static ToggleDirection GetRandomToggleDirection()
        {
            return (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), Util.GetRandomNumber(0, 2));
        }
    }
}