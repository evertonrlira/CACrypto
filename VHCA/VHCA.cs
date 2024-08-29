using CACrypto.Commons;
using System.Linq;

namespace VHCA_Crypto
{
    public class VHCA
    {
        public const int KeySizeInBytes = 48;
        public const int BlockSizeInBytes = 16;
        public const int BlockSizeInBits = 128;
        public const int RuleLength = 512;
        public const int KeyBitsToRuleFactor = 3; // 3 bits are needed to represent 1 rule
        private static readonly int Radius = 1;
        private static readonly int DoubleRadius = 2;
        private static readonly int BinaryCutMask = 0x7FFFFFFF >> (30 - (DoubleRadius));

        private static readonly Rule[] MainRulesLeftToggleAlphabet = new Rule[] {
            new Rule("00011110"),
            new Rule("00101101"),
            new Rule("01001011"),
            new Rule("01111000"),
            new Rule("10000111"),
            new Rule("10110100"),
            new Rule("11010010"),
            new Rule("11100001")
        };

        private static readonly Rule[] MainRulesRightToggleAlphabet = new Rule[] {
            new Rule("01010110"),
            new Rule("01011001"),
            new Rule("01100101"),
            new Rule("01101010"),
            new Rule("10010101"),
            new Rule("10011010"),
            new Rule("10100110"),
            new Rule("10101001")
        };

        private static readonly Rule[] BorderRulesLeftToggleAlphabet = new Rule[] {
            new Rule("00001111"),
            new Rule("00001111"),
            new Rule("00001111"),
            new Rule("00001111"),
            new Rule("11110000"),
            new Rule("11110000"),
            new Rule("11110000"),
            new Rule("11110000")
        };

        private static readonly Rule[] BorderRulesRightToggleAlphabet = new Rule[] {
            new Rule("01010101"),
            new Rule("01010101"),
            new Rule("01010101"),
            new Rule("01010101"),
            new Rule("10101010"),
            new Rule("10101010"),
            new Rule("10101010"),
            new Rule("10101010")
        };

        public static VHCACryptoKey GenerateRandomKey(int blockSize, ToggleDirection toggleDirection)
        {
            return VHCACryptoKey.GenerateRandomKey(blockSize, toggleDirection);
        }

        public static Rule[] DeriveMainRulesFromKey(int[] keyBits, ToggleDirection direction)
        {
            var mainRules = new Rule[keyBits.Length / KeyBitsToRuleFactor];
            var alphabet =
                direction == ToggleDirection.Left ?
                    MainRulesLeftToggleAlphabet :
                        MainRulesRightToggleAlphabet;

            int currentOctalIdx = 0;
            for (int idxBit = 0; idxBit < keyBits.Length; idxBit += KeyBitsToRuleFactor)
            {
                int currentOctalValue = (keyBits[idxBit] << 2) + (keyBits[idxBit + 1] << 1) + keyBits[idxBit + 2];
                mainRules[currentOctalIdx] = alphabet[currentOctalValue];
                currentOctalIdx++;
            }
            return mainRules;
        }

        public static Rule[] DeriveBorderRulesFromKey(int[] keyBits, ToggleDirection direction)
        {
            var borderRules = new Rule[keyBits.Length / VHCA.KeyBitsToRuleFactor];
            var alphabet =
                direction == ToggleDirection.Left ?
                    BorderRulesLeftToggleAlphabet :
                        BorderRulesRightToggleAlphabet;

            int currentOctalIdx = 0;
            for (int idxBit = 0; idxBit < keyBits.Length; idxBit += VHCA.KeyBitsToRuleFactor)
            {
                borderRules[currentOctalIdx] = keyBits[idxBit] == 0 ? alphabet[0x00] : alphabet[0x04];
                currentOctalIdx++;
            }
            return borderRules;
        }

        public static byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey)
        {
            Rule[] mainRules = VHCA.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
            Rule[] borderRules = VHCA.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

            return VHCA.BlockEncrypt(plainText, mainRules, borderRules, iterations: 8 * plainText.Length);
        }

        public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
        {
            int[] preImage = Util.ByteArrayToBinaryArray(initialLattice);
            int latticeLength = preImage.Length;
            int[] image = new int[latticeLength];
            int[] finalLattice;
            int[] swapAux;

            var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
            var borderLength = DoubleRadius;
            int borderLeftCellIdx = latticeLength - borderLength;
            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                SequentialEvolveBits(preImage, mainRules, borderRules, borderLeftCellIdx, image);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
                if (toggleDirection == ToggleDirection.Left)
                {
                    borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx + DoubleRadius, latticeLength);
                }
                else
                {
                    borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx - DoubleRadius, latticeLength);
                }
            }
            finalLattice = preImage;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static int[] SequentialEvolveBits(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image)
        {   
            var latticeLength = preImage.Length;

            // Initial Bits
            var currentBitInPreImageIdx = 0;
            var currentBitInImageIdx = 0;
            var neighSum = 0;
            foreach (var _ in Enumerable.Range(0, DoubleRadius))
            {
                neighSum |= preImage[currentBitInPreImageIdx];
                neighSum <<= 1;
                currentBitInImageIdx = currentBitInPreImageIdx;
                currentBitInPreImageIdx = Util.CircularIdx(currentBitInPreImageIdx + 1, latticeLength);
            }
            
            foreach (var _ in Enumerable.Range(0, latticeLength))
            {
                neighSum |= preImage[currentBitInPreImageIdx];
                if (currentBitInImageIdx == imageBorderLeftCellIdx || currentBitInImageIdx == imageBorderLeftCellIdx + 1)
                {
                    image[currentBitInImageIdx] = borderRules[currentBitInImageIdx].ResultBitForNeighSum[neighSum];
                }
                else
                {
                    image[currentBitInImageIdx] = mainRules[currentBitInImageIdx].ResultBitForNeighSum[neighSum];
                }
                neighSum <<= 1; neighSum &= BinaryCutMask;
                currentBitInImageIdx = currentBitInPreImageIdx;
                currentBitInPreImageIdx = Util.CircularIdx(currentBitInPreImageIdx + 1, latticeLength);
            }
            return image;
        }

        public static byte[] BlockDecrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey)
        {
            Rule[] mainRules = VHCA.DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
            Rule[] borderRules = VHCA.DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

            return VHCA.BlockDecrypt(cipherText, mainRules, borderRules, iterations: 8 * cipherText.Length);
        }

        public static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
        {
            int[] image = Util.ByteArrayToBinaryArray(initialLattice);
            int latticeLength = image.Length;
            int[] preImage = new int[image.Length];
            int[] finalLattice;
            int[] swapAux;

            var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
            var borderLength = DoubleRadius;
            int borderLeftCellIdx = latticeLength - borderLength;
            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                // Get Border Left Cell Index for the PreImage
                if (toggleDirection == ToggleDirection.Left)
                {
                    borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx - DoubleRadius, latticeLength);
                }
                else
                {
                    borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx + DoubleRadius, latticeLength);
                }
                PreImageCalculusBits(image, mainRules, borderRules, borderLeftCellIdx, preImage, toggleDirection);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = image;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static void PreImageCalculusBits(int[] image, Rule[] mainRules, Rule[] borderRules, int preImageBorderLeftCellIdx, int[] preImage, ToggleDirection toggleDirection)
        {
            var latticeLength = image.Length;
            int currentBitInPreImageIdx;
            if (toggleDirection == ToggleDirection.Left)
            {
                currentBitInPreImageIdx = preImageBorderLeftCellIdx;
            }
            else
            {
                currentBitInPreImageIdx = preImageBorderLeftCellIdx + Radius; // TODO: Revisar
            }

            int neighSum = 0;
            int toggleDirectionShift = toggleDirection == ToggleDirection.Left ? -1 : 1;
            int currentBitInImageIdx = Util.CircularIdx(currentBitInPreImageIdx + (toggleDirection == ToggleDirection.Left ? 1 : -1), latticeLength);
            foreach (var _ in Enumerable.Range(0, latticeLength))
            {
                if (currentBitInImageIdx == preImageBorderLeftCellIdx || currentBitInImageIdx == preImageBorderLeftCellIdx + 1)
                {
                    preImage[currentBitInPreImageIdx] = (borderRules[currentBitInImageIdx].ResultBitForNeighSum[0] == 0) 
                        ? image[currentBitInImageIdx] 
                        : Util.OppositeBit(image[currentBitInImageIdx]);
                } 
                else 
                {
                    preImage[currentBitInPreImageIdx] = (mainRules[currentBitInImageIdx].ResultBitForNeighSum[neighSum] == image[currentBitInImageIdx])
                        ? 0
                        : 1;
                }

                if (toggleDirection == ToggleDirection.Left)
                {
                    // Set new bit as MSB
                    neighSum |= (preImage[currentBitInPreImageIdx] << DoubleRadius);
                    // Erase previous LSB
                    neighSum >>= 1;
                }
                else
                {
                    // Set new bit as LSB
                    neighSum |= preImage[currentBitInPreImageIdx];
                    // Shift Left and Erase previous MSB
                    neighSum <<= 1; neighSum &= BinaryCutMask;
                }

                currentBitInImageIdx = currentBitInPreImageIdx;
                currentBitInPreImageIdx = Util.CircularIdx(currentBitInPreImageIdx + toggleDirectionShift, latticeLength);
            }
        }
    }
}
