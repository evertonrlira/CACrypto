using CACrypto.Commons;
using System;
using System.Threading.Tasks;

namespace CACrypto.VHCA;

public class VHCACrypto
{
    public const string Name = "VHCA";
    public const int KeySizeInBytes = 48;
    public const int DefaultBlockSizeInBytes = 16;
    public const int DefaultBlockSizeInBits = 128;
    public const int RuleLength = 512;
    public const int KeyBitsToRuleFactor = 3; // 3 bits are needed to represent 1 rule
    private static readonly int Radius = 1;
    private static readonly int DoubleRadius = 2;

    public static Rule[] DeriveMainRulesFromKey(int[] keyBits, ToggleDirection direction)
    {
        var mainRules = new Rule[keyBits.Length / KeyBitsToRuleFactor];
        var alphabet =
            direction == ToggleDirection.Left ?
                VHCARuleAlphabet.MainRulesLeftToggleAlphabet :
                    VHCARuleAlphabet.MainRulesRightToggleAlphabet;

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
        var borderRules = new Rule[keyBits.Length / KeyBitsToRuleFactor];
        var alphabet =
            direction == ToggleDirection.Left ?
                VHCARuleAlphabet.BorderRulesLeftToggleAlphabet :
                    VHCARuleAlphabet.BorderRulesRightToggleAlphabet;

        int currentOctalIdx = 0;
        for (int idxBit = 0; idxBit < keyBits.Length; idxBit += KeyBitsToRuleFactor)
        {
            borderRules[currentOctalIdx] = keyBits[idxBit] == 0 ? alphabet[0x00] : alphabet[0x04];
            currentOctalIdx++;
        }
        return borderRules;
    }

    public byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, int[] bufferArray = null)
    {
        Rule[] mainRules = DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
        Rule[] borderRules = DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

        return BlockEncrypt(plainText, mainRules, borderRules, bufferArray);
    }

    public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int[] bufferArray = null)
    {
        var preImage = Util.ByteArrayToBinaryArray(initialLattice);
        int latticeLength = preImage.Length;
        int iterations = latticeLength;
        var image = bufferArray ?? new int[latticeLength];

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        var borderLength = DoubleRadius;
        int borderLeftmostCellIdx = latticeLength - borderLength;
        int borderShift = toggleDirection == ToggleDirection.Left ? DoubleRadius : -DoubleRadius;
        for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
        {
            SequentialEvolveLattice(preImage, mainRules, borderRules, borderLeftmostCellIdx, image);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);

            borderLeftmostCellIdx = Util.CircularIdx(borderLeftmostCellIdx + borderShift, latticeLength);
        }
        return Util.BinaryArrayToByteArray(preImage);
    }

    protected static void EvolveLatticeSlice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image, int sliceStartInclusiveIdx, int sliceEndExclusiveIdx)
    {
        bool isBorderCell;
        int blockSize = preImage.Length;
        int startingBinaryFactor = 1 << DoubleRadius;
        int binaryFactor;
        for (int centralCellIdx = sliceStartInclusiveIdx; centralCellIdx < sliceEndExclusiveIdx; centralCellIdx++)
        {
            binaryFactor = startingBinaryFactor;
            int neighSum = 0;
            for (int neighCellShiftIdx = -Radius; neighCellShiftIdx <= Radius; neighCellShiftIdx++)
            {
                neighSum += binaryFactor * preImage[Util.CircularIdx(centralCellIdx + neighCellShiftIdx, blockSize)];
                binaryFactor >>= 1;
            }

            isBorderCell = (centralCellIdx >= imageBorderLeftCellIdx && centralCellIdx < imageBorderLeftCellIdx + DoubleRadius);
            if (isBorderCell)
            {
                image[centralCellIdx] = borderRules[centralCellIdx].ResultBitForNeighSum[neighSum];
            }
            else
            {
                image[centralCellIdx] = mainRules[centralCellIdx].ResultBitForNeighSum[neighSum];
            }
        }
    }

    private static int[] SequentialEvolveLattice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image)
    {
        EvolveLatticeSlice(preImage, mainRules, borderRules, imageBorderLeftCellIdx, image, 0, preImage.Length);
        return image;
    }

    private static int[] ParallelEvolveLattice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image)
    {
        var latticeLength = preImage.Length;
        var slices = Environment.ProcessorCount;
        var sliceSize = latticeLength / slices;

        Parallel.For(0, slices, (sliceIdx) =>
        {
            var sliceStartInclusiveIdx = sliceIdx * sliceSize;
            var sliceEndExclusiveIdx = ((sliceIdx + 1) * sliceSize);
            EvolveLatticeSlice(preImage, mainRules, borderRules, imageBorderLeftCellIdx, image, sliceStartInclusiveIdx, sliceEndExclusiveIdx);
        });

        return image;
    }

    public static byte[] BlockDecrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey)
    {
        Rule[] mainRules = DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
        Rule[] borderRules = DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

        return BlockDecrypt(cipherText, mainRules, borderRules);
    }

    public static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules)
    {
        int[] image = Util.ByteArrayToBinaryArray(initialLattice);
        int latticeLength = image.Length;
        int iterations = latticeLength;
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
            currentBitInPreImageIdx = preImageBorderLeftCellIdx + Radius;
        }

        int neighSum = 0;
        int toggleDirectionShift = toggleDirection == ToggleDirection.Left ? -1 : 1;
        int currentBitInImageIdx = Util.CircularIdx(currentBitInPreImageIdx + (toggleDirection == ToggleDirection.Left ? 1 : -1), latticeLength);
        int BinaryCutMask = 0x7FFFFFFF >> 30 - DoubleRadius;
        foreach (var _ in image)
        {
            if (currentBitInImageIdx == preImageBorderLeftCellIdx || currentBitInImageIdx == preImageBorderLeftCellIdx + 1)
            {
                preImage[currentBitInPreImageIdx] = borderRules[currentBitInImageIdx].ResultBitForNeighSum[0] == 0
                    ? image[currentBitInImageIdx]
                    : Util.OppositeBit(image[currentBitInImageIdx]);
            }
            else
            {
                preImage[currentBitInPreImageIdx] = mainRules[currentBitInImageIdx].ResultBitForNeighSum[neighSum] == image[currentBitInImageIdx]
                    ? 0
                    : 1;
            }

            if (toggleDirection == ToggleDirection.Left)
            {
                // Set new bit as MSB
                neighSum |= preImage[currentBitInPreImageIdx] << DoubleRadius;
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
