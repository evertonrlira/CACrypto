using CACrypto.Commons;
using System;
using System.Buffers;
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

    public static Rule[] DeriveMainRulesFromKey(Span<int> keyBits, ToggleDirection direction)
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

    public static Rule[] DeriveBorderRulesFromKey(Span<int> keyBits, ToggleDirection direction)
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

    public static void BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] ciphertext, int blockSize)
    {
        Rule[] mainRules = DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
        Rule[] borderRules = DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

        BlockEncrypt(plainText, mainRules, borderRules, ciphertext, blockSize);
    }

    public static void BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        int latticeLengthInBits = 8 * latticeSize;
        var image = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        var preImage = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        Util.ByteArrayToBinaryArray(initialLattice, preImage);

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        var borderLength = DoubleRadius;
        int borderLeftmostCellIdx = latticeLengthInBits - borderLength;
        int borderShift = toggleDirection == ToggleDirection.Left ? DoubleRadius : -DoubleRadius;
        for (int iterationIdx = 0; iterationIdx < latticeLengthInBits; ++iterationIdx)
        {
            SequentialEvolveLattice(preImage, mainRules, borderRules, borderLeftmostCellIdx, image, latticeLengthInBits);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);

            borderLeftmostCellIdx = Util.CircularIdx(borderLeftmostCellIdx + borderShift, latticeLengthInBits);
        }
        Util.BinaryArrayToByteArray(preImage, finalLattice, latticeSize);
        ArrayPool<int>.Shared.Return(image, true);
        ArrayPool<int>.Shared.Return(preImage, true);
    }

    protected static void EvolveLatticeSlice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image, int sliceStartInclusiveIdx, int sliceEndExclusiveIdx, int latticeSize)
    {
        int startingBinaryFactor = 1 << DoubleRadius;
        int binaryFactor;
        for (int centralCellIdx = sliceStartInclusiveIdx; centralCellIdx < sliceEndExclusiveIdx; centralCellIdx++)
        {
            binaryFactor = startingBinaryFactor;
            int neighSum = 0;
            for (int neighCellShiftIdx = -Radius; neighCellShiftIdx <= Radius; neighCellShiftIdx++)
            {
                neighSum += binaryFactor * preImage[Util.CircularIdx(centralCellIdx + neighCellShiftIdx, latticeSize)];
                binaryFactor >>= 1;
            }

            if (IsBorderCell(centralCellIdx, imageBorderLeftCellIdx, latticeSize))
            {
                image[centralCellIdx] = borderRules[centralCellIdx].ResultBitForNeighSum[neighSum];
            }
            else
            {
                image[centralCellIdx] = mainRules[centralCellIdx].ResultBitForNeighSum[neighSum];
            }
        }
    }

    private static int[] SequentialEvolveLattice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image, int latticeSize)
    {
        EvolveLatticeSlice(preImage, mainRules, borderRules, imageBorderLeftCellIdx, image, 0, latticeSize, latticeSize);
        return image;
    }

    private static int[] ParallelEvolveLattice(int[] preImage, Rule[] mainRules, Rule[] borderRules, int imageBorderLeftCellIdx, int[] image, int latticeSize)
    {
        var slices = Environment.ProcessorCount;
        var sliceSize = latticeSize / slices;

        Parallel.For(0, slices, (sliceIdx) =>
        {
            var sliceStartInclusiveIdx = sliceIdx * sliceSize;
            var sliceEndExclusiveIdx = ((sliceIdx + 1) * sliceSize);
            EvolveLatticeSlice(preImage, mainRules, borderRules, imageBorderLeftCellIdx, image, sliceStartInclusiveIdx, sliceEndExclusiveIdx, latticeSize);
        });

        return image;
    }

    public static byte[] BlockDecrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] plaintext, int blockSize)
    {
        Rule[] mainRules = DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
        Rule[] borderRules = DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

        return BlockDecrypt(cipherText, mainRules, borderRules, plaintext, blockSize);
    }

    public static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        int latticeLengthInBits = 8 * latticeSize;
        var image = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        var preImage = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        Util.ByteArrayToBinaryArray(initialLattice, image);

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        var borderLength = DoubleRadius;
        int borderLeftCellIdx = latticeLengthInBits - borderLength;
        int borderShift = toggleDirection == ToggleDirection.Left ? -DoubleRadius : DoubleRadius;
        for (int iterationIdx = 0; iterationIdx < latticeLengthInBits; ++iterationIdx)
        {
            borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx + borderShift, latticeLengthInBits);

            PreImageCalculusBits(image, mainRules, borderRules, borderLeftCellIdx, preImage, toggleDirection, latticeLengthInBits);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);
        }
        Util.BinaryArrayToByteArray(image, finalLattice, latticeSize);
        ArrayPool<int>.Shared.Return(image, true);
        ArrayPool<int>.Shared.Return(preImage, true);
        return finalLattice;
    }

    private static void PreImageCalculusBits(int[] image, Rule[] mainRules, Rule[] borderRules, int preImageBorderLeftCellIdx, int[] preImage, ToggleDirection toggleDirection, int latticeSize)
    {
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
        int currentBitInImageIdx = Util.CircularIdx(currentBitInPreImageIdx + (toggleDirection == ToggleDirection.Left ? Radius : -Radius), latticeSize);
        int BinaryCutMask = 0x7FFFFFFF >> 30 - DoubleRadius;
        foreach (var _ in image)
        {
            if (IsBorderCell(currentBitInImageIdx, preImageBorderLeftCellIdx, latticeSize))
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
            currentBitInPreImageIdx = Util.CircularIdx(currentBitInPreImageIdx + toggleDirectionShift, latticeSize);
        }
    }

    private static bool IsBorderCell(int cellIdx, int borderStartIdx, int latticeSize)
    {
        var borderEndIdx = borderStartIdx + DoubleRadius;
        if (borderEndIdx > latticeSize)
        {
            if (cellIdx >= borderStartIdx)
            {
                return true;
            }
            return cellIdx < borderEndIdx - latticeSize;
        }
        return (cellIdx >= borderStartIdx && cellIdx < borderEndIdx);
    }
}
