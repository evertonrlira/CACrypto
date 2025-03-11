using CACrypto.Commons;
using System.Buffers;

namespace CACrypto.HCA;

public class HCACrypto
{
    public const string Name = "HCA";
    public const int KeySizeInBytes = 32;
    public const int BlockSizeInBytes = 16;
    public const int BlockSizeInBits = 128;
    public const int RuleLength = 512;
    private static readonly int Radius = 4;
    private static readonly int DoubleRadius = 8;

    public static byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] ciphertext, int blockSize)
    {
        Rule[] mainRules;
        Rule[] borderRules;
        if (cryptoKey.Direction == ToggleDirection.Left)
        {
            mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.Bits);
            borderRules = Rule.GenerateLeftSensibleMarginRules(RuleLength);
        }
        else
        {
            mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.Bits);
            borderRules = Rule.GenerateRightSensibleMarginRules(RuleLength);
        }

        return BlockEncrypt(plainText, mainRules, borderRules, ciphertext, blockSize);
    }

    public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int blockSize)
    {
        int latticeLengthInBits = 8 * blockSize;
        var image = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        var preImage = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        Util.ByteArrayToBinaryArray(initialLattice, image);

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        int borderLeftCellIdx = 0;
        int borderShift = toggleDirection == ToggleDirection.Left ? -DoubleRadius : DoubleRadius;
        for (int iterationIdx = 0; iterationIdx < latticeLengthInBits; ++iterationIdx)
        {
            var mainRule = mainRules[iterationIdx % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            PreImageCalculusBits(image, mainRule, borderRule, borderLeftCellIdx, preImage, toggleDirection, latticeLengthInBits);

            borderLeftCellIdx = Util.CircularIdx(borderLeftCellIdx + borderShift, latticeLengthInBits);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);
        }

        Util.BinaryArrayToByteArray(image, finalLattice, blockSize);
        ArrayPool<int>.Shared.Return(image, true);
        ArrayPool<int>.Shared.Return(preImage, true);
        return finalLattice;
    }

    private static void PreImageCalculusBits(int[] image, Rule mainRule, Rule borderRule, int preImageBorderLeftCellIdx, int[] preImage, ToggleDirection toggleDirection, int latticeSize)
    {
        int currentBitInPreImageIdx;
        if (toggleDirection == ToggleDirection.Left)
        {
            currentBitInPreImageIdx = Util.CircularIdx(preImageBorderLeftCellIdx + Radius - 1, latticeSize);
        }
        else
        {
            currentBitInPreImageIdx = Util.CircularIdx(preImageBorderLeftCellIdx + Radius, latticeSize);
        }

        int neighSum = 0;
        int toggleDirectionShift = toggleDirection == ToggleDirection.Left ? -1 : 1;
        int BinaryCutMask = 0x7FFFFFFF >> 30 - DoubleRadius;
        foreach (var _ in image)
        {
            var currentBitInImageIdx = Util.CircularIdx(currentBitInPreImageIdx + (toggleDirection == ToggleDirection.Left ? Radius : -Radius), latticeSize);

            if (IsBorderCell(currentBitInImageIdx, preImageBorderLeftCellIdx, latticeSize))
            {
                preImage[currentBitInPreImageIdx] = borderRule.ResultBitForNeighSum[0] == 0
                    ? image[currentBitInImageIdx]
                    : Util.OppositeBit(image[currentBitInImageIdx]);
            }
            else
            {
                preImage[currentBitInPreImageIdx] = mainRule.ResultBitForNeighSum[neighSum] == image[currentBitInImageIdx]
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

    public static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, byte[] finalLattice, int latticeSize)
    {
        int latticeLengthInBits = 8 * latticeSize;
        var image = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        var preImage = ArrayPool<int>.Shared.Rent(latticeLengthInBits);
        Util.ByteArrayToBinaryArray(initialLattice, preImage);

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        int borderShift = toggleDirection == ToggleDirection.Left ? DoubleRadius : -DoubleRadius;
        int borderLeftmostCellIdx = Util.CircularIdx(borderShift, latticeLengthInBits);
        for (int iterationIdx = 0; iterationIdx < latticeLengthInBits; ++iterationIdx)
        {
            var mainRule = mainRules[(latticeLengthInBits - iterationIdx - 1) % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            SequentialEvolveLattice(preImage, mainRule, borderRule, borderLeftmostCellIdx, image, latticeLengthInBits);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);

            borderLeftmostCellIdx = Util.CircularIdx(borderLeftmostCellIdx + borderShift, latticeLengthInBits);
        }
        Util.BinaryArrayToByteArray(preImage, finalLattice, latticeSize);
        ArrayPool<int>.Shared.Return(image, true);
        ArrayPool<int>.Shared.Return(preImage, true);
        return finalLattice;
    }

    private static int[] SequentialEvolveLattice(int[] preImage, Rule mainRule, Rule borderRule, int imageBorderLeftCellIdx, int[] image, int latticeSize)
    {
        EvolveLatticeSlice(preImage, mainRule, borderRule, imageBorderLeftCellIdx, image, 0, latticeSize, latticeSize);
        return image;
    }

    private static void EvolveLatticeSlice(int[] preImage, Rule mainRule, Rule borderRule, int imageBorderLeftCellIdx, int[] image, int sliceStartInclusiveIdx, int sliceEndExclusiveIdx, int latticeSize)
    {
        bool isBorderCell;
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

            isBorderCell = (centralCellIdx >= imageBorderLeftCellIdx && centralCellIdx < imageBorderLeftCellIdx + DoubleRadius);
            if (isBorderCell)
            {
                image[centralCellIdx] = borderRule.ResultBitForNeighSum[neighSum];
            }
            else
            {
                image[centralCellIdx] = mainRule.ResultBitForNeighSum[neighSum];
            }
        }
    }
}
