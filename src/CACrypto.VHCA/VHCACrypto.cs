using CACrypto.Commons;
using System.Linq;

namespace CACrypto.VHCA;

public class VHCACrypto
{
    public const string Name = "VHCA";
    public const int KeySizeInBytes = 48;
    public const int BlockSizeInBytes = 16;
    public const int BlockSizeInBits = 128;
    public const int RuleLength = 512;
    public const int KeyBitsToRuleFactor = 3; // 3 bits are needed to represent 1 rule
    private static readonly int Radius = 1;
    private static readonly int DoubleRadius = 2;
    private static readonly int BinaryCutMask = 0x7FFFFFFF >> 30 - DoubleRadius;

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

    public static byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey)
    {
        Rule[] mainRules = DeriveMainRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);
        Rule[] borderRules = DeriveBorderRulesFromKey(cryptoKey.Bits, cryptoKey.Direction);

        return BlockEncrypt(plainText, mainRules, borderRules);
    }

    public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules)
    {
        int[] preImage = Util.ByteArrayToBinaryArray(initialLattice);
        int latticeLength = preImage.Length;
        int iterations = latticeLength;
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
            currentBitInPreImageIdx = preImageBorderLeftCellIdx + Radius; // TODO: Revisar
        }

        int neighSum = 0;
        int toggleDirectionShift = toggleDirection == ToggleDirection.Left ? -1 : 1;
        int currentBitInImageIdx = Util.CircularIdx(currentBitInPreImageIdx + (toggleDirection == ToggleDirection.Left ? 1 : -1), latticeLength);
        foreach (var _ in Enumerable.Range(0, latticeLength))
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
