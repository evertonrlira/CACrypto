using CACrypto.Commons;

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

    public byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, int[]? bufferArray = null)
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

        return BlockEncrypt(plainText, mainRules, borderRules, bufferArray);
    }

    public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int[]? bufferArray = null)
    {
        int[] image = Util.ByteArrayToBinaryArray(initialLattice);
        int iterations = image.Length;
        int[] preImage = bufferArray ?? new int[image.Length];
        int[] finalLattice;

        for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
        {
            var mainRule = mainRules[iterationIdx % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            PreImageCalculusBits(image, mainRule, borderRule, iterationIdx, preImage);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);
        }
        finalLattice = image;
        return Util.BinaryArrayToByteArray(finalLattice);
    }

    private static void PreImageCalculusBits(int[] image, Rule mainRule, Rule borderRule, int execIdx, int[] preImage)
    {
        var stateLength = image.Length;
        var borderLength = DoubleRadius;
        var borderShift = DoubleRadius;

        if (borderRule.IsLeftSensible) // Cálculo da Direita pra Esquerda
        {
            int neighSum = 0;
            // Região de Borda (Contorno = 2*Raio)
            int borderStartIdx = Util.CircularIdx(-1 * (borderShift * execIdx), stateLength);
            int equivalentSensibleBitInPreImageIdx;
            int borderResultingBitInImageIdx;
            for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);
                if (borderRule.ResultBitForNeighSum[0] == 0)
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = image[borderResultingBitInImageIdx];
                }
                else
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = Util.OppositeBit(image[borderResultingBitInImageIdx]);
                }
                neighSum |= preImage[equivalentSensibleBitInPreImageIdx];
                neighSum <<= 1;
            }

            borderResultingBitInImageIdx = borderStartIdx;
            // Região Principal
            for (int mainStepIdx = stateLength - borderLength - 1; mainStepIdx >= 0; mainStepIdx--)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - 1, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);

                // Apaga o Antigo LSB
                neighSum >>= 1;
                if (mainRule.ResultBitForNeighSum[neighSum] == image[borderResultingBitInImageIdx])
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = 0;
                }
                else
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = 1;
                }
                // Coloca Novo Bit como MSB
                neighSum |= (preImage[equivalentSensibleBitInPreImageIdx] << (DoubleRadius));
            }
        }
        else
        {
            int binaryCutMask = 0x7FFFFFFF >> (30 - (DoubleRadius));
            int neighSum = 0;
            int borderResultingBitInImageIdx = 0;
            // Região de Borda (Contorno = 2*Raio)
            int borderStartIdx = Util.CircularIdx((borderShift * execIdx), stateLength);
            int equivalentSensibleBitInPreImageIdx;
            for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + Radius, stateLength);
                if (borderRule.ResultBitForNeighSum[0] == 0)
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = image[borderResultingBitInImageIdx];
                }
                else
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = Util.OppositeBit(image[borderResultingBitInImageIdx]);
                }
                neighSum |= preImage[equivalentSensibleBitInPreImageIdx];
                neighSum <<= 1;
            }

            // Região Principal
            for (int mainStepIdx = stateLength - borderLength - 1; mainStepIdx >= 0; mainStepIdx--)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + 1, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + Radius, stateLength);

                // Apaga o Antigo LSB

                if (mainRule.ResultBitForNeighSum[neighSum] == image[borderResultingBitInImageIdx])
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = 0;
                }
                else
                {
                    preImage[equivalentSensibleBitInPreImageIdx] = 1;
                }
                // Coloca Novo Bit como novo LSB
                neighSum |= (preImage[equivalentSensibleBitInPreImageIdx]);
                // Corta Antigo MSB
                neighSum <<= 1; neighSum &= binaryCutMask;
            }
        }
    }

    public static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules)
    {
        int[] preImage = Util.ByteArrayToBinaryArray(initialLattice);
        int iterations = preImage.Length;
        int latticeLength = preImage.Length;
        int[] image = new int[latticeLength];
        int[] finalLattice;

        var toggleDirection = mainRules[0].IsLeftSensible ? ToggleDirection.Left : ToggleDirection.Right;
        int borderShift = toggleDirection == ToggleDirection.Left ? DoubleRadius : -DoubleRadius;
        int borderLeftmostCellIdx = Util.CircularIdx(borderShift, latticeLength);
        for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
        {
            var mainRule = mainRules[(iterations - iterationIdx - 1) % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            SequentialEvolveLattice(preImage, mainRule, borderRule, borderLeftmostCellIdx, image);

            // Prepare for Next Iteration
            Util.Swap(ref image, ref preImage);

            borderLeftmostCellIdx = Util.CircularIdx(borderLeftmostCellIdx + borderShift, latticeLength);
        }
        finalLattice = preImage;
        return Util.BinaryArrayToByteArray(finalLattice);
    }

    private static int[] SequentialEvolveLattice(int[] preImage, Rule mainRule, Rule borderRule, int imageBorderLeftCellIdx, int[] image)
    {
        EvolveLatticeSlice(preImage, mainRule, borderRule, imageBorderLeftCellIdx, image, 0, preImage.Length);
        return image;
    }

    private static void EvolveLatticeSlice(int[] preImage, Rule mainRule, Rule borderRule, int imageBorderLeftCellIdx, int[] image, int sliceStartInclusiveIdx, int sliceEndExclusiveIdx)
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
                image[centralCellIdx] = borderRule.ResultBitForNeighSum[neighSum];
            }
            else
            {
                image[centralCellIdx] = mainRule.ResultBitForNeighSum[neighSum];
            }
        }
    }
}
