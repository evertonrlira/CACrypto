using CACrypto.Commons;

namespace CACrypto.HCA;

public class HCACrypto
{
    public const int KeySizeInBytes = 32;
    public const int BlockSizeInBytes = 16;
    public const int BlockSizeInBits = 128;
    public const int RuleLength = 512;
    private static readonly int Radius = 4;
    private static readonly int DoubleRadius = 8;

    public static byte[] BlockEncrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey)
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

        return BlockEncrypt(plainText, mainRules, borderRules, iterations: HCACrypto.BlockSizeInBits);
    }

    public static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
    {
        int[] image = Util.ByteArrayToBinaryArray(initialLattice);
        int[] preImage = new int[image.Length];
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


    public static void BlockEncryptOptimized(byte[] image, byte[] preImage, Rule[] mainRules, Rule[] borderRules, int iterations)
    {
        for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
        {
            var mainRule = mainRules[iterationIdx % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            PreImageCalculusBytes(image, mainRule, borderRule, iterationIdx, preImage);

            if (iterationIdx < iterations - 1)
            {
                // Prepare for Next Iteration
                Util.Swap(ref image, ref preImage);
            }
        }
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

    private static void SetBit(byte[] self, int index, bool value)
    {
        int byteIndex = index / 8;
        int bitIndex = index % 8;
        byte mask = (byte)(1 << bitIndex);

        self[byteIndex] = (byte)(value ? (self[byteIndex] | mask) : (self[byteIndex] & ~mask));
    }

    private static void ToggleBit(byte[] self, int index)
    {
        int byteIndex = index / 8;
        int bitIndex = index % 8;
        byte mask = (byte)(1 << bitIndex);

        self[byteIndex] ^= mask;
    }

    private static bool GetBit(byte[] self, int index)
    {
        int byteIndex = index / 8;
        int bitIndex = index % 8;
        byte mask = (byte)(1 << bitIndex);

        return (self[byteIndex] & mask) != 0;
    }

    private static void PreImageCalculusBytes(byte[] image, Rule mainRule, Rule borderRule, int execIdx, byte[] preImage)
    {
        var stateLength = image.Length * 8;
        var borderLength = DoubleRadius;
        var borderShift = DoubleRadius;

        if (borderRule.IsLeftSensible) // Cálculo da Direita pra Esquerda
        {
            int currentPreImageNeighSum = 0;
            // Região de Borda (Contorno = 2*Raio)
            int borderStartIdx = Util.CircularIdx(-1 * (borderShift * execIdx), stateLength);
            int equivalentSensibleBitInPreImageIdx;
            int borderResultingBitInImageIdx;
            for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);

                var imageBitValue = GetBit(image, borderResultingBitInImageIdx);
                var preImageSensibleBitValue = (borderRule.ResultBitForNeighSum[0] == 0) ? imageBitValue : !imageBitValue;

                SetBit(preImage, equivalentSensibleBitInPreImageIdx, preImageSensibleBitValue);
                currentPreImageNeighSum |= (preImageSensibleBitValue ? 1 : 0);
                currentPreImageNeighSum <<= 1;
            }

            borderResultingBitInImageIdx = borderStartIdx;
            // Região Principal
            for (int mainStepIdx = stateLength - borderLength - 1; mainStepIdx >= 0; mainStepIdx--)
            {
                borderResultingBitInImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - 1, stateLength);
                equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);

                // Apaga o Antigo LSB
                currentPreImageNeighSum >>= 1;

                var imageBitValue = GetBit(image, borderResultingBitInImageIdx);
                var preImageSensibleBitValue = (mainRule.ResultBitForNeighSum[currentPreImageNeighSum] == (imageBitValue ? 1 : 0)) ? false : true;

                SetBit(preImage, equivalentSensibleBitInPreImageIdx, preImageSensibleBitValue);

                // Coloca Novo Bit como MSB
                currentPreImageNeighSum |= ((preImageSensibleBitValue ? 1 : 0) << (DoubleRadius));
            }
        }
        else
        {
            /*
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
                if (borderRule.Bits[0] == 0)
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

                if (mainRule.Bits[neighSum] == image[borderResultingBitInImageIdx])
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
            */
        }
    }

    public static byte[] BlockDecrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey)
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

        return BlockDecrypt(cipherText, mainRules, borderRules, iterations: HCACrypto.BlockSizeInBits);
    }

    protected static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
    {
        int[] preImage = Util.ByteArrayToBinaryArray(initialLattice);
        int[] image = new int[preImage.Length];
        int[] finalLattice;

        int[] swapAux;

        for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
        {
            var mainRule = mainRules[(iterations - iterationIdx - 1) % mainRules.Length];
            var borderRule = borderRules[Util.OppositeBit(mainRule.ResultBitForNeighSum[0])];
            SequentialEvolveBits(preImage, mainRule, borderRule, (iterations - iterationIdx - 1), image);

            // Prepare for Next Iteration
            swapAux = image;
            image = preImage;
            preImage = swapAux;
        }
        finalLattice = preImage;
        return Util.BinaryArrayToByteArray(finalLattice);
    }

    private static int[] SequentialEvolveBits(int[] preImage, Rule mainRule, Rule borderRule, int execIdx, int[] image)
    {
        var stateLength = preImage.Length;
        var marginLength = DoubleRadius;
        int binaryCutMask = 0x7FFFFFFF >> (30 - (DoubleRadius));

        int borderNeighStartIdx;
        if (borderRule.IsLeftSensible)
        {
            borderNeighStartIdx = Util.CircularIdx((-1 * (marginLength * execIdx)) - Radius, stateLength);
        }
        else
        {
            borderNeighStartIdx = Util.CircularIdx((marginLength * execIdx) - Radius, stateLength);
        }

        var neighSum = 0;

        // Initial Bits
        var currentInitialBitInPreImageIdx = borderNeighStartIdx;
        for (int initialBitsIdx = 0; initialBitsIdx < marginLength; initialBitsIdx++)
        {
            neighSum |= preImage[currentInitialBitInPreImageIdx];
            currentInitialBitInPreImageIdx = Util.CircularIdx(currentInitialBitInPreImageIdx + 1, stateLength);
            neighSum <<= 1;
        }

        // Border Bits
        var currentBorderBitInPreImageIdx = currentInitialBitInPreImageIdx;
        int resultBitInImageIdx;
        for (int borderStepIdx = 0; borderStepIdx < marginLength; borderStepIdx++)
        {
            resultBitInImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx - Radius, stateLength);
            neighSum |= preImage[currentBorderBitInPreImageIdx];
            image[resultBitInImageIdx] = borderRule.ResultBitForNeighSum[neighSum];
            currentBorderBitInPreImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx + 1, stateLength);
            neighSum <<= 1; neighSum &= binaryCutMask;
        }

        // Main Bits
        var currentMainBitInPreImageIdx = currentBorderBitInPreImageIdx;
        for (int mainStepIdx = 0; mainStepIdx < stateLength - marginLength; mainStepIdx++)
        {
            resultBitInImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx - Radius, stateLength);
            neighSum |= preImage[currentMainBitInPreImageIdx];
            image[resultBitInImageIdx] = mainRule.ResultBitForNeighSum[neighSum];
            currentMainBitInPreImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx + 1, stateLength);
            neighSum <<= 1; neighSum &= binaryCutMask;
        }
        return image;
    }
}
