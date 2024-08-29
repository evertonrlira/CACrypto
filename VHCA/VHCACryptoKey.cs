using CACrypto.Commons;

namespace VHCA_Crypto
{
    public class VHCACryptoKey : PermutiveCACryptoKey
    {
        public VHCACryptoKey(int[] keyBits, ToggleDirection toggleDirection) : base(Util.BinaryArrayToByteArray(keyBits), toggleDirection) { }

        public VHCACryptoKey(byte[] keyBytes, ToggleDirection toggleDirection) : base(keyBytes, toggleDirection) { }

        public static VHCACryptoKey GenerateRandomKey(int blockSize = VHCA.BlockSizeInBytes, ToggleDirection? toggleDirection = null)
        {
            toggleDirection ??= Util.GetRandomToggleDirection();

            var keyBytes = Util.GetSecureRandomByteArray(VHCA.KeyBitsToRuleFactor * blockSize);
            //while (Util.SpatialEntropyCalculusForBinary(Util.ByteArrayToBinaryArray(keyBytes)) <= 0.75)
            //{
            //    keyBytes = Util.GetSecureRandomByteArray(VHCA.KeyBitsToRuleFactor * blockSize);
            //}
            return new VHCACryptoKey(keyBytes, toggleDirection.Value);
        }
    }

    /*
     * 
     * public class VHCACryptoKey
        {
            public ToggleDirection Direction { get; private set; }

            public int[] KeyBits { get; private set; }

            public Rule[] MainRules { get; private set; }
            public Rule[] BorderRules { get; private set; }

            private VHCACryptoKey(int[] keyBits, int directionBit)
            {
                KeyBits = keyBits;                
                Direction = (directionBit == 1) ? ToggleDirection.Right : ToggleDirection.Left;
                MainRules = DeriveMainRulesFromKey(keyBits, Direction);
                BorderRules = DeriveBorderRulesFromKey(keyBits, Direction);
            }

            private static Rule[] DeriveMainRulesFromKey(int[] keyBits, ToggleDirection direction)
            {
                var mainRules = new Rule[BlockSizeInBits];
                var alphabet = 
                    direction == ToggleDirection.Left ? 
                        MainRulesLeftToggleAlphabet : 
                            MainRulesRightToggleAlphabet;

                int currentOctalIdx = 0;
                for (int idxBit = 0; idxBit < keyBits.Length; idxBit += 3)
                {
                    int currentOctalValue = (keyBits[idxBit] << 2) + (keyBits[idxBit + 1] << 1) + keyBits[idxBit + 2];
                    mainRules[currentOctalIdx] = alphabet[currentOctalValue];
                    currentOctalIdx++;
                }
                return mainRules;
            }

            private static Rule[] DeriveBorderRulesFromKey(int[] keyBits, ToggleDirection direction)
            {
                var borderRules = new Rule[BlockSizeInBits];
                var alphabet =
                    direction == ToggleDirection.Left ?
                        BorderRulesLeftToggleAlphabet :
                            BorderRulesRightToggleAlphabet;

                int currentOctalIdx = 0;
                for (int idxBit = 0; idxBit < keyBits.Length; idxBit += 3)
                {
                    borderRules[currentOctalIdx] = keyBits[idxBit] == 0 ? alphabet[0x00] : alphabet[0x04];
                    currentOctalIdx++;
                }
                return borderRules;
            }

            public static VHCACryptoKey GenerateRandomKey()
            {
                var ruleBitsCount = 3*BlockSizeInBits;

                var directionBit = Util.GetRandomNumber(0, 2);

                // Excess bits are needed to calculate spatial entropy (length must be power of 2)
                var keyBitsWithExcess = Util.GetSecureRandomBinaryArray(4*BlockSizeInBits);
                while (Util.SpatialEntropyCalculusForBinary(keyBitsWithExcess) <= 0.75)
                {
                    keyBitsWithExcess = Util.GetSecureRandomBinaryArray(4*BlockSizeInBits);
                }
                var keyBits = new int[ruleBitsCount];
                var randomOffset = Util.GetRandomNumber(0, BlockSizeInBits);
                Buffer.BlockCopy(keyBitsWithExcess, randomOffset * sizeof(int), keyBits, 0, ruleBitsCount * sizeof(int));

                return new VHCACryptoKey(keyBits, directionBit);
            }
        }
     */
}
