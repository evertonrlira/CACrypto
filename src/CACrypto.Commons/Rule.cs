namespace CACrypto.Commons;

public class Rule
{
    public int[] ResultBitForNeighSum { get; private set; }
    public int[] RuleBits { get; private set; }
    public int Length { get; private set; }
    public bool IsLeftSensible { get; private set; }
    public bool IsRightSensible { get; private set; }

    public Rule(string bits) : this(bits.Select(c => (int)c - 48).ToArray()) { }

    public Rule(int[] bits)
    {
        RuleBits = bits;
        ResultBitForNeighSum = RuleBits.Reverse().ToArray();
        Length = bits.Length;

        IsLeftSensible = true;
        IsRightSensible = true;
        int halfLength = Length / 2;
        for (int i = 0; i < halfLength; ++i)
        {
            IsLeftSensible = IsLeftSensible && (RuleBits[i] != RuleBits[i + halfLength]);
            IsRightSensible = IsRightSensible && (RuleBits[2 * i] != RuleBits[2 * i + 1]);
        }
    }

    internal static bool IsValidRule(string bits)
    {
        double ruleLengthLogDec = (Math.Log(bits.Length) / Math.Log(2));
        if (ruleLengthLogDec % 1 != 0)
            return false;

        int ruleLengthLog = (int)ruleLengthLogDec;

        if (ruleLengthLog % 2 == 0 || ruleLengthLog < 3)
            return false;

        if (bits.Any(c => c != '0' && c != '1'))
            return false;

        return true;
    }


    public static Rule GenerateLeftSensibleRule(Span<int> nuclei)
    {
        int[] ruleBits = new int[2 * nuclei.Length];
        for (int idx = 0; idx < nuclei.Length; ++idx)
        {
            ruleBits[idx] = nuclei[idx];
            ruleBits[nuclei.Length + idx] = Util.OppositeBit(nuclei[idx]);
        }
        return new Rule(ruleBits);
    }

    public static Rule GenerateRightSensibleRule(Span<int> nuclei)
    {
        int[] ruleBits = new int[2 * nuclei.Length];
        for (int idx = 0; idx < nuclei.Length; ++idx)
        {
            ruleBits[2 * idx] = nuclei[idx];
            ruleBits[2 * idx + 1] = Util.OppositeBit(nuclei[idx]);
        }
        return new Rule(ruleBits);
    }

    public static Rule[] GetAllLeftSensibleRulesByShiftingNuclei(Span<int> nuclei)
    {
        #region Preconditions
        double nucleiLengthLogDec = (Math.Log(nuclei.Length) / Math.Log(2));
        if (nucleiLengthLogDec % 1 != 0)
            throw new Exception("Nuclei length must be a power of two");

        int nucleiLengthLog = (int)nucleiLengthLogDec;

        if (nucleiLengthLog % 2 == 1)
            throw new Exception("Invalid nuclei length. No equivalent radius");
        #endregion /* Preconditions */

        Rule[] mainRules = new Rule[nuclei.Length];
        Span<int> temp = nuclei;
        for (int shiftIdx = 0; shiftIdx < nuclei.Length; ++shiftIdx)
        {
            mainRules[shiftIdx] = Rule.GenerateLeftSensibleRule(temp);
            temp = Util.LeftShift(temp);
        }
        return mainRules;
    }

    public static Rule[] GetAllRightSensibleRulesByShiftingNuclei(Span<int> nuclei)
    {
        #region Pré-Condições
        double nucleiLengthLogDec = (Math.Log(nuclei.Length) / Math.Log(2));
        if (nucleiLengthLogDec % 1 != 0)
            throw new Exception("Nuclei length must be a power of two");

        int nucleiLengthLog = (int)nucleiLengthLogDec;

        if (nucleiLengthLog % 2 == 1)
            throw new Exception("Invalid nuclei length. No equivalent radius");
        #endregion /* Pré-Condições */

        Rule[] mainRules = new Rule[nuclei.Length];
        Span<int> temp = nuclei;
        for (int shiftIdx = 0; shiftIdx < nuclei.Length; ++shiftIdx)
        {
            mainRules[shiftIdx] = Rule.GenerateRightSensibleRule(temp);
            temp = Util.RightShift(temp);
        }
        return mainRules;
    }

    public static Rule[] GenerateLeftSensibleMarginRules(int ruleLength)
    {
        var zeros = Enumerable.Repeat(0, ruleLength / 2);
        var ones = Enumerable.Repeat(1, ruleLength / 2);
        return [
            new Rule(Enumerable.Concat(zeros, ones).ToArray()),
            new Rule(Enumerable.Concat(ones, zeros).ToArray())
        ];
    }

    public static Rule[] GenerateRightSensibleMarginRules(int ruleLength)
    {
        return new Rule[] {
            new Rule(String.Join("", Enumerable.Repeat("01", ruleLength / 2))),
            new Rule(String.Join("", Enumerable.Repeat("10", ruleLength / 2)))
        };
    }

    public static int GetRuleLengthForRadius(int radius)
    {
        return (int)Math.Pow(2, 2 * radius + 1);
    }
}