using CACrypto.Commons;

namespace CACrypto.VHCA;

internal static class VHCARuleAlphabet
{
    // Main Left Toggle Rules
    private static readonly Rule R030 = new("00011110");
    private static readonly Rule R045 = new("00101101");
    private static readonly Rule R075 = new("01001011");
    private static readonly Rule R120 = new("01111000");
    private static readonly Rule R135 = new("10000111");
    private static readonly Rule R180 = new("10110100");
    private static readonly Rule R210 = new("11010010");
    private static readonly Rule R225 = new("11100001");

    // Border Left Toggle Rules
    private static readonly Rule R015 = new("00001111");
    private static readonly Rule R240 = new("11110000");

    // Main Right Toggle Rules
    private static readonly Rule R086 = new("01010110");
    private static readonly Rule R089 = new("01011001");
    private static readonly Rule R101 = new("01100101");
    private static readonly Rule R106 = new("01101010");
    private static readonly Rule R149 = new("10010101");
    private static readonly Rule R154 = new("10011010");
    private static readonly Rule R166 = new("10100110");
    private static readonly Rule R169 = new("10101001");

    // Border Right Toggle Rules
    private static readonly Rule R085 = new("01010101");
    private static readonly Rule R170 = new("10101010");

    internal static readonly Rule[] MainRulesLeftToggleAlphabet = [
        R030, R045, R075, R120, R135, R180, R210, R225
    ];

    internal static readonly Rule[] MainRulesRightToggleAlphabet = [
        R086, R089, R101, R106, R149, R154, R166, R169
    ];

    internal static readonly Rule[] BorderRulesLeftToggleAlphabet = [
        R015, R015, R015, R015, R240, R240, R240, R240
    ];

    internal static readonly Rule[] BorderRulesRightToggleAlphabet = [
        R085, R085, R085, R085, R170, R170, R170, R170
    ];
}
