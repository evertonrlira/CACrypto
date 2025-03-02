using CACrypto.Commons;

namespace CACrypto.RNGValidators.PractRand;

public class AutomatedPractRand
{
    public static void Run(PermutiveCACryptoMethodBase cryptoMethod, IEnumerable<string> filenames)
    {
        var sequenceCount = filenames.Count();
        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");

        int[] count = new int[6];
        string[] keys = ["BCFN", "BRank", "DC6-9x1Bytes-1", "FPF-14+6/16", "Gap-16", "mod3n"];

        foreach (var filename in filenames)
        {
            using (var testInput = ProxyPractRand.CreateTestInput(filename))
            {
                var result = ProxyPractRand.Test(testInput, out List<ProxyPractRand.TestResult> testList);

                var i = testList.GroupBy(
                    tl => ParseGroupName(tl.TestName)
                        , tl => tl);

                for (int idx = 0; idx < 6; idx++)
                {
                    var key = keys[idx];
                    var group = i.First(g => g.Key == key);
                    if (group.All(t => t.Passed))
                        count[idx]++;
                }
            }
        }

        for (int idxKey = 0; idxKey < 6; ++idxKey)
        {
            var strResult = string.Format("Teste: {0} \tResultado: {1}", keys[idxKey], count[idxKey]);
            Console.WriteLine(strResult);
        }
    }

    private static string ParseGroupName(string testName)
    {
        var startIdx = (testName.IndexOf(']') == -1) ? 0 : testName.IndexOf(']') + 1;
        var idxOfTwoDots = testName.IndexOf(':');
        var idxOfParen = testName.IndexOf('(');
        if (idxOfTwoDots == -1 && idxOfParen == -1)
            return testName.Substring(startIdx, testName.Length - startIdx);
        var smaller = (idxOfTwoDots == -1) ? idxOfParen : ((idxOfParen == -1) ? idxOfTwoDots : ((idxOfTwoDots > idxOfParen) ? idxOfParen : idxOfTwoDots));
        return testName.Substring(startIdx, smaller - startIdx);
    }
}
