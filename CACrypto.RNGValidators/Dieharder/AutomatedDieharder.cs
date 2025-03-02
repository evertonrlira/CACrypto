using CACrypto.Commons;

namespace CACrypto.RNGValidators.Dieharder;

public static class AutomatedDieharder
{
    public static void Run(PermutiveCACryptoMethodBase cryptoMethod, IEnumerable<string> filenames)
    {
        var sequenceCount = filenames.Count();
        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");

        foreach (var filename in filenames)
        {
            using (var testInput = ProxyDieharder.CreateTestInput(filename))
            {
                var result = ProxyDieharder.Test(testInput, out List<ProxyDieharder.TestResult> testList);

                var strResult = string.Format("Passos: {0} \tResultado: {1} \t Parcial: {2}/{3}", 1, result, testList.Count(r => r.Passed), testList.Count());
                Console.WriteLine(strResult);
            }
        }
    }
}
