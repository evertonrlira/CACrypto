using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;
using System.Text;

namespace CACrypto.RNGValidators.PractRand;

internal class PractRandValidator(IEnumerable<CryptoProviderBase> cryptoMethods, ValidatorOptions? opt = null)
    : RNGValidatorBase(cryptoMethods, opt)
{
    protected override string GetValidatorName() => "PractRand";
    protected override int GetMaxAllowedDegreeOfParallelism() => Environment.ProcessorCount;

    public PractRandValidator(CryptoProviderBase cryptoMethod, ValidatorOptions? opt = null) : this([cryptoMethod], opt) { }

    protected override string CompileValidationReport(CryptoProviderBase cryptoMethod, IEnumerable<string> individualReportFiles)
    {
        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");

        int[] count = new int[6];
        string[] testGroupKeys = ["BCFN", "BRank", "DC6-9x1Bytes-1", "FPF-14+6/16", "Gap-16", "mod3n"];
        var testGroupSuccessCount = testGroupKeys.ToDictionary(k => k, k => 0);

        foreach (string reportFile in individualReportFiles)
        {
            List<PractRandProxy.TestResult> results = PractRandProxy.ParseTestResultsFromFile(reportFile);
            var testGroups = results.GroupBy(
                    tl => ParseGroupName(tl.TestName)
                        , tl => tl);

            foreach (var testGroupKey in testGroupKeys)
            {
                var groupResults = testGroups.First(g => g.Key == testGroupKey);
                if (groupResults.All(t => t.Passed))
                    testGroupSuccessCount[testGroupKey] += 1;
            }
        }

        var reportCompiler = new StringBuilder();
        reportCompiler.AppendLine($"METHOD {cryptoMethod.GetMethodName()}");
        reportCompiler.AppendLine($"SUCCESS RATES ON {GetValidatorName()}");
        reportCompiler.AppendLine($"INPUT COUNT: {individualReportFiles.Count()}");
        foreach (var testGroupKey in testGroupKeys)
        {
            var successPercentage = (((float)testGroupSuccessCount[testGroupKey] / (float)individualReportFiles.Count()) * 100.0f).ToString("N2", culture.NumberFormat) + "%";
            reportCompiler.AppendLine($"TEST {testGroupKey}: {successPercentage}");
        }
        return reportCompiler.ToString();
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

    protected override string? GenerateIndividualReportFile(string inputFilename)
    {
        string outputFilename = GetIndividualReportFilename(inputFilename);
        var testInput = PractRandProxy.CreateTestInput(inputFilename);
        var wasReportGenerated = PractRandProxy.GenerateIndividualReportFile(testInput, outputFilename);
        return wasReportGenerated ? outputFilename : null;
    }
}
