using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;
using System.Text;

namespace CACrypto.RNGValidators.NIST;

internal class NISTValidator(IEnumerable<CryptoProviderBase> cryptoMethods, ValidatorOptions? opt = null)
    : RNGValidatorBase(cryptoMethods, opt)
{
    protected override string GetValidatorName() => "NIST";
    protected override int GetMaxAllowedDegreeOfParallelism() => 5;

    public NISTValidator(CryptoProviderBase cryptoMethod, ValidatorOptions? opt = null) : this([cryptoMethod], opt) { }

    protected override string CompileValidationReport(CryptoProviderBase cryptoMethod, IEnumerable<string> individualReportFiles)
    {
        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");

        int[] successCountArray = new int[15];

        foreach (string reportFile in individualReportFiles)
        {
            var results = NISTProxy.ParseTestResultsFromFile(reportFile);
            for (int test = 0; test < 15; test++)
            {
                if (results[test])
                {
                    successCountArray[test]++;
                }
            }
        }

        var reportCompiler = new StringBuilder();
        reportCompiler.AppendLine($"METHOD {cryptoMethod.GetMethodName()}");
        reportCompiler.AppendLine($"SUCCESS RATES ON {GetValidatorName()}");
        reportCompiler.AppendLine($"INPUT COUNT: {individualReportFiles.Count()}");
        for (int test = 0; test < 15; test++)
        {
            var successPercentage = (((float)successCountArray[test] / (float)individualReportFiles.Count()) * 100.0f).ToString("N2", culture.NumberFormat) + "%";
            reportCompiler.AppendLine($"TEST {test + 1}: {successPercentage}");
        }
        return reportCompiler.ToString();
    }

    protected override string? GenerateIndividualReportFile(string inputFilename)
    {
        string outputFilename = GetIndividualReportFilename(inputFilename);
        var testInput = NISTProxy.CreateTestInput(inputFilename);
        var wasReportGenerated = NISTProxy.GenerateIndividualReportFile(testInput, outputFilename);
        return wasReportGenerated ? outputFilename : null;
    }
}
