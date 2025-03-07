using CACrypto.Commons;
using System.Text;

namespace CACrypto.RNGValidators.Commons;

internal abstract class CryptoValidatorBase
{
    protected string ValidatorName => GetValidatorName();
    protected int MaxAllowedDegreeOfParallelism => GetMaxAllowedDegreeOfParallelism();
    protected IEnumerable<CryptoMethodBase> CryptoMethods { get; init; }
    protected ValidatorOptions Options { get; init; }

    protected abstract string GetValidatorName();
    protected abstract int GetMaxAllowedDegreeOfParallelism();

    internal CryptoValidatorBase(CryptoMethodBase cryptoMethod, ValidatorOptions? options = null)
    {
        CryptoMethods = [cryptoMethod];
        Options = options ?? GetDefaultValidatorOptions();
    }

    internal CryptoValidatorBase(IEnumerable<CryptoMethodBase> cryptoMethods, ValidatorOptions? options = null)
    {
        CryptoMethods = cryptoMethods;
        Options = options ?? GetDefaultValidatorOptions();
    }

    protected abstract ValidatorOptions GetDefaultValidatorOptions();

    public void Run()
    {
        string formattedReport = CompileValidationReport();

        OutputValidationResults(formattedReport);
    }

    private string CompileValidationReport()
    {
        var sb = new StringBuilder();
        foreach (CryptoMethodBase cryptoMethod in CryptoMethods)
        {
            var methodReport = CompileValidationReport(cryptoMethod);
            sb.Append(methodReport);
            sb.AppendLine();
        }
        return sb.ToString();
    }

    protected void OutputValidationResults(string formattedReport)
    {
        if (Options.WriteToConsole)
        {
            Console.Write(formattedReport);
        }

        if (Options.WriteToFile)
        {
            var outputDirectory = GetOutputFolderForReports(Options.DataDirectoryPath);

            var dateTime = DateTime.Now.ToString("s").Replace(':', '-');
            var cryptoMethods = CryptoMethods.Count() == 1 
                ? $"{CryptoMethods.First().GetMethodName()}" 
                : "Multiple";
            var reportFilename = string.Format($"Report_{ValidatorName}_{cryptoMethods}_{dateTime}.txt");
            File.WriteAllText(Path.Combine(outputDirectory, reportFilename), formattedReport);
        }
    }

    private static string GetOutputFolderForReports(string outputDir)
    {
        if (!Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        return outputDir;
    }

    protected abstract string CompileValidationReport(CryptoMethodBase cryptoMethod);
}
