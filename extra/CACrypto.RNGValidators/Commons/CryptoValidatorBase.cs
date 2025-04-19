using System.Text;

namespace CACrypto.RNGValidators.Commons;

internal abstract class CryptoValidatorBase
{
    protected string ValidatorName => GetValidatorName();
    protected int MaxAllowedDegreeOfParallelism => GetMaxAllowedDegreeOfParallelism();
    protected IEnumerable<CryptoValidatorInput> ValidatorInputs { get; init; }

    protected abstract string GetValidatorName();
    protected abstract int GetMaxAllowedDegreeOfParallelism();

    internal CryptoValidatorBase(IEnumerable<CryptoValidatorInput> validatorInputs)
    {
        ValidatorInputs = validatorInputs;
    }

    public void Run()
    {
        string formattedReport = CompileValidationReport();

        OutputValidationResults(formattedReport);
    }

    private string CompileValidationReport()
    {
        var sb = new StringBuilder();
        foreach (var input in ValidatorInputs)
        {
            var methodReport = CompileValidationReport(input);
            sb.Append(methodReport);
            sb.AppendLine();
        }
        return sb.ToString();
    }

    protected void OutputValidationResults(string formattedReport)
    {
        // TODO: Refactor, due to simply using the first one
        if (ValidatorInputs.First().Options.WriteToConsole)
        {
            Console.Write(formattedReport);
        }

        if (ValidatorInputs.First().Options.WriteToFile)
        {
            var outputDirectory = GetOutputFolderForReports(ValidatorInputs.First().Options.DataDirectoryPath);

            var dateTime = DateTime.Now.ToString("s").Replace(':', '-');
            var cryptoMethods = ValidatorInputs.Count() == 1
                ? $"{ValidatorInputs.First().CryptoMethod.GetMethodName()}"
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

    protected abstract string CompileValidationReport(CryptoValidatorInput validatorInput);
}
