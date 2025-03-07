using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

internal abstract class CryptoValidatorBase
{
    protected string ValidatorName => GetValidatorName();
    protected int MaxAllowedDegreeOfParallelism => GetMaxAllowedDegreeOfParallelism();
    protected CryptoMethodBase CryptoMethod { get; init; }
    protected ValidatorOptions Options { get; init; }

    protected abstract string GetValidatorName();
    protected abstract int GetMaxAllowedDegreeOfParallelism();

    internal CryptoValidatorBase(CryptoMethodBase cryptoMethod, ValidatorOptions? options = null)
    {
        CryptoMethod = cryptoMethod;
        Options = options ?? GetDefaultValidatorOptions();
    }

    protected abstract ValidatorOptions GetDefaultValidatorOptions();

    public void Run()
    {
        string formattedReport = CompileValidationReport();

        OutputValidationResults(formattedReport);
    }

    protected void OutputValidationResults(string formattedReport)
    {
        if (Options.WriteToConsole)
        {
            Console.Write(formattedReport);
        }

        if (Options.WriteToFile)
        {
            var outputDirectory = CryptoMethod.GetOutputFolderForMethod(Options.DataDirectoryPath);

            var dateTime = DateTime.Now.ToString("s").Replace(':', '-');
            var reportFilename = string.Format($"{dateTime}_{ValidatorName}_{CryptoMethod.AlgorithmName}.txt");
            File.WriteAllText(Path.Combine(outputDirectory, reportFilename), formattedReport);
        }
    }

    protected abstract string CompileValidationReport();
}
