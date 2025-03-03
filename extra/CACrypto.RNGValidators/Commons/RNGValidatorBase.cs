using CACrypto.Commons;
using CACrypto.RNGValidators.PractRand;

namespace CACrypto.RNGValidators.Commons;

internal abstract class RNGValidatorBase(CryptoMethodBase cryptoMethod, ValidatorOptions options)
{
    protected string ValidatorName => GetValidatorName();
    protected int MaxAllowedDegreeOfParallelism => GetMaxAllowedDegreeOfParallelism();
    protected CryptoMethodBase CryptoMethod { get; init; } = cryptoMethod;
    protected ValidatorOptions Options { get; init; } = options;

    protected abstract string GetValidatorName();
    protected abstract int GetMaxAllowedDegreeOfParallelism();
    protected string GetIndividualReportFilename(string inputFileName)
    {
        var testedBinFile = new FileInfo(inputFileName);
        if (!testedBinFile.Exists)
        {
            throw new FileNotFoundException();
        }
        var testedBinFileName = testedBinFile.Name[..^4];
        if (testedBinFile.Directory is null)
        {
            throw new DirectoryNotFoundException();
        }
        return Path.Combine(testedBinFile.Directory.FullName, $"{testedBinFileName}_{ValidatorName}.txt");
    }

    public void Run()
    {
        var inputfiles = CryptoMethod.GenerateBinaryFiles(Options.InputFilesSize, Options.InputFilesCount, Options.DataDirectoryPath);
        var individualReportFiles = GenerateIndividualValidationReports(inputfiles);
        while (individualReportFiles.Count < Options.InputFilesCount)
        {
            inputfiles = CryptoMethod.GenerateBinaryFiles(Options.InputFilesSize, Options.InputFilesCount, Options.DataDirectoryPath);
            individualReportFiles = GenerateIndividualValidationReports(inputfiles);
        }

        string formattedReport = CompileValidationReport(individualReportFiles);
        
        if (Options.WriteToConsole)
        {
            Console.Write(formattedReport);
        }

        if (Options.WriteToFile)
        {
            var dateTime = DateTime.Now.ToString("s").Replace(':', '-');
            var reportFilename = string.Format($"{dateTime}_{ValidatorName}_{CryptoMethod.AlgorithmName}_{individualReportFiles.Count}.txt");
            File.WriteAllText(Path.Combine(Options.DataDirectoryPath, reportFilename), formattedReport);
        }
    }

    protected abstract string? GenerateIndividualReportFile(string inputFilename);

    protected List<string> GenerateIndividualValidationReports(IEnumerable<string> sequenceFiles)
    {
        var individualReportFiles = new List<string>();

        Parallel.ForEach(sequenceFiles, new ParallelOptions() { MaxDegreeOfParallelism = MaxAllowedDegreeOfParallelism }, inputFilename =>
        {
            try
            {
                var outputFilename = GenerateIndividualReportFile(inputFilename);

                if (outputFilename is null)
                {
                    File.Delete(inputFilename);
                }
                else
                {
                    individualReportFiles.Add(outputFilename);
                }
            }
            catch (Exception ex)
            {
                if (Options.WriteToConsole)
                {
                    Console.WriteLine("[Warning] Error when processing: \"{0}\"", ex.Message);
                }
                if (File.Exists(inputFilename))
                {
                    File.Delete(inputFilename);
                }
            }
        });

        return individualReportFiles;
    }


    protected abstract string CompileValidationReport(IEnumerable<string> individualReportFiles);
}
