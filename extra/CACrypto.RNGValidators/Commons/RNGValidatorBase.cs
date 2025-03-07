﻿using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

internal abstract class RNGValidatorBase(CryptoMethodBase cryptoMethod, ValidatorOptions? options = null) 
    : CryptoValidatorBase(cryptoMethod, options)
{
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

    protected override string CompileValidationReport()
    {
        var inputfiles = CryptoMethod.GenerateBinaryFiles(Options.InputSampleSize, Options.InputSamplesCount, Options.DataDirectoryPath);
        var individualReportFiles = GenerateIndividualValidationReports(inputfiles);
        while (individualReportFiles.Count < Options.InputSamplesCount)
        {
            inputfiles = CryptoMethod.GenerateBinaryFiles(Options.InputSampleSize, Options.InputSamplesCount, Options.DataDirectoryPath);
            individualReportFiles = GenerateIndividualValidationReports(inputfiles);
        }

        return CompileValidationReport(individualReportFiles);
    }

    protected abstract string CompileValidationReport(IEnumerable<string> individualReportFiles);

    protected override ValidatorOptions GetDefaultValidatorOptions()
    {
        return new ValidatorOptions
        {
            InputSampleSize = SampleSize.TenMegaBytes,
            InputSamplesCount = 1000
        };
    }
}
