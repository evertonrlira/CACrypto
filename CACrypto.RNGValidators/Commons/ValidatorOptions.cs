using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

public record ValidatorOptions
{
    public bool WriteToConsole { get; init; }
    public bool WriteToFile { get; init; }
    public string DataDirectoryPath { get; init; }
    public int InputFilesSize { get; init; }
    public int InputFilesCount { get; init; }

    public ValidatorOptions(int? inputFilesSize = null, int? inputFilesCount = null, string? dataDirectoryPath = null, bool? writeToConsole = null, bool? writeToFile = null)
    {
        InputFilesSize = inputFilesSize ?? SampleSize.OneMegaByte;
        InputFilesCount = inputFilesCount ?? 1;
        DataDirectoryPath = dataDirectoryPath ?? ".\\ValidationData\\";
        WriteToConsole = writeToConsole ?? true;
        WriteToFile = writeToFile ?? true;
    }
}