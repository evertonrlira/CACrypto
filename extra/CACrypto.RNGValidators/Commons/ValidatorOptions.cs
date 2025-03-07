using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

public record ValidatorOptions
{
    public bool WriteToConsole { get; init; }
    public bool WriteToFile { get; init; }
    public string DataDirectoryPath { get; init; }
    public int InputSampleSize { get; init; }
    public int InputSamplesCount { get; init; }

    public ValidatorOptions(int? inputSampleSize = null, int? inputSamplesCount = null, string? dataDirectoryPath = null, bool? writeToConsole = null, bool? writeToFile = null)
    {
        InputSampleSize = inputSampleSize ?? SampleSize.OneMegaByte;
        InputSamplesCount = inputSamplesCount ?? 1;
        DataDirectoryPath = dataDirectoryPath ?? ".\\ValidationData\\";
        WriteToConsole = writeToConsole ?? true;
        WriteToFile = writeToFile ?? true;
    }
}