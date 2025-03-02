using CACrypto.Commons;

namespace CACrypto.RNGValidators.Commons;

public class TestOptions
{
    public bool writeConsole = false;
    public bool writeToFile = false;
    public string dataDirectoryPath = ".\\";
    public int inputFilesSize = SampleSize.OneMegaByte;
    public int inputFilesCount = 1;
    public bool usePreexistingFiles = true;
}