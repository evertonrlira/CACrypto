using System.Collections.Concurrent;

namespace CACrypto.Commons;

public abstract class CryptoMethodBase(string algorithmName)
{
    public string AlgorithmName { get; init; } = algorithmName;

    public string GetMethodName() => AlgorithmName;
    public string GetFolderNameForGeneratedFiles() => AlgorithmName;
    public abstract int GetDefaultBlockSizeInBits();
    public abstract int GetDefaultBlockSizeInBytes();

    public string GenerateBinaryFile(int sequenceSizeInBytes, string outputDir = ".\\")
    {
        string methodOutputFolder = GetOutputFolderForMethod(outputDir);

        string binaryFilePath = string.Format("{0}.bin", Path.Combine(methodOutputFolder, Path.GetRandomFileName()));
        var generatedContent = GeneratePseudoRandomSequence(sequenceSizeInBytes);
        File.WriteAllBytes(binaryFilePath, generatedContent);
        return binaryFilePath;
    }

    public IEnumerable<string> GenerateBinaryFiles(int sequenceSize, int fileCount = 1, string outputDir = ".\\", bool considerPreexistingFiles = true)
    {
        string methodOutputFolder = GetOutputFolderForMethod(outputDir);

        ConcurrentBag<string> fileBag;
        if (considerPreexistingFiles)
        {
            var dirInfo = new DirectoryInfo(methodOutputFolder);
            var files = dirInfo.GetFiles().Where(f => f.Length == sequenceSize);
            if (files.Count() > fileCount)
            {
                return files.Take(fileCount).Select(f => f.FullName);
            }
            else
            {
                fileBag = new ConcurrentBag<string>(files.Select(f => f.FullName));
                fileCount -= files.Count();
            }
        }
        else
        {
            fileBag = new ConcurrentBag<string>();
        }

        Parallel.For(0, fileCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (index) =>
        {
            var newFilePath = GenerateBinaryFile(sequenceSize, outputDir);
            fileBag.Add(newFilePath);
        });
        return fileBag;
    }

    public abstract byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes);

    private string GetOutputFolderForMethod(string outputDir)
    {
        if (!Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        var dirNameForMethod = GetFolderNameForGeneratedFiles();
        var dirCombined = Path.Combine(outputDir, dirNameForMethod);
        if (!Directory.Exists(dirCombined))
            Directory.CreateDirectory(dirCombined);
        return dirCombined;
    }
}
