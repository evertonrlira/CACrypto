using System.Collections.Concurrent;

namespace CACrypto.Commons;

public abstract class CryptoProviderBase(string methodName)
{
    public string MethodName { get; init; } = methodName;

    public string GetMethodName() => MethodName;
    public string GetFolderNameForGeneratedFiles() => MethodName;
    public abstract int GetDefaultBlockSizeInBits();
    public abstract int GetDefaultBlockSizeInBytes();
    public abstract int GetDefaultKeySizeInBytes();

    public abstract CryptoKey GenerateRandomKey();

    public string GenerateBinaryFile(int sequenceSizeInBytes, string outputDir = ".\\")
    {
        string methodOutputFolder = GetOutputFolderForBinaryFiles(outputDir);

        string binaryFilePath = string.Format("{0}.bin", Path.Combine(methodOutputFolder, Path.GetRandomFileName()));
        var generatedContent = GeneratePseudoRandomSequence(sequenceSizeInBytes);
        File.WriteAllBytes(binaryFilePath, generatedContent);
        return binaryFilePath;
    }

    public IEnumerable<string> GenerateBinaryFiles(int sequenceSize, int fileCount = 1, string outputDir = ".\\")
    {
        ConcurrentBag<string> fileBag;
        string methodOutputFolder = GetOutputFolderForBinaryFiles(outputDir);

        var dirInfo = new DirectoryInfo(methodOutputFolder);
        var preexistingFiles = dirInfo.GetFiles().Where(f => f.Length == sequenceSize);
        if (preexistingFiles.Count() >= fileCount)
        {
            return preexistingFiles.Take(fileCount).Select(f => f.FullName);
        }
        else
        {
            fileBag = new ConcurrentBag<string>(preexistingFiles.Select(f => f.FullName));
            fileCount -= preexistingFiles.Count();
        }

        Parallel.For(0, fileCount, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, (index) =>
        {
            var newFilePath = GenerateBinaryFile(sequenceSize, outputDir);
            fileBag.Add(newFilePath);
        });
        return fileBag;
    }

    public abstract byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes);

    public string GetOutputFolderForBinaryFiles(string outputDir)
    {
        if (!Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        var dirNameForMethod = GetFolderNameForGeneratedFiles();
        var dirCombined = Path.Combine(outputDir, dirNameForMethod);
        if (!Directory.Exists(dirCombined))
            Directory.CreateDirectory(dirCombined);
        return dirCombined;
    }

    public abstract void EncryptAsSingleBlock(byte[] plaintext, CryptoKey key, byte[] ciphertext, int blockSize);
}
