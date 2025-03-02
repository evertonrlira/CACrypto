using CACrypto.Commons;
using CACrypto.RNGValidators.Commons;

namespace CACrypto.RNGValidators.NIST;

public static class AutomatedNIST
{
    public static void Run(PermutiveCACryptoMethodBase cryptoMethod, TestOptions options)
    {
        var nistSuite = new ProxyNIST();

        var inputfiles = cryptoMethod.GenerateBinaryFiles(options.inputFilesSize, options.inputFilesCount, options.dataDirectoryPath, options.usePreexistingFiles);

        var culture = System.Globalization.CultureInfo.CreateSpecificCulture("en-US");
        int[] successCountArray = new int[15];
        var testResultArray = new bool[15];
        int filesWithFailedReport = 0;

        do
        {
            if (filesWithFailedReport != 0)
            {
                inputfiles = cryptoMethod.GenerateBinaryFiles(options.inputFilesSize, options.inputFilesCount, options.dataDirectoryPath, options.usePreexistingFiles);
                filesWithFailedReport = 0;
            }

            Parallel.ForEach(inputfiles, new ParallelOptions() { MaxDegreeOfParallelism = 5 }, filename =>
            {
                bool[] results;
                try
                {
                    using (var testInput = ProxyNIST.CreateTestInput(filename, false))
                    {
                        results = nistSuite.Test(testInput);
                    }

                    for (int test = 0; test < 15; test++)
                    {
                        if (results[test])
                        {
                            Interlocked.Increment(ref successCountArray[test]);
                        }
                    }
                }
                catch (InvalidDataException)
                {
                    var invalidFile = new FileInfo(filename);
                    if (options.writeConsole)
                    {
                        Console.WriteLine("[Warning] File: \"{0}\"", invalidFile.Name);
                    }
                    Interlocked.Increment(ref filesWithFailedReport);
                    File.Delete(filename);
                }
                catch (Exception ex)
                {
                    if (options.writeConsole)
                    {
                        Console.WriteLine("[Warning] Error when processing: \"{0}\"", ex.Message);
                    }
                }
            });
        } while (filesWithFailedReport != 0);

        if (options.writeConsole)
        {
            Console.WriteLine(string.Format("METHOD {0} - SUCCESS RATES ON NIST", cryptoMethod.GetMethodName()));
            for (int test = 0; test < 15; test++)
            {
                Console.WriteLine("TEST " + (test + 1) + ": " + (((float)successCountArray[test] / (float)options.inputFilesCount) * 100.0f).ToString("N2", culture.NumberFormat) + "%");
            }
        }
        return successCountArray.Select(i => ((float)i / (float)options.inputFilesCount) * 100.0f).ToArray();
    }
}
