using CACrypto.Commons;
using System.Diagnostics;

namespace CACrypto.RNGValidators.NIST;

internal class ProxyNIST
{
    private readonly string NIST_PATH;
    private readonly string EXECUTABLE_FILENAME;
    private readonly string EXECUTABLE_PATH;
    private readonly string PLUGIN_FILENAME;
    private readonly string PLUGIN_PATH;

    public ProxyNIST()
    {
        var projectPath = Util.GetCurrentProjectDirectoryPath();

        NIST_PATH = Path.Combine(projectPath, ".\\NIST");
        PLUGIN_FILENAME = "libfftw3-3.dll";
        PLUGIN_PATH = Path.Combine(NIST_PATH, PLUGIN_FILENAME);
        if (Environment.Is64BitOperatingSystem && Environment.Is64BitProcess)
            EXECUTABLE_FILENAME = "NIST_STS_x64.exe";
        else
            EXECUTABLE_FILENAME = "NIST_STS_x32.exe";
        EXECUTABLE_PATH = Path.Combine(NIST_PATH, EXECUTABLE_FILENAME);
    }

    private static string ExecutableFile
    {
        get
        {
            if (Environment.Is64BitOperatingSystem && Environment.Is64BitProcess)
                return "NIST_STS_x64.exe";
            else
                return "NIST_STS_x32.exe";
        }
    }

    public class TestInput : IDisposable
    {
        public int Bytes { get; set; }

        public bool IsDisposableFile { get; set; }

        public string FileName { get; set; }

        public void Dispose()
        {
            if (IsDisposableFile)
            {
                File.Delete(FileName);
            }
        }
    }

    public bool[] Test(TestInput input)
    {
        var testedBinFile = new FileInfo(input.FileName);
        var testedBinFileName = testedBinFile.Name.Substring(0, testedBinFile.Name.Length - 4);
        var newReportFileName = Path.Combine(testedBinFile.Directory.FullName, testedBinFileName + "_NIST.txt");
        if (!File.Exists(newReportFileName))
        {
            var newTempDir = Util.CreateUniqueTempDirectory();
            var newTempExecutable = Path.Combine(newTempDir, EXECUTABLE_FILENAME);
            File.Copy(EXECUTABLE_PATH, newTempExecutable);
            var newPluginExecutable = Path.Combine(".\\", PLUGIN_FILENAME);
            if (!File.Exists(newPluginExecutable))
            {
                File.Copy(PLUGIN_PATH, newPluginExecutable);
            }
            newPluginExecutable = Path.Combine(newTempDir, PLUGIN_FILENAME);
            if (!File.Exists(newPluginExecutable))
            {
                File.Copy(PLUGIN_PATH, newPluginExecutable);
            }

            var templatesSrc = Path.Combine(NIST_PATH, "templates");
            var templatesDst = Path.Combine(newTempDir, "templates\\");
            var experimentsDir = Path.Combine(newTempDir, "experiments\\");
            var algorithmTestingDir = Path.Combine(experimentsDir, "AlgorithmTesting\\");
            var analysisReportFilename = Path.Combine(algorithmTestingDir, "finalAnalysisReport.txt");

            if (Directory.Exists(templatesDst))
                Directory.Delete(templatesDst, true);

            Util.CopyDirectory(templatesSrc, templatesDst);

            if (!Directory.Exists(experimentsDir))
                Directory.CreateDirectory(experimentsDir);
            if (Directory.Exists(algorithmTestingDir))
                Directory.Delete(algorithmTestingDir, true);
            Directory.CreateDirectory(algorithmTestingDir);

            var testsNames = new string[]
            {
                "Frequency", "BlockFrequency", "Runs", "LongestRun", "Rank", "FFT", "NonOverlappingTemplate", "OverlappingTemplate",
                "Universal", "LinearComplexity", "Serial", "ApproximateEntropy", "CumulativeSums", "RandomExcursions", "RandomExcursionsVariant"
            };
            foreach (var testName in testsNames)
            {
                Directory.CreateDirectory(Path.Combine(algorithmTestingDir, testName));
            }

            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.StartInfo.WorkingDirectory = newTempDir;
            cmd.Start();

            var inputCmd = string.Format("{0} -file \"{1}\" {2} -binary -defaultpar -fast -tests 111111111111111 -streams 1 -fileoutput",//-onlymem",
                EXECUTABLE_FILENAME, input.FileName, 8 * input.Bytes);
            cmd.StandardInput.WriteLine(inputCmd);
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            var executionOutputTxt = cmd.StandardOutput.ReadToEnd();
            var sucessfulTesting =
                executionOutputTxt.Contains("Statistical Testing Complete!!!!!!!!!!!!")
                && !executionOutputTxt.Contains("ERROR") && !executionOutputTxt.Contains("Unable");

            if (sucessfulTesting)
            {
                File.Copy(analysisReportFilename, newReportFileName);
                Directory.Delete(newTempDir, true);
            }
            else
            {
                Directory.Delete(newTempDir, true);
                throw new Exception("NIST test failure: " + Environment.NewLine + executionOutputTxt);
            }
        }
        return ParseTestResultsFromFile(newReportFileName);
    }

    public static TestInput CreateTestInput(string fileName, bool isDisposable = false)
    {
        var fileInfo = new FileInfo(fileName);

        return new TestInput() { Bytes = (int)fileInfo.Length, IsDisposableFile = isDisposable, FileName = fileName };
    }

    private static bool[] ParseTestResultsFromFile(string reportFilename)
    {
        var stringErro = string.Format("Failure when processing file: {0}", reportFilename);
        var reportLines = File.ReadAllLines(reportFilename).Skip(7).Take(188);

        try
        {
            // Test 01 - Frequency Monobit
            var frequencyMonobitTest = reportLines.First(l => l.EndsWith("Frequency"));
            var result01 =
                frequencyMonobitTest.Contains("1.0000") ?
                true :
                frequencyMonobitTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 02 - Block Frequency
            var blockFrequencyTest = reportLines.First(l => l.EndsWith("BlockFrequency"));
            var result02 = blockFrequencyTest.Contains("1.0000") ?
                true :
                blockFrequencyTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 03 - Runs
            var runsTest = reportLines.First(l => l.EndsWith("Runs"));
            var result03 = runsTest.Contains("1.0000") ?
                true :
                runsTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 04 - Longest Run of Ones
            var longestRunTest = reportLines.First(l => l.EndsWith("LongestRun"));
            var result04 = longestRunTest.Contains("1.0000") ?
                true :
                longestRunTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 05 - Binary Matrix Rank
            var rankTest = reportLines.First(l => l.EndsWith("Rank"));
            var result05 = rankTest.Contains("1.0000") ?
                true :
                rankTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 06 - Discrete Fourier Transform
            var fftTest = reportLines.First(l => l.EndsWith("FFT"));
            var result06 = fftTest.Contains("1.0000") ?
                true :
                fftTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 07 - Non-overlapping Template Matching
            var allNonOverTests = reportLines.Where(l => l.EndsWith("NonOverlappingTemplate"));
            var failedNonOverTests = allNonOverTests.Where(t => t.Contains("0.0000"));
            var successfulNonOverTests = allNonOverTests.Where(t => t.Contains("1.0000"));
            if (failedNonOverTests.Count() + successfulNonOverTests.Count() != allNonOverTests.Count())
                throw new Exception(stringErro);
            var result07 = (float)failedNonOverTests.Count() / allNonOverTests.Count() <= 0.03;

            // Test 08 - Overlapping Template Matching Test
            var overlapTest = reportLines.First(l => l.EndsWith("OverlappingTemplate"));
            var result08 = overlapTest.Contains("1.0000") ?
                true :
                overlapTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 09 - Maurer’s “Universal Statistical” Test
            var universalTest = reportLines.First(l => l.EndsWith("Universal"));
            var result09 = universalTest.Contains("1.0000") ?
                true :
                universalTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 10 - Linear Complexity Test
            var linearTest = reportLines.First(l => l.EndsWith("LinearComplexity"));
            var result10 = linearTest.Contains("1.0000") ?
                true :
                linearTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 11 - Serial Test
            var allSerialTests = reportLines.Where(l => l.EndsWith("Serial"));
            var failedSerialTests = allSerialTests.Where(t => t.Contains("0.0000"));
            var successfulSerialTests = allSerialTests.Where(t => t.Contains("1.0000"));
            if (failedSerialTests.Count() + successfulSerialTests.Count() != allSerialTests.Count())
                throw new Exception(stringErro);
            var result11 = !failedSerialTests.Any();

            // Test 12 - Approximate Entropy Test
            var entropyTest = reportLines.First(l => l.EndsWith("ApproximateEntropy"));
            var result12 = entropyTest.Contains("1.0000") ?
                true :
                entropyTest.Contains("0.0000") ? false : throw new Exception(stringErro);

            // Test 13 - Cumulative Sums Test
            var allCumulativeSumsTests = reportLines.Where(l => l.EndsWith("CumulativeSums"));
            var failedCumulativeSumsTests = allCumulativeSumsTests.Where(t => t.Contains("0.0000"));
            var successfulCumulativeSumsTests = allCumulativeSumsTests.Where(t => t.Contains("1.0000"));
            if (failedCumulativeSumsTests.Count() + successfulCumulativeSumsTests.Count() != allCumulativeSumsTests.Count())
                throw new Exception(stringErro);
            var result13 = !failedCumulativeSumsTests.Any();

            // Test 14 - Random Excursions Test
            var allRandomExcursionsTests = reportLines.Where(l => l.EndsWith("RandomExcursions"));
            var failedRandomExcursionsTests = allRandomExcursionsTests.Where(t => t.Contains("0.0000"));
            var successfulRandomExcursionsTests = allRandomExcursionsTests.Where(t => t.Contains("1.0000"));
            if (failedRandomExcursionsTests.Count() + successfulRandomExcursionsTests.Count() != allRandomExcursionsTests.Count())
                throw new Exception(stringErro);
            var result14 = !failedRandomExcursionsTests.Any();

            // Test 15 - Random Excursions Variant Test
            var allRandomExcursionsVariantTests = reportLines.Where(l => l.EndsWith("RandomExcursionsVariant"));
            var failedRandomExcursionsVariantTests = allRandomExcursionsVariantTests.Where(t => t.Contains("0.0000"));
            var successfulRandomExcursionsVariantTests = allRandomExcursionsVariantTests.Where(t => t.Contains("1.0000"));
            if (failedRandomExcursionsVariantTests.Count() + successfulRandomExcursionsVariantTests.Count() != allRandomExcursionsVariantTests.Count())
                throw new Exception(stringErro);
            var result15 = !failedRandomExcursionsVariantTests.Any();

            return new bool[] {
                result01, result02, result03, result04, result05, result06, result07, result08,
                result09, result10, result11, result12, result13, result14, result15
            };
        }
        catch (Exception ex)
        {
            File.Delete(reportFilename);
            throw new InvalidDataException("Invalid format for testing", ex);
        }
    }
}
