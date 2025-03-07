using CACrypto.Commons;
using System.Diagnostics;

namespace CACrypto.RNGValidators.PractRand;

internal class PractRandProxy
{
    private static string ExecutablePath
    {
        get
        {
            if (Environment.Is64BitOperatingSystem && Environment.Is64BitProcess)
                return "..\\..\\..\\PractRand\\PractRand_RNG_test_x64.exe";
            else
                return "..\\..\\PractRand\\PractRand_RNG_test_x32.exe";
        }
    }

    public class TestInput
    {
        public long Bytes { get; set; }

        public required string Representation { get; set; }

        public required string FileName { get; set; }
    }

    public class TestResult
    {
        public required string TestName { get; set; }
        public required string Raw { get; set; }
        public required string Processed { get; set; }
        public required string Evaluation { get; set; }
        public bool Passed { get { return Evaluation.StartsWith("normal", StringComparison.InvariantCultureIgnoreCase); } }
    }

    public static bool GenerateIndividualReportFile(TestInput input, string newReportFilename)
    {
        if (File.Exists(newReportFilename))
        {
            return true;
        }

        Process cmd = new Process();
        cmd.StartInfo.FileName = "cmd.exe";
        cmd.StartInfo.RedirectStandardInput = true;
        cmd.StartInfo.RedirectStandardOutput = true;
        cmd.StartInfo.CreateNoWindow = true;
        cmd.StartInfo.UseShellExecute = false;
        cmd.Start();

        cmd.StandardInput.WriteLine(ExecutablePath + " stdin -tlmin " + input.Representation + " -tlmax " + input.Representation + " -p 1 < " + input.FileName);
        cmd.StandardInput.Flush();
        cmd.StandardInput.Close();
        string testResultTxt = cmd.StandardOutput.ReadToEnd();
        File.WriteAllText(newReportFilename, testResultTxt);
        return true;
    }

    public static TestInput CreateTestInput(string filename)
    {
        long length = new FileInfo(filename).Length;
        if (length < SampleSize.OneKiloByte)
        {
            throw new ArgumentException("The minimal sample size for PractRand is 1KB");
        }
        if (length % SampleSize.OneKiloByte != 0)
        {
            throw new ArgumentException("The PractRand sample size must be an exact multiple from 1 KB");
        }

        string formattedSize = FormatSizeIn_KB_MB(length / SampleSize.OneKiloByte);
        return new TestInput() { Bytes = length, Representation = formattedSize, FileName = filename };
    }

    private static string FormatSizeIn_KB_MB(long lengthInKB)
    {
        if (lengthInKB < SampleSize.OneKiloByte || lengthInKB % SampleSize.OneKiloByte != 0)
        {
            return lengthInKB + "KB";
        }
        else
        {
            var lengthInMB = lengthInKB / SampleSize.OneKiloByte;
            if (lengthInMB <= SampleSize.OneKiloByte || lengthInMB % SampleSize.OneKiloByte != 0)
            {
                return lengthInMB + "MB";
            }
            else
            {
                throw new ArgumentException("The maximum sample size for PractRand is 1GB");
            }
        }
    }

    internal static List<TestResult> ParseTestResultsFromFile(string reportFile)
    {
        var testResultTxt = File.ReadAllText(reportFile);
        var testOutputTxt = testResultTxt.Substring(testResultTxt.IndexOf("  Test Name"));
        int idxRaw = testOutputTxt.IndexOf("Raw");
        int idxProcessed = testOutputTxt.IndexOf("Processed");
        int idxEvaluation = testOutputTxt.IndexOf("Evaluation");
        var testResultTxtArray = testOutputTxt
            .Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries)
            .Skip(1).Reverse().Skip(1).Reverse();
        return testResultTxtArray
            .Select(S =>
                new TestResult()
                {
                    TestName = S.Substring(0, idxRaw).Trim(),
                    Raw = S.Substring(idxRaw, idxProcessed - idxRaw).Trim(),
                    Processed = S.Substring(idxProcessed, idxEvaluation - idxProcessed).Trim(),
                    Evaluation = S.Substring(idxEvaluation).Trim()
                }
            ).ToList();
    }
}
