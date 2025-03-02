using System.Diagnostics;

namespace CACrypto.RNGValidators.PractRand;

public class ProxyPractRand
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
    //public static TestInputSize MB_1 = new TestInputSize() { Bytes = 1048576, Representation = "1MB" };
    //public static TestInputSize KB_64 = new TestInputSize() { Bytes = 65536, Representation = "64KB" };
    //public static TestInputSize KB_1 = new TestInputSize() { Bytes = 1024, Representation = "1KB" };

    public class TestInput : IDisposable
    {
        public long Bytes { get; set; }

        public string Representation { get; set; }

        public string FileName { get; set; }

        public void Dispose()
        {
            //throw new NotImplementedException();
        }

        //public void Dispose() => { return; }// System.IO.File.Delete(FileName);
    }

    public class TestResult
    {
        public string TestName { get; set; }
        public string Raw { get; set; }
        public string Processed { get; set; }
        public string Evaluation { get; set; }
        public bool Passed { get { return Evaluation.StartsWith("normal", StringComparison.InvariantCultureIgnoreCase); } }
    }

    public static bool Test(TestInput input, out List<TestResult> testList)
    {
        var testedBinFile = new FileInfo(input.FileName);
        var testedBinFileName = testedBinFile.Name.Substring(0, testedBinFile.Name.Length - 4);
        var newReportFileName = Path.Combine(testedBinFile.Directory.FullName, testedBinFileName + "_PRACT.txt");
        string testResultTxt;
        if (!File.Exists(newReportFileName))
        {
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
            testResultTxt = cmd.StandardOutput.ReadToEnd();
            File.WriteAllText(newReportFileName, testResultTxt);
        }
        else
        {
            testResultTxt = File.ReadAllText(newReportFileName);
        }
        testList = ParseTestResults(testResultTxt);
        return testList.All(t => t.Passed);
    }

    public static TestInput CreateTestInput(byte[] byteArray)
    {
        int length = byteArray.Length;
        if (length < 1024)
        {
            throw new ArgumentException("The minimal sample size for PractRand is 1KB");
        }
        if (length % 1024 != 0)
        {
            throw new ArgumentException("The PractRand sample size must be an exact multiple from 1 KB");
        }

        string formattedSize = FormatSizeIn_KB_MB(length / 1024);

        var tempFileName = Path.GetRandomFileName();
        File.WriteAllBytes(tempFileName, byteArray);
        return new TestInput() { Bytes = length, Representation = formattedSize, FileName = tempFileName };
    }

    public static TestInput CreateTestInput(string filename)
    {
        long length = new FileInfo(filename).Length;
        if (length < 1024)
        {
            throw new ArgumentException("The minimal sample size for PractRand is 1KB");
        }
        if (length % 1024 != 0)
        {
            throw new ArgumentException("The PractRand sample size must be an exact multiple from 1 KB");
        }

        string formattedSize = FormatSizeIn_KB_MB(length / 1024);

        //var tempFileName = System.IO.Path.GetRandomFileName();
        //System.IO.File.Copy(filename, tempFileName);
        return new TestInput() { Bytes = length, Representation = formattedSize, FileName = filename };
    }

    private static List<TestResult> ParseTestResults(string testOutputTxt)
    {
        testOutputTxt = testOutputTxt.Substring(testOutputTxt.IndexOf("  Test Name"));
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

    private static string FormatSizeIn_KB_MB(long lengthInKB)
    {
        if (lengthInKB < 1024 || lengthInKB % 1024 != 0)
        {
            return lengthInKB + "KB";
        }
        else
        {
            var lengthInMB = lengthInKB / 1024;
            if (lengthInMB <= 1024 || lengthInMB % 1024 != 0)
            {
                return lengthInMB + "MB";
            }
            else
            {
                throw new ArgumentException("The maximum sample size for PractRand is 1GB");
            }
        }
    }
}
