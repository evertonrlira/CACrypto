using System.Diagnostics;

namespace CACrypto.RNGValidators.Dieharder;

public class ProxyDieharder
{
    private static string ExecutablePath
    {
        get
        {
            if (Environment.Is64BitOperatingSystem && Environment.Is64BitProcess)
                return "..\\..\\..\\Dieharder\\Dieharder_x64.exe";
            else
                return "..\\..\\Dieharder\\Dieharder_x64.exe";
        }
    }
    //public static TestInputSize MB_1 = new TestInputSize() { Bytes = 1048576, Representation = "1MB" };
    //public static TestInputSize KB_64 = new TestInputSize() { Bytes = 65536, Representation = "64KB" };
    //public static TestInputSize KB_1 = new TestInputSize() { Bytes = 1024, Representation = "1KB" };

    public class TestInput : IDisposable
    {
        public string FileName { get; set; }

        public void Dispose() => File.Delete(FileName);
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
        Process cmd = new Process();
        cmd.StartInfo.FileName = "cmd.exe";
        cmd.StartInfo.RedirectStandardInput = true;
        cmd.StartInfo.RedirectStandardOutput = true;
        cmd.StartInfo.CreateNoWindow = true;
        cmd.StartInfo.UseShellExecute = false;
        cmd.Start();

        cmd.StandardInput.WriteLine(ExecutablePath + " -a -g 201 -f " + input.FileName);
        cmd.StandardInput.Flush();
        cmd.StandardInput.Close();
        var testResultTxt = cmd.StandardOutput.ReadToEnd();
        testList = ParseTestResults(testResultTxt);
        return testList.All(t => t.Passed);
    }

    public static TestInput CreateTestInput(byte[] byteArray)
    {
        var tempFileName = Path.GetRandomFileName();
        File.WriteAllBytes(tempFileName, byteArray);
        return new TestInput() { FileName = tempFileName };
    }

    public static TestInput CreateTestInput(string filename)
    {

        var tempFileName = Path.GetRandomFileName();
        File.Copy(filename, tempFileName);
        return new TestInput() { FileName = tempFileName };
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
}
